# Specialized init for Docker containers

[![Go Report Card](https://goreportcard.com/badge/gitlab.com/tozd/dinit)](https://goreportcard.com/report/gitlab.com/tozd/dinit)
[![pipeline status](https://gitlab.com/tozd/dinit/badges/main/pipeline.svg?ignore_skipped=true)](https://gitlab.com/tozd/dinit/-/pipelines)
[![coverage report](https://gitlab.com/tozd/dinit/badges/main/coverage.svg)](https://gitlab.com/tozd/dinit/-/graphs/main/charts)

Docker containers should generally contain one service per container. But what happens when this service
consist of multiple different programs? Or when this service spawns sub-processes? Then a less-known fact about
Docker containers comes into the effect: they all have the init process (PID 1)
which has to reap zombie processes and handle signals from the container's supervisor. Using a program
as the init process which does not expect to handle subprocesses and signals (e.g., distroless builds or naive
application bundles) properly can [lead to resource exhaustion or data loss](#what-was-the-motivation-to-start-this-project).
Docker containers are similar but not exactly the same as a full Linux system so traditional init systems
are not the best fit for Docker containers.

dinit is an opinionated init for Docker containers which has been specially designed for operation
inside Docker containers and does things slightly differently than traditional init systems but it
makes much more sense inside Docker containers.

Features:

- Multi-process:
  - It supports running multiple different programs inside a Docker container, compatible with
    [runit init system](http://smarden.org/runit/). If any program finishes, dinit terminates
    the whole container so that container's supervisor can decide whether to restart the whole
    container or do something else, e.g., a backoff or to even log that container has terminated.
    Traditional init systems restart programs themselves, but that then hides any issues from the
    container's supervisor. Moreover, traditional init systems generally do not do any backoff
    between restarts.
- Signal handling:
  - On TERM signal it gracefully terminates all programs. It just sends them TERM signal as well
    (by default) and then waits for them to terminate. It does not send them KILL signal because
    the container's supervisor does that anyway if the whole container takes too long to terminate.
- Managing processes:
  - It reaps [zombie processes](https://en.wikipedia.org/wiki/Zombie_process) so that they do not
    accumulate inside a Docker container.
  - It extends reaping of zombie processes to handling any running process which gets reparented to dinit
    (when the parent of such process exits before its child, e.g., when process is
    [daemonized](<https://en.wikipedia.org/wiki/Daemon_(computing)>)).
    By default it terminates such processes (any daemonization is seen as configuration error)
    but it also supports adopting such processes. When dinit adopts a reparented process it
    redirects stdout and stderr of the process to dinit itself.
  - Instead of default TERM signal one can provide a `terminate` file to be run to terminate
    the main program (e.g., which can call `nginx -s quit`).
- Managing processes' stdout and stderr:
  - It line-wise multiplexes stdout and stderr from programs into its own stdout and stderr
    so that all logs are available through `docker logs` or similar log collecting mechanism.
  - To every logged line it adds the program's name and timestamp metadata. When configured that
    stdout contains JSON per line (the default), it adds metadata as JSON fields, otherwise it
    prepends metadata to every line. It prepends metadata to stderr as well.
  - It uses stderr for its own errors. The idea here is that stdout should be used for expected
    logging from programs while anything written to stderr by dinit or any program is exceptional
    and that it cannot be assured to be JSON (e.g., Go runtime panic).
  - Supports a logging program which then receives stdout from the main program. You can use it
    to redirect stdout to a file or elsewhere, or to convert non-JSON stdout to JSON
    (e.g., using [regex2json](https://gitlab.com/tozd/regex2json) tool). Stdout output
    from the logging program is then used by dinit as stdout of the main program.
- Configuration of dinit itself is done through environment variables.

## Installation

dinit requires Docker 19.03 or newer and Linux kernel versions 4.8 or newer.

[Releases page](https://gitlab.com/tozd/dinit/-/releases)
contains a list of stable versions. Each includes statically compiled binaries.
You should just download the latest one inside your Dockerfile.

You can also use [tozd/dinit](https://gitlab.com/tozd/docker/dinit) Docker image as a base
image for your Docker images.

dinit is implemented in Go. You can also use `go install` to install the latest stable (released) version:

```sh
go install gitlab.com/tozd/dinit/cmd/dinit@latest
```

To install the latest development version (`main` branch):

```sh
go install gitlab.com/tozd/dinit/cmd/dinit@main
```

## Usage

You should configure
dinit as the [entrypoint](https://docs.docker.com/engine/reference/builder/#entrypoint) in your Docker image.
When Docker image runs, dinit will then look into `/etc/service` directory (by default, see `DINIT_DIR`)
for configuration of programs to run. The structure of `/etc/service` directory is
[compatible with runit](http://smarden.org/runit/runsv.8.html) and consists of the following executable
files for each program to run:

- `/etc/service/<name>/run`: The main executable file which is run to start a program. Generally it is a
  shell script which prepares program for execution and then [exec](<https://en.wikipedia.org/wiki/Exec_(system_call)>)
  into the executable of the program you want to run.
  If `run` file finishes with code 115 it signals that the program is disabling itself and that it does not
  have to run and the rest of the whole container is then not terminated as it would otherwise be when any
  of its programs finishes.
- `/etc/service/<name>/terminate`: When present, dinit does not send TERM signal to the process when it wants
  to terminate it, but runs this executable file. When this file is executed, it receives the PID of the
  corresponding terminating process through `DINIT_PID` environment variable.
  Remember, you do not have to KILL the process, just initiate termination.
  Container's supervisor will KILL any remaining processes anyway.
- `/etc/service/<name>/log/run`: Optional executable file for a logging program. Stdout of the main program
  (i.e., from `/etc/service/<name>/run`) is piped to stdin of this program which can then process it.
  It can be use to redirect stdout to a file or elsewhere, or to convert non-JSON stdout to JSON
  (e.g., using [regex2json](https://gitlab.com/tozd/regex2json) tool). Stdout output
  from the logging program is then used by dinit as stdout of the main program.
  Stderr outputs of the main and logging programs are used by dinit normally as well.

dinit expects programs to not daemonize but to stay running with dinit as their parent process.
If any program does daemonize, the default `terminate` reparenting policy will simply terminate them.
(`adopt` reparenting policy will adopt such processes, but that should be more of an exception than a rule.)

### Configuration

Configuration of dinit itself is done through environment variables:

- `DINIT_JSON_STDOUT`: By default dinit expects stdout lines to be JSON objects. It does a basic check
  to verify this is so and if not it complains to its stderr. Set this variable to `0` to disable JSON
  processing. Setting it to `0` also makes dinit prepend program's name and timestamp metadata to
  the line instead of adding metadata as JSON fields.
- `DINIT_LOG_LEVEL`: The level at which dinit logs. Default is `warn`. Possible levels are `none`,
  `error`, `warn`, `info`, and `debug`.
- `DINIT_REPARENTING_POLICY`: Default is `terminate`. Possible policies are `adopt`, `terminate`, and
  `ignore`. `terminate` policy terminates any process which gets reparented to dinit.
  `adopt` policy waits for the process to terminate (and then terminates the whole container). When adopting
  a process dinit also redirects stdout and stderr of the process to dinit itself.
- `DINIT_KILL_TIMEOUT`: How long (in seconds) does `terminate` policy waits after sending the TERM signal
  to send the KILL signal to a reparented process? Default is 30 seconds.
- `DINIT_DIR`: In which directory to look for programs to run. Default is `/etc/service`.

## What was the motivation to start this project?

In [our Docker images](https://gitlab.com/tozd/docker) we used
[runit init system](https://gitlab.com/tozd/docker/runit) but we discovered that
images [are not gracefully shut down](https://gitlab.com/tozd/docker/runit/-/issues/1). For example,
databases were often not cleanly shut down. This happens because after runit receives the TERM signal
and passes it on to running processes it immediately terminates itself causing Docker to believe that
the container has finished, after which Docker KILLs any remaining processes, including the database
which has not yet cleanly shut down.

Once we started thinking about replacing runit we could not find any [existing project](#related-projects)
which would provide all of the features we wanted, so a new project was started.

## Why is JSON used just for stdout and not also for stderr?

It is hard to generate proper JSON once things start falling apart (e.g.,
[Go runtime panic](https://github.com/golang/go/issues/40238)). The idea is that under default logging level,
stdout should be used for expected logging from programs while anything written to stderr by dinit or any program
is exceptional and means a human intervention is needed. You should setup programs run by dinit this way as well
(defining a logging program can help you with that).

## runit supports dependencies between programs, why not dinit?

runit compatibility is in how programs to run are specified.
But there are many aspects of runit which are not supported by dinit (e.g., dinit does not expose status
information of programs through files and does not create control named pipes) which also prevents
[waiting for another program to start](http://smarden.org/runit/faq.html#depends). There are two reasons for
this. First, creating files inside `DINIT_DIR` directory (like runit does) requires `DINIT_DIR` to be writable,
but writing outside of volumes in Docker containers is discouraged. Second, waiting for another program to start does
not necessarily mean that another program is also ready. This means that often it is better to have a
program-specific way to test if another program is ready which can be done inside the `run` file.

## Are there any examples of real service files?

Many [tozd Docker images](https://gitlab.com/tozd/docker) use dinit any you can check files there, e.g.,
[nginx](https://gitlab.com/tozd/docker/nginx/-/blob/master/etc/service/nginx/run) and its
[terminate](https://gitlab.com/tozd/docker/nginx/-/blob/master/etc/service/nginx/terminate),
[mongodb](https://gitlab.com/tozd/docker/mongodb/-/blob/master/etc/service/mongod/run) and its
[log](https://gitlab.com/tozd/docker/mongodb/-/blob/master/log/run) (or an
[older one](https://gitlab.com/tozd/docker/mongodb/-/blob/master/log-3.0/run) which converts logs to JSON).

## Related projects

- [runit](http://smarden.org/runit/index.html) – Awesome init system which looks like it is suitable for use inside
  Docker containers for its simplicity and small size, but it does not really work well.
  [Discourse has this script](https://github.com/discourse/discourse_docker/blob/master/image/base/boot)
  and [baseimage-docker has another one](https://github.com/phusion/baseimage-docker/blob/master/image/bin/my_init)
  to address some issues.
- [runsvinit](https://github.com/peterbourgon/runsvinit) – Another solution for issues with running runit inside
  Docker containers. It suggests that one should run both `runit` and `runsvdir` and not just `runsvdir` inside
  Docker containers and suggests to write your own `/etc/service/ctrlaltdel` to cleanup processes. dinit just does
  the right thing and does not require you to write custom cleanup scripts.
- [github.com/ramr/go-reaper](https://github.com/ramr/go-reaper) – Recognizes the same issue of zombie processes in Docker
  containers when Go programs are used as the init process (PID 1) inside Docker containers and provides a library
  for Go programs to reap them. dinit supports also non-Go programs.
- [dumb-init](https://github.com/Yelp/dumb-init) – Init to run a program which is not expecting to be the init process.
  Supports running only one such program per container.
- [tini](https://github.com/krallin/tini) – Another init to run a program which is not expecting to be the init process.
  Now bundled with Docker. Also limited to only one such program per container.
- [s6-overlay](https://github.com/just-containers/s6-overlay) – Provides utilities for [s6](https://skarnet.org/software/s6/overview.html),
  another popular init system, for easier use inside Docker containers. It shares many features and
  [design goals](https://github.com/just-containers/s6-overlay#the-docker-way) with dinit and more and is very
  configurable. dinit is compatible with runit. dinit is simpler, opinionated, and attempts to be less configurable
  and simply do the right thing.

## GitHub mirror

There is also a [read-only GitHub mirror available](https://github.com/tozd/dinit),
if you need to fork the project there.
