# Specialized init for Docker containers

[![Go Report Card](https://goreportcard.com/badge/gitlab.com/tozd/dinit)](https://goreportcard.com/report/gitlab.com/tozd/dinit)
[![pipeline status](https://gitlab.com/tozd/dinit/badges/main/pipeline.svg?ignore_skipped=true)](https://gitlab.com/tozd/dinit/-/pipelines)
[![coverage report](https://gitlab.com/tozd/dinit/badges/main/coverage.svg)](https://gitlab.com/tozd/dinit/-/graphs/main/charts)

Docker containers should generally contain one service per container. But what when this service
consist of multiple different programs? Or when this service spawns sub-processes? Then a less
known fact about Docker containers comes into the effect: they all have the main process (PID 1)
which has to reap zombie processes and handle signals from container's supervisor. Not doing that
properly can lead to resource exhaustion or data loss. Docker containers are similar but not exactly
the same as a full Linux system so traditional init systems are not the best fit for Docker containers.

dinit is an opinionated init for Docker containers which has been specially designed for operation
inside Docker containers and does things slightly differently than traditional init systems but it
makes much more sense inside Docker containers.

Features:

- It reaps [zombie processes](https://en.wikipedia.org/wiki/Zombie_process) so that they do not
  accumulate inside a Docker container.
- It supports running multiple different programs inside a Docker container, compatible with
  [runit init system](http://smarden.org/runit/). If any program finishes, dinit terminates
  the whole container so that container's supervisor can decide whether to restart the whole
  container or do something else, e.g., backoff (and to even log that container has terminated).
  Traditional init systems restart programs themselves, but that then hides any issues from the
  container's supervisor. Moreover, traditional init systems generally do not do any backoff
  between restarts.
- On TERM signal it gracefully terminates all programs. It just sends them TERM signal as well
  (by default) and then waits for them to terminate. It does not send them KILL signal because
  container's supervisor does that anyway if the whole container takes too long to terminate.
- It line-wise multiplexes stdout and stderr from programs into its own stdout and stderr
  so that all logs are available through `docker logs` or similar log collecting mechanism.
- To every logged line it adds program's name and timestamp metadata. When configured that
  stdout contains JSON per line (default), it adds metadata as JSON fields, otherwise it
  prepends metadata to every line. It prepends metadata to stderr as well.
- It uses stderr for its own errors. The idea here is that stdout should be used for expected
  logging from programs while anything written to stderr by dinit or any program is exceptional
  and that it cannot be assured to be JSON (e.g., Go runtime panic).
- It extends reaping of zombie processes to handling any running process which gets reparented to dinit
  (when the parent of such process exits before its child, e.g., when process is
  [daemonized](<https://en.wikipedia.org/wiki/Daemon_(computing)>)).
  By default it terminates such processes (any daemonization is seen as configuration error)
  but it also supports adopting such processes. When dinit adopts a reparented process it
  redirects stdout and stderr of the process to dinit itself.
- Instead of default TERM signal one can provide a `finish` program to be called to terminate
  the main program (e.g., which can call `nginx -s quit`).
- Supports a logging program which then receives stdout from the main program. You can use it
  to redirect logs to a file or elsewhere, or to convert non-JSON logging to JSON logging
  (e.g., using [regex2json](https://gitlab.com/tozd/regex2json) tool). Any stdout and stderr output
  from the logging program is then used by dinit as stdout and stderr output of the main program.
- Configuration of dinit itself is done through environment variables.

## Installation

dinit is implemented in Go. You can use `go install` to install the latest stable (released) version:

```sh
go install gitlab.com/tozd/dinit/cmd/dinit@latest
```

[Releases page](https://gitlab.com/tozd/dinit/-/releases)
contains a list of stable versions. Each includes statically compiled binaries.

To install the latest development version (`main` branch):

```sh
go install gitlab.com/tozd/dinit/cmd/dinit@main
```

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

## Why is JSON used just for stdout and not also for stderr?

It is hard to generate proper JSON once things start failing apart (e.g.,
[Go runtime panic](https://github.com/golang/go/issues/40238)). The idea is that under default logging level,
stdout should be used for expected logging from programs while anything written to stderr by dinit or any program
is exceptional and means a human intervention is needed. You should setup programs run by dinit this way as well.

## runit supports dependencies between programs, why not dinit?

runit compatibility is in how programs to run are specified, including a logging program and a finish program.
But there are many aspects of runit which are not supported by dinit (e.g., dinit does not expose status
information of programs through files) which also prevents
[waiting for another program to start](http://smarden.org/runit/faq.html#depends). There are two reasons for
this. Creating files inside `DINIT_DIR` directory (like runit does) requires `DINIT_DIR` to be writable,
but writing outside of volumes in Docker containers is discouraged. Waiting for another program to start does
not necessary mean that the another program is also ready. This means that often it is better to have a
program-specific way to test if another program is ready which can be done inside the `run` file and is
out of scope of dinit itself.

## GitHub mirror

There is also a [read-only GitHub mirror available](https://github.com/tozd/dinit),
if you need to fork the project there.