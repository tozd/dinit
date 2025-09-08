# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Binaries and Docker images are now built for linux/arm64.

### Changed

- Go 1.23 or newer is required.

## [0.3.0] - 2023-10-10

### Added

- Support for ARM64 (AArch64) architecture.
  [#4](https://gitlab.com/tozd/dinit/-/issues/4)

## [0.2.0] - 2023-07-10

### Changed

- If `run` file exits with code 115 it signals that the program is disabling itself
  and that it does not have to run and the rest of the container is then not terminated.
- Change name to `terminate` file instead of `finish` file to avoid confusion.
  `finish` file is used differently in runit.

## [0.1.0] - 2023-07-09

### Added

- First public release.

[unreleased]: https://gitlab.com/tozd/dinit/-/compare/v0.3.0...main
[0.3.0]: https://gitlab.com/tozd/dinit/-/compare/v0.2.0...v0.3.0
[0.2.0]: https://gitlab.com/tozd/dinit/-/compare/v0.1.0...v0.2.0
[0.1.0]: https://gitlab.com/tozd/dinit/-/tags/v0.1.0

<!-- markdownlint-disable-file MD024 -->
