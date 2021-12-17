# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2021-12-17
### Changed
- Fixed `except TimeoutError` for python version < 3.10
- Fixed minimum python version required (3.8)
- Tuned up wireguard file modes

## [0.1.1] - 2021-12-17
### Changed
- Fixed server first execution, checking for `/etc` subdirs existence
- Fixed server first execution, checking existence of psk before using it

## [0.1.0] - 2021-12-17
### Added
- Add possibility to peers to name themselves: it will be saved as an INI comment inside the central peer's relative Peer section
- Added `wgstarman resolv` command (runnable as unprivileged user) to interrogate a central resolv server for the required network's host name

### Changed
- Fixed setup.cfg's development status classifier to 4 - Beta
- Fixed WgStarMan `/etc` dir and files permissions

## [0.0.3] - 2021-12-15
### Changed
- Fixed setup.cfg's project's URL

## [0.0.2] - 2021-12-15
### Added
- First release
