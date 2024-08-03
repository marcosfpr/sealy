# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.5]

### Added

- Added `PyContext` serialization (#16)(@marcosfpr)

## [0.1.4]

### Added

- Added serialization/deserialization of Context to make it pickeable (#16)(@marcosfpr)

## [0.1.3]

### Added

- Added batch bytes serialization (#15)(@marcosfpr)

## [0.1.2]

### Added

- Added batching in Python to overcome size limits of SEAL. (#14)(@marcosfpr)

## [0.1.1]

### Fixed

- Added `CKKSEncoder` in the FFI bindings (#13)(@marcosfpr)

## [0.1.0]

### Added

- Added Microsoft SEAL Rust bindings initial version (#2,#3,#4,#5,#7)(@marcosfpr)
- Added tensor operations for ciphertexts using batching (#8)(@marcosfpr)
- Added python bindings for sealy (#9)(@marcosfpr)

[0.1.0]: https://github.com/marcosfpr/sealy/compare/v0.1.0...v0.1.0
[0.1.1]: https://github.com/marcosfpr/sealy/compare/v0.1.0...v0.1.1
[0.1.2]: https://github.com/marcosfpr/sealy/compare/v0.1.1...v0.1.2
[0.1.3]: https://github.com/marcosfpr/sealy/compare/v0.1.2...v0.1.3
[0.1.4]: https://github.com/marcosfpr/sealy/compare/v0.1.3...v0.1.4
[0.1.5]: https://github.com/marcosfpr/sealy/compare/v0.1.4...v0.1.5
[unreleased]: https://github.com/marcosfpr/sealy/compare/v0.1.5...HEAD
