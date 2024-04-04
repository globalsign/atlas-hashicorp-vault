# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.1] - 2024-03-27
### Changed
- Updated all go dependancies
- Stubbed TestCase and TestStep from github.com/hashicorp/vault/helper/testhelpers/logical to avoid loading vault as a module
- Updated action to build with golang version 1.21

### Fixed
 - Fixed test_and_cover.sh script to exit 1 on any error


## [v1.0.1] - 2024-03-27
### Changed
- Updated build-all-arch.sh to build container compatible binary

### Fixed
- Build and Publish workflow to be a manual run, which gets release version from version.txt
