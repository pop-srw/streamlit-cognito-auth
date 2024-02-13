# Changelog

All notable changes to this project will be documented in this file.

## [1.3.0] - 2024-02-14

### Added

- Introduced hosted UI authentication flow.
- Implemented a customizable login button.
- Added the ability to disable the login button.
- Enhanced documentation.

## [1.2.0] - 2023-06-04

### Added

- Added support for Cognito pools without app client secret.

## [1.1.1] - 2023-04-06

### Fixed

- Fixed an issue where `awssrp` was requiring a region.

## [1.1.0] - 2023-04-06

### Changed

- Updated authentication library from warrant to pycognito.
- Changed token verification to use pycognito library instead of custom implementation.

## [1.0.2] - 2023-04-06

### Changed

- Updated documentations.

## [1.0.0] - 2023-04-05

### Added

- Initial release
- Implemented CognitoAuthenticator class with login, logout, and get_username methods.
- Added ability to load session state from cookies.
- Implemented password reset functionality.
- Added exception handling for login and password reset.
- Created login and password reset forms using Streamlit components.
- Added ability to set and clear cookies for authentication tokens.
- Added function to verify access token.
- Created custom exceptions for authentication errors.
