# Streamlit Cognito Auth

A Streamlit component for authenticating users with AWS Cognito

## Installation

To install the package, you can use pip:

```sh
pip install streamlit-cognito-auth
```

## Usage

To use the package, you can import the `CognitoAuthenticator` class from the `streamlit_cognito_auth` package, and create an instance of it, passing your `pool_id`, `app_client_id` and `app_client_secret` as the arguments.

```python
from streamlit_cognito_auth import CognitoAuthenticator
```

To perform login, you can call the login() method on the authenticator instance and check the returned value, if it's True then the user is logged in, otherwise the login process failed.

```python
is_logged_in = authenticator.login()
if not is_logged_in:
    print("Login failed")
```

To perform logout, you can call the logout() method on the authenticator instance

```python
authenticator.logout()
```

You can also get the logged in user's username by calling get_username() method on the authenticator instance

```
username = authenticator.get_username()
```

You can find the full example code in `examples/example.py` file.

## Example

You can find an example of how to use the package in the examples directory.

To run the example file, you can use the following command, while replacing `your_pool_id`, `your_app_client_id` and `your_app_client_secret` with the actual values:

```sh
POOL_ID="your_pool_id"
APP_CLIENT_ID="your_app_client_id"
APP_CLIENT_SECRET="your_app_client_secret"

cd examples
streamlit run example.py
```

or in windows

```ps
set POOL_ID="your_pool_id"
set APP_CLIENT_ID="your_app_client_id"
set APP_CLIENT_SECRET="your_app_client_secret"

cd examples
streamlit run example.py
```

## Limitations

- This package has been tested and known to work with Amazon Cognito pools that have an app client with a secret enabled and using the SRP protocol. Other configurations of Cognito pools may not be supported and have not been tested.
- This package has been tested and known to work with python 3.8 in Linux environment. It may not work with other versions of python or other operating systems.

## Future Work

- [x] Support for Cognito pools with app client secret
- [ ] Support for Cognito pools without app client secret
- [x] Support for "USER_SRP_AUTH" authentication flow
- [ ] Support for "REFRESH_TOKEN_AUTH / REFRESH_TOKEN" authentication flow
- [ ] Support for "USER_PASSWORD_AUTH" authentication flow

## Credits

- This package is inspired by the work of [mkhorasani/Streamlit-Authenticator](https://github.com/mkhorasani/Streamlit-Authenticator) and I would like to thank the author for their work.
- JWT verification functionality is based on the work of [awslabs/aws-support-tools](https://github.com/awslabs/aws-support-tools/blob/master/Cognito/decode-verify-jwt/decode-verify-jwt.py) and I would like to thank the author for their work.
- Thanks to OpenAI's ChatGPT for providing helpful suggestions and examples throughout the development of this project.
