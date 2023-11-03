# Password and Encryption Utilities

This module contains functions for password validation, user registration, user authentication, and password hashing using the SHA-256 and bcrypt algorithms. Additionally, it provides functionalities for RSA key generation, encryption, decryption, signing, verification, and self-signed certificate generation.

## Table of Contents
- [Password Validation](#password-validation)
- [User Registration](#user-registration)
- [User Authentication](#user-authentication)
- [Password Hashing](#password-hashing)
- [RSA Key Management](#rsa-key-management)
- [RSA Encryption and Decryption](#rsa-encryption-and-decryption)
- [RSA Signing and Verification](#rsa-signing-and-verification)
- [Self-Signed Certificate Generation](#self-signed-certificate-generation)
- [Dictionary Attack](#dictionary-attack)

## Password Validation
You can use these functions to validate passwords based on the following criteria:
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one of the special characters: @, #, $, %, ^, &, +, or =
- Minimum length of 8 characters

```python
# Example usage
is_valid_password(pwd)
