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
```

## User Registration
This function allows you to register a new user with a valid email and password. It also securely hashes the password using bcrypt before storing it.

```python
# Example usage
register_user(email, pwd)
```

## User Authentication
This function allows you to authenticate a user with a valid email and password. It also securely compares the password with the hashed password stored in the database.

```python
authenticate_user(email, pwd)
```
## Password Hashing
This module provides two functions for password hashing:

SHA-256 Hashing
```python
sha256_hash(password)
```

Bcrypt Hashing (with salt generation)

```python
bcrypt_hash(password)
```

### RSA Key Management
You can generate RSA key pairs and save them to files using the following functions:

Generate RSA Key Pair
```python
generate_rsa_key_pair()
```
## RSA Encryption and Decryption
You can use RSA to encrypt and decrypt messages. The user can interactively input a message to encrypt and decrypt.

Encrypt a message using a public key
```python
encrypt_message_rsa()
```
Decrypt a message using a private key
```python
decrypt_message_rsa()
```

## RSA Signing and Verification
You can sign and verify messages using RSA keys. The user can interactively input a message to sign and verify.

Sign a message using a private key
```python
sign_message_rsa()
```
Verify the signature of a message using a public key
```python
verify_signature_rsa()
```
## Self-Signed Certificate Generation
Generate a self-signed certificate for secure communication. This function generates a certificate and saves it, along with the public and private keys, to files.

```python
generate_self_signed_certificate()
```
## Dictionary Attack
The dictionary attack function checks if a given password hash matches any entry in a provided dictionary file.

```python
attack_dictionary()
```

## Sub-Menus
This project includes sub-menus to help you navigate through the different functionalities, such as password hashing, RSA encryption, and certificate generation.

Sub-Menu A: Password Hashing
Sub-Menu B: RSA Encryption
Sub-Menu C: RSA Certificate Generation

## Usage
Run the script.
Choose an option from the main menu (1 for registration, 2 for authentication).
If you choose authentication, you will have access to additional sub-menus for various cryptographic operations.
Please make sure to follow the instructions and options provided in the menus to explore the features of this project.

Note: This README provides a brief overview of the project. For more detailed information on how to use the functions, refer to the code and comments within the script.