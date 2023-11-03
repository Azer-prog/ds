"""
This module contains functions for password validation, user registration, user authentication, and password hashing using sha256 and bcrypt algorithms.
"""

import re
import hashlib
import bcrypt
import re
import hashlib
import bcrypt
import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


# Fonction pour vérifier si un mot de passe est valide
def is_valid_password(pwd):
    # Vérifie que le mot de passe respecte les règles
    return re.match(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@#$%^&+=]).{8,}$", pwd)
"""
At least one uppercase letter.
At least one lowercase letter.
At least one digit.
At least one of the special characters @, #, $, %, ^, &, +, or =.
A minimum length of 8 characters.
"""
# Fonction pour enregistrer un nouvel utilisateur
def register_user(email, pwd):
    if not is_valid_password(pwd):
        print("Le mot de passe ne respecte pas les règles.")
        return

    # Vérification si l'utilisateur existe déjà
    with open("Enregistrement.txt", "r") as file:
        lines = file.readlines()
        for line in lines:
            stored_email, _ = line.strip().split(":")
            if email == stored_email:
                print("L'utilisateur existe déjà.")
                return
    
     # Generate a random salt for hashing
    salt = bcrypt.gensalt()
    # Hash the password with the generated salt
    hashed_pwd = bcrypt.hashpw(pwd.encode('utf-8'), salt)

    # Store the email and hashed password in Enregistrement.txt
    with open("Enregistrement.txt", "a") as file:
        file.write(f"{email}:{hashed_pwd.decode('utf-8')}\n")

# Fonction pour authentifier un utilisateur
def authenticate_user(email, pwd):
    # Vérification des identifiants dans Enregistrement.txt
    with open("Enregistrement.txt", "r") as file:
        lines = file.readlines()
        for line in lines:
            stored_email, stored_pwd = line.strip().split(":")
            if email == stored_email and bcrypt.checkpw(pwd.encode('utf-8'), stored_pwd.encode('utf-8')):
                return True
    return False

# Fonction pour hacher un mot avec sha256
def sha256_hash(password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return hashed

# Fonction pour hacher un mot avec bcrypt (avec salt)
def bcrypt_hash(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def generate_rsa_key_pair():
    # Generate a public/private key pair
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Save the private key to a file
    with open("private_key.pem", "wb") as private_key_file:
        private_key_file.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
    # Save the public key to a file
    with open("public_key.pem", "wb") as public_key_file:
        public_key_file.write(key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

def encrypt_message_rsa():
    message = input("Entrez le message à chiffrer : ")

    # Load the public key from a file
    with open("public_key.pem", "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(public_key_file.read())

    # Encrypt the message
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(f"Le message chiffré est : {encrypted_message.hex()}")

def decrypt_message_rsa():
    encrypted_message = input("Entrez le message à déchiffrer (en format hexadécimal) : ")

    # Load the private key from a file
    with open("private_key.pem", "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(private_key_file.read(), password=None)

    # Decrypt the message
    encrypted_bytes = bytes.fromhex(encrypted_message)
    decrypted_message = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(f"Le message déchiffré est : {decrypted_message.decode('utf-8')}")



def sign_message_rsa():
    # Load the private key from a file
    with open("private_key.pem", "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(private_key_file.read(), password=None)

    # Sign the message
    message = input("Entrez le message à signer : ")
    hashed_message = hashes.Hash(hashes.SHA256())
    hashed_message.update(message.encode('utf-8'))
    digest = hashed_message.finalize()
    
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    print(f"La signature est : {signature.hex()}")

def verify_signature_rsa():
    # Load the public key from a file
    with open("public_key.pem", "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(public_key_file.read())

    # Verify the signature
    message = input("Entrez le message à vérifier : ")
    signature = input("Entrez la signature (en format hexadécimal) : ")

    hashed_message = hashes.Hash(hashes.SHA256())
    hashed_message.update(message.encode('utf-8'))
    digest = hashed_message.finalize()

    try:
        public_key.verify(
            bytes.fromhex(signature),
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("La signature est valide.")
    except InvalidSignature:
        print("La signature n'est pas valide.")

def generate_self_signed_certificate():
    # Generate a public/private key pair
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CA"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Quebec"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Montreal"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UQAM"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"uqam.ca"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.utcnow() + timedelta(days=10)
    ).sign(key, hashes.SHA256())

    # Save the private key to a file
    with open("private_key.pem", "wb") as private_key_file:
        private_key_file.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
    # Save the public key to a file
    with open("public_key.pem", "wb") as public_key_file:
        public_key_file.write(key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    # Save the certificate to a file
    with open("certificate.pem", "wb") as certificate_file:
        certificate_file.write(cert.public_bytes(serialization.Encoding.PEM))


def encrypt_message_with_certificate():
    message = input("Entrez le message à chiffrer : ")

    # Load the certificate from a file
    with open("certificate.pem", "rb") as certificate_file:
        certificate = x509.load_pem_x509_certificate(certificate_file.read())

    # Encrypt the message
    encrypted_message = certificate.public_key().encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(f"Le message chiffré est : {encrypted_message.hex()}")

def attack_dictionary():
    # Load the dictionary from a file
    with open("dictionary.txt", "r") as dictionary_file:
        words = dictionary_file.readlines()

    # ask the user for the password to crack
    password = input("Entrez le mot de passe à cracker : ")

    # Try to find the password in the dictionary
    for word in words:
        hashed_word = sha256_hash(word.strip())
        if hashed_word == password:
            print(f"Le mot de passe est : {word.strip()}")
            return

    print("Le mot de passe n'a pas été trouvé dans le dictionnaire.")

def submenu_a():
    while True:
        print("Sous-menu A - Hachage:")
        print("a- Hacher le mot par sha256")
        print("b- Hacher le mot en générant un salt (bcrypt)")
        print("c- Attaquer par dictionnaire le mot inséré")
        print("d- Revenir au menu principal")

        choice = input("Choisissez une option (a/b/c/d): ")

        if choice == "a":
            word = input("Entrez le mot à hacher : ")
            hashed_word = sha256_hash(word)
            print(f"Résultat du hachage SHA-256 : {hashed_word}")
        elif choice == "b":
            word = input("Entrez le mot à hacher : ")
            salt = bcrypt.gensalt()
            hashed_word = bcrypt_hash(word.encode('utf-8'), salt)
            print(f"Résultat du hachage avec bcrypt : {hashed_word}")
        elif choice == "c":
            attack_dictionary()
            pass
        elif choice == "d":
            break
        else:
            print("Option invalide. Veuillez choisir a, b, c ou d.")



# Fonction pour le sous-menu B : Chiffrement RSA
def submenu_b():
    while True:
        print("Sous-menu B - Chiffrement (RSA):")
        print("a- Générer les paires de clés dans un fichier")
        print("b- Chiffrer un message de votre choix par RSA")
        print("c- Déchiffrer le message (b)")
        print("d- Signer un message de votre choix par RSA")
        print("e- Vérifier la signature du message (d)")
        print("f- Revenir au menu principal")

        choice = input("Choisissez une option (a/b/c/d/e/f): ")

        if choice == "a":
            generate_rsa_key_pair()
        elif choice == "b":
            encrypt_message_rsa()
        elif choice == "c":
            decrypt_message_rsa()
        elif choice == "d":
            sign_message_rsa()
        elif choice == "e":
            verify_signature_rsa()
        elif choice == "f":
            break
        else:
            print("Option invalide. Veuillez choisir a, b, c, d, e ou f.")

# Fonction pour le sous-menu C : Certificat RSA
def submenu_c():
    while True:
        print("Sous-menu C - Certificat (RSA):")
        print("a- Générer les paires de clés dans un fichier")
        print("b- Générer un certificat autosigné par RSA")
        print("c- Chiffrer un message de votre choix par ce certificat")
        print("d- Revenir au menu principal")

        choice = input("Choisissez une option (a/b/c/d): ")

        if choice == "a":
            generate_rsa_key_pair()
        elif choice == "b":
            generate_self_signed_certificate()
        elif choice == "c":
            encrypt_message_with_certificate()
        elif choice == "d":
            break
        else:
            print("Option invalide. Veuillez choisir a, b, c ou d.")

# ... Votre code précédent ...

# Fonction principale du menu après l'authentification
def authenticated_menu():
    while True:
        print("Menu après authentification:")
        print("A- Donnez un mot à hacher (en mode invisible)")
        print("B- Chiffrement (RSA)")
        print("C- Certificat (RSA)")
        print("Q- Quitter le programme")

        choice = input("Choisissez une option (A/B/C/Q): ")

        if choice == "A":
            submenu_a()
        elif choice == "B":
            submenu_b()
        elif choice == "C":
            submenu_c()
        elif choice == "Q":
            break
        else:
            print("Option invalide. Veuillez choisir A, B, C ou Q.")

# Rest of your code
def main_menu():
    while True:
        print("Menu principal:")
        print("1- Enregistrement")
        print("2- Authentification")
        choice = input("Choisissez une option (1/2): ")

        if choice == "1":
            email = input("Entrez votre email: ")
            pwd = input("Entrez votre mot de passe: ")
            register_user(email, pwd)
        elif choice == "2":
            email = input("Entrez votre email: ")
            pwd = input("Entrez votre mot de passe: ")
            if authenticate_user(email, pwd):
                
                authenticated_menu()
                
            else:
                print("Authentification échouée.")
        else:
            print("Option invalide. Veuillez choisir 1 ou 2.")

if __name__ == "__main__":
    main_menu()