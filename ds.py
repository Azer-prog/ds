import re
import hashlib
import bcrypt


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

# Menu principal
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
                print("Authentification réussie.")
                # Mettez ici la logique du sous-menu pour les opérations de hachage et de chiffrement RSA.
            else:
                print("Authentification échouée.")
        else:
            print("Option invalide. Veuillez choisir 1 ou 2.")

if __name__ == "__main__":
    main_menu()

