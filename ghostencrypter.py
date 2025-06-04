import hashlib
import sys

DEFAULT_ALGORITHM = 'sha256'

def encrypt_password(password, algorithm=DEFAULT_ALGORITHM):
    algorithm = algorithm.lower()
    
    if algorithm not in hashlib.algorithms_available:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}")
    
    hash_algorithm = getattr(hashlib, algorithm)()
    hash_algorithm.update(password.encode('utf-8'))
    hashed_password = hash_algorithm.hexdigest()
    return hashed_password

def print_available_algorithms():
    print("Available hashing algorithms:")
    for algorithm in sorted(hashlib.algorithms_available):
        print(algorithm)

def main():
    if len(sys.argv) < 2:
        print("Usage: python password_encrypt.py <password> [algorithm]")
        print("Example: python password_encrypt.py mypassword sha256")
        sys.exit(1)

    if sys.argv[1] in ['-h', '--help']:
        print_available_algorithms()
        sys.exit(0)

    password = sys.argv[1]
    algorithm = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_ALGORITHM

    try:
        encrypted_password = encrypt_password(password, algorithm)
        print(f"Encrypted password using {algorithm.upper()} algorithm:", encrypted_password)
    except ValueError as ve:
        print(ve)
        sys.exit(1)

if __name__ == "__main__":
    main()
