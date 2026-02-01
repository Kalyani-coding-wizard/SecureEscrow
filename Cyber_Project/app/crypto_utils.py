"""
Cryptographic utilities for the Secure Escrow Platform.
Handles encryption, decryption, hashing, and digital signatures.
"""

import os
import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


def generate_rsa_keypair():
    """
    Generate a new RSA 2048-bit key pair.
    Returns: (private_key_pem, public_key_pem) as bytes
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem


def encrypt_private_key(private_key_pem: bytes, password: str) -> bytes:
    """
    Encrypt a private key with a password using Fernet.
    """
    # Derive a key from the password
    key = hashlib.sha256(password.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key)
    f = Fernet(fernet_key)
    return f.encrypt(private_key_pem)


def decrypt_private_key(encrypted_key: bytes, password: str) -> bytes:
    """
    Decrypt a private key with a password.
    """
    key = hashlib.sha256(password.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key)
    f = Fernet(fernet_key)
    return f.decrypt(encrypted_key)


def hash_file(file_data: bytes) -> str:
    """
    Calculate SHA-256 hash of file data.
    Returns: Hex string of the hash
    """
    return hashlib.sha256(file_data).hexdigest()


def encrypt_file(file_data: bytes, fernet_instance: Fernet) -> bytes:
    """
    Encrypt file data using Fernet (AES-256).
    """
    return fernet_instance.encrypt(file_data)


def decrypt_file(encrypted_data: bytes, fernet_instance: Fernet) -> bytes:
    """
    Decrypt file data using Fernet (AES-256).
    """
    return fernet_instance.decrypt(encrypted_data)


def sign_data(data: bytes, private_key_pem: bytes) -> bytes:
    """
    Sign data using RSA private key.
    Returns: Signature as bytes
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature


def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """
    Verify a signature using RSA public key.
    Returns: True if valid, False otherwise
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
        
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def hash_data(data: bytes) -> bytes:
    """
    Return SHA-256 hash of data as bytes.
    Used for signing operations.
    """
    return hashlib.sha256(data).digest()
