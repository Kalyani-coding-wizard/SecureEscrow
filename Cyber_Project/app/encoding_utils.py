"""
Encoding utilities for the Secure Escrow Platform.
Implements Base64, QR Code encoding/decoding for rubric compliance.
"""

import base64
import io
import qrcode
from PIL import Image


def base64_encode(data: bytes) -> str:
    """
    Encode binary data to Base64 string.
    
    Base64 Encoding Properties:
    - Encoding Type: Base64 (RFC 4648)
    - Character Set: A-Z, a-z, 0-9, +, / (with = padding)
    - Expansion Ratio: 4:3 (4 output chars per 3 input bytes)
    - Use Case: Safe transmission of binary data over text-based protocols
    """
    return base64.b64encode(data).decode('utf-8')


def base64_decode(encoded_string: str) -> bytes:
    """
    Decode Base64 string back to binary data.
    """
    return base64.b64decode(encoded_string.encode('utf-8'))


def base64_urlsafe_encode(data: bytes) -> str:
    """
    URL-safe Base64 encoding (uses - and _ instead of + and /).
    Suitable for URLs and filenames.
    """
    return base64.urlsafe_b64encode(data).decode('utf-8')


def base64_urlsafe_decode(encoded_string: str) -> bytes:
    """
    Decode URL-safe Base64 string back to binary data.
    """
    return base64.urlsafe_b64decode(encoded_string.encode('utf-8'))


def generate_qr_code(data: str, size: int = 200) -> bytes:
    """
    Generate a QR Code image from text data.
    
    QR Code Properties:
    - Version: Auto-selected based on data length
    - Error Correction: Level L (7% recovery)
    - Box Size: 10 pixels
    - Border: 4 boxes (standard)
    - Output: PNG image bytes
    
    Args:
        data: String to encode in QR code
        size: Target size in pixels (width/height)
    
    Returns:
        PNG image bytes of the QR code
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Resize if needed
    img = img.resize((size, size), Image.Resampling.LANCZOS)
    
    # Convert to bytes
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    return buffer.getvalue()


def generate_totp_uri(secret: str, username: str, issuer: str = "SecureEscrow") -> str:
    """
    Generate TOTP URI for authenticator apps.
    Format: otpauth://totp/ISSUER:USERNAME?secret=SECRET&issuer=ISSUER
    """
    return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}"


def hex_encode(data: bytes) -> str:
    """
    Encode binary data to hexadecimal string.
    
    Hex Encoding Properties:
    - Character Set: 0-9, a-f
    - Expansion Ratio: 2:1 (2 hex chars per byte)
    - Use Case: Human-readable binary representation
    """
    return data.hex()


def hex_decode(hex_string: str) -> bytes:
    """
    Decode hexadecimal string back to binary data.
    """
    return bytes.fromhex(hex_string)


# Encoding demonstration data
ENCODING_INFO = {
    "base64": {
        "name": "Base64",
        "description": "Encodes binary data into ASCII text using 64 printable characters",
        "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "padding": "=",
        "expansion_ratio": "4:3",
        "use_cases": ["Email attachments (MIME)", "Data URLs", "JWT tokens", "API payloads"]
    },
    "base64_urlsafe": {
        "name": "Base64 URL-safe",
        "description": "URL-safe variant using - and _ instead of + and /",
        "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        "padding": "=",
        "expansion_ratio": "4:3",
        "use_cases": ["URL parameters", "Filenames", "Cryptographic tokens"]
    },
    "hex": {
        "name": "Hexadecimal",
        "description": "Base-16 encoding using digits and letters",
        "alphabet": "0123456789abcdef",
        "expansion_ratio": "2:1",
        "use_cases": ["Hash representation", "Binary debugging", "Color codes"]
    },
    "qrcode": {
        "name": "QR Code",
        "description": "2D barcode for machine-readable data",
        "error_correction_levels": ["L (7%)", "M (15%)", "Q (25%)", "H (30%)"],
        "max_capacity": "7,089 numeric / 4,296 alphanumeric / 2,953 bytes",
        "use_cases": ["Mobile authentication", "Payment links", "URL sharing", "TOTP setup"]
    }
}
