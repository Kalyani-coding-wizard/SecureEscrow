"""
Password Validation Module for NIST SP 800-63-2 Compliance.
Implements password strength requirements per E-Authentication Architecture Model.
"""

import re
from typing import Tuple, List


# NIST SP 800-63-2 Password Requirements
PASSWORD_REQUIREMENTS = {
    'min_length': 8,
    'require_uppercase': True,
    'require_lowercase': True,
    'require_digit': True,
    'require_special': True,
    'special_characters': r'!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?`~'
}

# Common weak passwords (NIST recommends blocking these)
COMMON_PASSWORDS = {
    'password', 'password1', 'password123', '12345678', 'qwerty123',
    'letmein', 'welcome', 'admin123', 'iloveyou', 'sunshine',
    'princess', 'football', 'monkey123', 'shadow', 'master',
    'dragon', 'trustno1', 'whatever', 'qazwsx', 'michael'
}


def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
    """
    Validate password against NIST SP 800-63-2 requirements.
    
    Requirements:
    - Minimum 8 characters
    - At least 1 uppercase letter (A-Z)
    - At least 1 lowercase letter (a-z)
    - At least 1 digit (0-9)
    - At least 1 special character (!@#$%^&*...)
    - Not a commonly used password
    
    Args:
        password: The password to validate
        
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []
    
    # Length check
    if len(password) < PASSWORD_REQUIREMENTS['min_length']:
        errors.append(f"Password must be at least {PASSWORD_REQUIREMENTS['min_length']} characters long.")
    
    # Uppercase check
    if PASSWORD_REQUIREMENTS['require_uppercase'] and not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least 1 uppercase letter (A-Z).")
    
    # Lowercase check  
    if PASSWORD_REQUIREMENTS['require_lowercase'] and not re.search(r'[a-z]', password):
        errors.append("Password must contain at least 1 lowercase letter (a-z).")
    
    # Digit check
    if PASSWORD_REQUIREMENTS['require_digit'] and not re.search(r'\d', password):
        errors.append("Password must contain at least 1 number (0-9).")
    
    # Special character check
    if PASSWORD_REQUIREMENTS['require_special']:
        special_pattern = f"[{re.escape(PASSWORD_REQUIREMENTS['special_characters'])}]"
        if not re.search(special_pattern, password):
            errors.append("Password must contain at least 1 special character (!@#$%^&*...).")
    
    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        errors.append("This password is too common. Please choose a stronger password.")
    
    is_valid = len(errors) == 0
    return is_valid, errors


def get_password_strength_score(password: str) -> int:
    """
    Calculate password strength score (0-100).
    
    Scoring:
    - Length: up to 25 points
    - Uppercase: 15 points
    - Lowercase: 15 points
    - Digits: 15 points
    - Special chars: 20 points
    - Variety bonus: 10 points
    """
    score = 0
    
    # Length score (max 25 points)
    length_score = min(len(password) * 2, 25)
    score += length_score
    
    # Character type scores
    if re.search(r'[A-Z]', password):
        score += 15
    if re.search(r'[a-z]', password):
        score += 15
    if re.search(r'\d', password):
        score += 15
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?`~]', password):
        score += 20
    
    # Variety bonus (multiple character types)
    char_types = sum([
        bool(re.search(r'[A-Z]', password)),
        bool(re.search(r'[a-z]', password)),
        bool(re.search(r'\d', password)),
        bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?`~]', password))
    ])
    if char_types >= 4:
        score += 10
    
    return min(score, 100)


def get_strength_label(score: int) -> str:
    """Get human-readable strength label."""
    if score < 30:
        return "Very Weak"
    elif score < 50:
        return "Weak"
    elif score < 70:
        return "Moderate"
    elif score < 90:
        return "Strong"
    else:
        return "Very Strong"


# NIST SP 800-63-2 Compliance Information
NIST_COMPLIANCE_INFO = """
NIST SP 800-63-2 E-Authentication Architecture Compliance:

Level 1 (Little or no confidence):
- Single-factor authentication
- Memorized secret (password)

Level 2 (Some confidence):  
- Single-factor authentication with stronger credentials
- Password + cryptographic device OR
- Multi-factor authentication

Level 3 (High confidence):
- Multi-factor authentication required
- Hardware token or biometric + password

Level 4 (Very high confidence):
- Multi-factor with hardware cryptographic authenticator
- In-person identity proofing required

This application implements:
- Password complexity requirements (Level 1+)
- bcrypt hashing with salt (Level 2)
- Optional TOTP MFA (Level 3)
- RSA key pair per user (cryptographic credentials)
"""
