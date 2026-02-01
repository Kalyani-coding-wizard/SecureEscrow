# SecureEscrow

A **Zero-Knowledge Digital Escrow Platform** built with Flask, featuring cryptographic security, multi-party contract signing, and comprehensive audit logging.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Features

### Security
- **AES-256 Encryption** - All contracts encrypted at rest
- **RSA-2048 Digital Signatures** - Cryptographic signing for authenticity
- **SHA-256 Integrity Verification** - Document tampering detection
- **OTP Authentication** - One-time passwords for login verification
- **TOTP Multi-Factor Authentication** - Optional TOTP-based MFA with backup codes
- **NIST SP 800-63-2 Compliant Passwords** - Strong password requirements
- **Rate Limiting with Exponential Backoff** - Brute-force protection

### Role-Based Access Control (RBAC)
| Role | Permissions |
|------|-------------|
| **Admin** | Full system access, user management, statistics |
| **Initiator** | Create and upload contracts |
| **Signatory** | Sign assigned contracts |
| **Auditor** | View audit logs and integrity reports |

### Core Functionality
- Upload and encrypt contracts
- Multi-party digital signing workflow
- Signature verification
- Admin dashboard with statistics
- Immutable audit logging
- File integrity checking

## Quick Start

### Prerequisites
- Python 3.10+
- pip

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Cyber_Project
   ```

2. **Create virtual environment** (optional but recommended)
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   flask --app app run --debug
   ```

5. **Access the application**
   Open http://127.0.0.1:5000 in your browser

## Project Structure

```
Cyber_Project/
├── app/
│   ├── __init__.py          # App factory
│   ├── config.py             # Configuration
│   ├── models.py             # Database models
│   ├── crypto_utils.py       # RSA/AES cryptography
│   ├── otp_manager.py        # OTP authentication
│   ├── rate_limiter.py       # Brute-force protection
│   ├── password_validator.py # NIST password validation
│   ├── routes/
│   │   ├── auth.py           # Authentication routes
│   │   ├── contracts.py      # Contract management
│   │   ├── signing.py        # Digital signing
│   │   ├── admin.py          # Admin panel
│   │   └── mfa.py            # Multi-factor auth
│   ├── templates/            # Jinja2 HTML templates
│   └── static/               # CSS, JS assets
├── uploads/                  # Encrypted file storage
├── keys/                     # Server encryption keys
├── requirements.txt
└── README.md
```

## Security Architecture

### Encryption Flow
```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  User File  │ ──▶ │  AES-256     │ ──▶ │  Encrypted  │
│             │     │  Encryption  │     │  Storage    │
└─────────────┘     └──────────────┘     └─────────────┘
                           │
                    SHA-256 Hash
                           │
                    ┌──────▼──────┐
                    │   Database  │
                    │  (Metadata) │
                    └─────────────┘
```

### Signing Flow
```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  File Hash   │ ──▶ │  RSA-2048    │ ──▶ │  Signature   │
│  (SHA-256)   │     │  Private Key │     │  Stored      │
└──────────────┘     └──────────────┘     └──────────────┘
```

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| Flask | 3.0.0 | Web framework |
| Flask-SQLAlchemy | 3.1.1 | Database ORM |
| Flask-Login | 0.6.3 | User session management |
| Flask-Bcrypt | 1.0.1 | Password hashing |
| cryptography | 41.0.7 | RSA/AES encryption |
| pyotp | 2.9.0 | TOTP MFA |
| qrcode | 7.4.2 | MFA QR code generation |

## 🔧 Configuration

Environment variables (optional):
```bash
SECRET_KEY=your-secret-key
SQLALCHEMY_DATABASE_URI=sqlite:///site.db
FERNET_KEY=your-fernet-key
```

## Usage

### Register a New Account
1. Navigate to `/auth/register`
2. Choose your role (Signatory, Initiator, Auditor, Admin)
3. Your RSA key pair is generated automatically

### Upload a Contract (Initiator/Admin)
1. Go to Dashboard → Upload Contract
2. Select file and add description
3. Assign required signers
4. Contract is encrypted and stored

### Sign a Contract
1. View contract from Dashboard
2. Enter your password to unlock private key
3. Digital signature is created and verified

### Admin Functions
- View audit logs
- Run integrity checks
- Manage users
- View system statistics

## Testing

Run the development server with debug mode:
```bash
py -m flask --app app run --debug
```

OTP codes are printed to the terminal during login.

## License

This project is for educational/demonstration purposes.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

---

**Built withFlask and modern cryptography**
 
