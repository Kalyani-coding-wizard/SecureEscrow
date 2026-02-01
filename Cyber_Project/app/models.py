"""
Database models for the Secure Escrow Platform.
"""

from datetime import datetime
from flask_login import UserMixin
from . import db, login_manager
import json


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    """User model with RSA keys and role-based access."""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    public_key = db.Column(db.Text, nullable=True)  # PEM format
    private_key_encrypted = db.Column(db.LargeBinary, nullable=True)  # Encrypted with user password
    role = db.Column(db.String(20), default='signatory')  # initiator, signatory, auditor, admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Multi-Factor Authentication (MFA) - TOTP
    totp_secret = db.Column(db.String(32), nullable=True)  # Base32 encoded secret
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_backup_codes = db.Column(db.Text, nullable=True)  # JSON list of backup codes
    
    # Relationships
    contracts = db.relationship('Contract', backref='owner', lazy='dynamic')
    signatures = db.relationship('Signature', backref='signer', lazy='dynamic')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def is_admin(self):
        return self.role == 'admin'
    
    def is_auditor(self):
        return self.role in ['auditor', 'admin']
    
    def can_initiate(self):
        return self.role in ['initiator', 'admin']


class Contract(db.Model):
    """Contract/Document model with encryption metadata."""
    __tablename__ = 'contracts'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, partially_signed, finalized
    file_hash = db.Column(db.String(64), nullable=False)  # SHA-256 hash
    encrypted_path = db.Column(db.String(500), nullable=False)
    _required_signers = db.Column('required_signers', db.Text, default='[]')  # JSON list of user IDs
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    finalized_at = db.Column(db.DateTime, nullable=True)
    description = db.Column(db.Text, nullable=True)
    
    # Relationships
    signatures = db.relationship('Signature', backref='contract', lazy='dynamic', cascade='all, delete-orphan')
    
    @property
    def required_signers(self):
        return json.loads(self._required_signers) if self._required_signers else []
    
    @required_signers.setter
    def required_signers(self, value):
        self._required_signers = json.dumps(value)
    
    def __repr__(self):
        return f'<Contract {self.filename}>'
    
    def get_signature_count(self):
        """Return count of valid signatures."""
        return self.signatures.filter_by(verified=True).count()
    
    def get_required_count(self):
        """Return count of required signatures."""
        return len(self.required_signers)
    
    def is_fully_signed(self):
        """Check if all required signers have signed."""
        signed_user_ids = set(s.user_id for s in self.signatures.filter_by(verified=True).all())
        required_ids = set(self.required_signers)
        return required_ids.issubset(signed_user_ids)
    
    def get_pending_signers(self):
        """Return list of users who haven't signed yet."""
        signed_user_ids = set(s.user_id for s in self.signatures.filter_by(verified=True).all())
        pending_ids = [uid for uid in self.required_signers if uid not in signed_user_ids]
        return User.query.filter(User.id.in_(pending_ids)).all() if pending_ids else []
    
    def get_signed_users(self):
        """Return list of users who have signed."""
        signed_user_ids = [s.user_id for s in self.signatures.filter_by(verified=True).all()]
        return User.query.filter(User.id.in_(signed_user_ids)).all() if signed_user_ids else []
    
    def can_user_sign(self, user_id):
        """Check if a user is required to sign and hasn't signed yet."""
        if user_id not in self.required_signers:
            return False
        existing_sig = self.signatures.filter_by(user_id=user_id, verified=True).first()
        return existing_sig is None
    
    def update_status(self):
        """Update contract status based on signatures."""
        if self.status == 'finalized':
            return
        
        if self.is_fully_signed():
            self.status = 'finalized'
            self.finalized_at = datetime.utcnow()
        elif self.get_signature_count() > 0:
            self.status = 'partially_signed'
        else:
            self.status = 'pending'


class Signature(db.Model):
    """Digital signature model."""
    __tablename__ = 'signatures'
    
    id = db.Column(db.Integer, primary_key=True)
    contract_id = db.Column(db.Integer, db.ForeignKey('contracts.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    signature_blob = db.Column(db.LargeBinary, nullable=False)  # Binary signature data
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    verified = db.Column(db.Boolean, default=False)
    verification_timestamp = db.Column(db.DateTime, nullable=True)
    
    # Unique constraint: one signature per user per contract
    __table_args__ = (db.UniqueConstraint('contract_id', 'user_id', name='unique_user_contract_signature'),)
    
    def __repr__(self):
        return f'<Signature Contract:{self.contract_id} User:{self.user_id}>'


class AuditLog(db.Model):
    """Immutable audit log for all critical actions."""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 compatible
    details = db.Column(db.Text, nullable=True)  # JSON additional data
    resource_type = db.Column(db.String(50), nullable=True)  # e.g., 'contract', 'user'
    resource_id = db.Column(db.Integer, nullable=True)
    
    def __repr__(self):
        return f'<AuditLog {self.action} at {self.timestamp}>'
    
    @classmethod
    def log(cls, action, user_id=None, ip_address=None, details=None, resource_type=None, resource_id=None):
        """Create a new audit log entry."""
        from . import db
        log_entry = cls(
            action=action,
            user_id=user_id,
            ip_address=ip_address,
            details=json.dumps(details) if details else None,
            resource_type=resource_type,
            resource_id=resource_id
        )
        db.session.add(log_entry)
        db.session.commit()
        return log_entry
