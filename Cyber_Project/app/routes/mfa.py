"""
Multi-Factor Authentication (MFA) routes for the Secure Escrow Platform.
Implements TOTP-based two-factor authentication.
"""

import pyotp
import secrets
import io
import base64
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_required, current_user

from ..models import User, AuditLog
from .. import db
from ..encoding_utils import generate_qr_code, generate_totp_uri, base64_encode

mfa_bp = Blueprint('mfa', __name__)


def generate_totp_secret():
    """
    Generate a secure TOTP secret.
    
    TOTP Properties:
    - Algorithm: HMAC-SHA1 (RFC 6238)
    - Secret Length: 160 bits (32 base32 characters)
    - Time Step: 30 seconds
    - Digits: 6
    """
    return pyotp.random_base32()


def verify_totp(secret: str, code: str) -> bool:
    """
    Verify a TOTP code against the secret.
    Allows for 1 time step tolerance (±30 seconds).
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def generate_backup_codes(count: int = 8) -> list:
    """
    Generate one-time backup codes for MFA recovery.
    Each code is 8 alphanumeric characters.
    """
    codes = []
    for _ in range(count):
        code = secrets.token_hex(4).upper()  # 8 hex characters
        codes.append(code)
    return codes


@mfa_bp.route('/setup', methods=['GET', 'POST'])
@login_required
def setup():
    """Set up MFA for the current user."""
    if current_user.mfa_enabled:
        flash('MFA is already enabled on your account.', 'info')
        return redirect(url_for('auth.profile'))
    
    if request.method == 'POST':
        # Verify the code before enabling
        code = request.form.get('code', '').strip().replace(' ', '')
        secret = session.get('mfa_setup_secret')
        
        if not secret:
            flash('MFA setup session expired. Please try again.', 'danger')
            return redirect(url_for('mfa.setup'))
        
        if verify_totp(secret, code):
            # Generate backup codes
            backup_codes = generate_backup_codes()
            
            # Save to user
            current_user.totp_secret = secret
            current_user.mfa_enabled = True
            current_user.mfa_backup_codes = ','.join(backup_codes)
            db.session.commit()
            
            # Clear session
            session.pop('mfa_setup_secret', None)
            
            # Log action
            AuditLog.log(
                action='MFA_ENABLED',
                user_id=current_user.id,
                ip_address=request.remote_addr
            )
            
            flash('MFA has been enabled successfully!', 'success')
            return render_template('mfa/backup_codes.html', backup_codes=backup_codes)
        else:
            flash('Invalid verification code. Please try again.', 'danger')
    
    # Generate new secret if not in session
    if 'mfa_setup_secret' not in session:
        session['mfa_setup_secret'] = generate_totp_secret()
    
    secret = session['mfa_setup_secret']
    
    # Generate QR code
    totp_uri = generate_totp_uri(secret, current_user.username)
    qr_bytes = generate_qr_code(totp_uri)
    qr_base64 = base64_encode(qr_bytes)
    
    return render_template('mfa/setup.html', 
                          secret=secret, 
                          qr_code=qr_base64)


@mfa_bp.route('/verify', methods=['GET', 'POST'])
def verify():
    """Verify MFA code during login."""
    # Check if user is in MFA verification state
    pending_user_id = session.get('mfa_pending_user_id')
    if not pending_user_id:
        flash('No pending MFA verification.', 'warning')
        return redirect(url_for('auth.login'))
    
    user = User.query.get(pending_user_id)
    if not user:
        session.pop('mfa_pending_user_id', None)
        flash('User not found.', 'danger')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        code = request.form.get('code', '').strip().replace(' ', '')
        
        # Check if it's a backup code
        if len(code) == 8 and code.isalnum():
            backup_codes = user.mfa_backup_codes.split(',') if user.mfa_backup_codes else []
            if code.upper() in backup_codes:
                # Remove used backup code
                backup_codes.remove(code.upper())
                user.mfa_backup_codes = ','.join(backup_codes)
                db.session.commit()
                
                # Complete login
                from flask_login import login_user
                login_user(user, remember=session.pop('mfa_remember', False))
                session.pop('mfa_pending_user_id', None)
                
                AuditLog.log(
                    action='MFA_LOGIN_BACKUP_CODE',
                    user_id=user.id,
                    ip_address=request.remote_addr
                )
                
                flash(f'Welcome back, {user.username}! (Backup code used - {len(backup_codes)} remaining)', 'success')
                return redirect(url_for('contracts.dashboard'))
        
        # Verify TOTP code
        if verify_totp(user.totp_secret, code):
            from flask_login import login_user
            login_user(user, remember=session.pop('mfa_remember', False))
            session.pop('mfa_pending_user_id', None)
            
            AuditLog.log(
                action='MFA_LOGIN_SUCCESS',
                user_id=user.id,
                ip_address=request.remote_addr
            )
            
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('contracts.dashboard'))
        else:
            AuditLog.log(
                action='MFA_LOGIN_FAILED',
                user_id=user.id,
                ip_address=request.remote_addr
            )
            flash('Invalid verification code.', 'danger')
    
    return render_template('mfa/verify.html', username=user.username)


@mfa_bp.route('/disable', methods=['POST'])
@login_required
def disable():
    """Disable MFA for the current user."""
    if not current_user.mfa_enabled:
        flash('MFA is not enabled on your account.', 'info')
        return redirect(url_for('auth.profile'))
    
    password = request.form.get('password', '')
    
    from .. import bcrypt
    if bcrypt.check_password_hash(current_user.password_hash, password):
        current_user.totp_secret = None
        current_user.mfa_enabled = False
        current_user.mfa_backup_codes = None
        db.session.commit()
        
        AuditLog.log(
            action='MFA_DISABLED',
            user_id=current_user.id,
            ip_address=request.remote_addr
        )
        
        flash('MFA has been disabled.', 'success')
    else:
        flash('Invalid password.', 'danger')
    
    return redirect(url_for('auth.profile'))


@mfa_bp.route('/regenerate-backup-codes', methods=['POST'])
@login_required
def regenerate_backup_codes():
    """Regenerate backup codes."""
    if not current_user.mfa_enabled:
        flash('MFA is not enabled on your account.', 'warning')
        return redirect(url_for('auth.profile'))
    
    code = request.form.get('code', '').strip()
    
    if verify_totp(current_user.totp_secret, code):
        backup_codes = generate_backup_codes()
        current_user.mfa_backup_codes = ','.join(backup_codes)
        db.session.commit()
        
        AuditLog.log(
            action='MFA_BACKUP_CODES_REGENERATED',
            user_id=current_user.id,
            ip_address=request.remote_addr
        )
        
        return render_template('mfa/backup_codes.html', backup_codes=backup_codes)
    else:
        flash('Invalid verification code.', 'danger')
        return redirect(url_for('auth.profile'))
