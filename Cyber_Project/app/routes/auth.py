"""
Authentication routes for the Secure Escrow Platform.
Handles user registration, login, logout with RSA key generation.
Implements OTP verification and rate limiting.
"""

from functools import wraps
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from ..models import User, AuditLog
from .. import db, bcrypt
from ..crypto_utils import generate_rsa_keypair, encrypt_private_key
from ..otp_manager import OTPManager
from ..rate_limiter import RateLimiter

auth_bp = Blueprint('auth', __name__)

# Available roles for registration
AVAILABLE_ROLES = ['signatory', 'initiator', 'auditor', 'admin']


def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        if not current_user.is_admin():
            flash('Admin access required.', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function


def auditor_required(f):
    """Decorator to require auditor or admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        if not current_user.is_auditor():
            flash('Auditor access required.', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function


def initiator_required(f):
    """Decorator to require initiator or admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        if not current_user.can_initiate():
            flash('Initiator access required to create contracts.', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    User registration with RSA key pair generation.
    Implements NIST SP 800-63-2 E-Authentication Architecture Model.
    Allows role selection for RBAC demonstration.
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        selected_role = request.form.get('role', 'signatory')
        
        # Import NIST password validator
        from ..password_validator import validate_password_strength
        
        # Validation
        errors = []
        
        # Username validation
        if len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if not username.replace('_', '').isalnum():
            errors.append('Username can only contain letters, numbers, and underscores.')
        
        # NIST SP 800-63-2 Password Validation
        is_valid_password, password_errors = validate_password_strength(password)
        if not is_valid_password:
            errors.extend(password_errors)
        
        # Confirm password match
        if password != confirm_password:
            errors.append('Passwords do not match.')
        
        # Email validation
        if not email or '@' not in email:
            errors.append('Please provide a valid email address.')
        
        # Role validation
        if selected_role not in AVAILABLE_ROLES:
            errors.append('Invalid role selected.')
            selected_role = 'signatory'
        
        # Uniqueness checks
        if User.query.filter_by(username=username).first():
            errors.append('Username already exists.')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('auth/register.html', roles=AVAILABLE_ROLES)
        
        # Generate RSA key pair
        private_key_pem, public_key_pem = generate_rsa_keypair()
        
        # Encrypt private key with user's password
        encrypted_private_key = encrypt_private_key(private_key_pem, password)
        
        # Hash password with bcrypt
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Create user with selected role
        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            public_key=public_key_pem.decode('utf-8'),
            private_key_encrypted=encrypted_private_key,
            role=selected_role
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Log registration
        AuditLog.log(
            action='USER_REGISTERED',
            user_id=user.id,
            ip_address=request.remote_addr,
            details={'username': username, 'role': selected_role}
        )
        
        flash(f'Registration successful! You registered as {selected_role.capitalize()}. Please log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html', roles=AVAILABLE_ROLES)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    User login with rate limiting and OTP verification.
    Implements brute force protection with exponential backoff.
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)
        
        # Check rate limiting first
        is_allowed, lockout_message, remaining_seconds = RateLimiter.check_rate_limit(username)
        if not is_allowed:
            flash(lockout_message, 'danger')
            AuditLog.log(
                action='LOGIN_BLOCKED_RATE_LIMIT',
                ip_address=request.remote_addr,
                details={'username': username, 'lockout_seconds': remaining_seconds}
            )
            return render_template('auth/login.html', lockout_seconds=remaining_seconds)
        
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, password):
            if not user.is_active:
                flash('Your account has been deactivated.', 'danger')
                return render_template('auth/login.html')
            
            # Record successful login attempt (resets counter)
            RateLimiter.record_successful_login(username)
            
            # Store user info in session for OTP verification
            session['otp_pending_user_id'] = user.id
            session['otp_remember'] = remember
            
            # Generate and send OTP (OTPManager handles console output)
            OTPManager.create_and_store_otp(user.email)
            
            AuditLog.log(
                action='OTP_SENT',
                user_id=user.id,
                ip_address=request.remote_addr
            )
            
            flash('OTP has been sent. Check the console for the code.', 'info')
            return redirect(url_for('auth.verify_otp'))
        else:
            # Record failed attempt and check if locked
            is_locked, message, lockout_seconds = RateLimiter.record_failed_attempt(username)
            
            # Log failed attempt
            AuditLog.log(
                action='LOGIN_FAILED',
                ip_address=request.remote_addr,
                details={'attempted_username': username, 'locked': is_locked}
            )
            
            flash(message, 'danger')
            
            if is_locked:
                return render_template('auth/login.html', lockout_seconds=lockout_seconds)
    
    return render_template('auth/login.html')


@auth_bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    """Verify OTP after password authentication."""
    # Check if user is in OTP verification state
    pending_user_id = session.get('otp_pending_user_id')
    if not pending_user_id:
        flash('No pending OTP verification. Please log in.', 'warning')
        return redirect(url_for('auth.login'))
    
    user = User.query.get(pending_user_id)
    if not user:
        session.pop('otp_pending_user_id', None)
        flash('User not found.', 'danger')
        return redirect(url_for('auth.login'))
    
    time_remaining = OTPManager.get_time_remaining()
    can_resend, resend_wait = OTPManager.can_resend_otp()
    
    if request.method == 'POST':
        action = request.form.get('action', 'verify')
        
        if action == 'resend':
            # Resend OTP
            if can_resend:
                OTPManager.create_and_store_otp(user.email)
                AuditLog.log(
                    action='OTP_RESENT',
                    user_id=user.id,
                    ip_address=request.remote_addr
                )
                flash('New OTP has been sent. Check the console.', 'info')
            else:
                flash(f'Please wait {resend_wait} seconds before requesting a new OTP.', 'warning')
            return redirect(url_for('auth.verify_otp'))
        
        # Verify OTP
        otp_code = request.form.get('otp', '').strip()
        is_valid, message = OTPManager.verify_otp(otp_code)
        
        if is_valid:
            remember = session.pop('otp_remember', False)
            session.pop('otp_pending_user_id', None)
            
            # Check if MFA is also enabled
            if user.mfa_enabled:
                session['mfa_pending_user_id'] = user.id
                session['mfa_remember'] = remember
                
                AuditLog.log(
                    action='OTP_VERIFIED_MFA_REQUIRED',
                    user_id=user.id,
                    ip_address=request.remote_addr
                )
                
                return redirect(url_for('mfa.verify'))
            
            # Complete login
            login_user(user, remember=remember)
            
            AuditLog.log(
                action='USER_LOGIN',
                user_id=user.id,
                ip_address=request.remote_addr
            )
            
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('contracts.dashboard'))
        else:
            AuditLog.log(
                action='OTP_VERIFICATION_FAILED',
                user_id=user.id,
                ip_address=request.remote_addr
            )
            flash(message, 'danger')
    
    return render_template('auth/verify_otp.html', 
                          email=user.email,
                          time_remaining=time_remaining,
                          can_resend=can_resend)


@auth_bp.route('/cancel-otp')
def cancel_otp():
    """Cancel OTP verification and return to login."""
    OTPManager.clear_otp()
    session.pop('otp_pending_user_id', None)
    session.pop('otp_remember', None)
    flash('Login cancelled.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/logout')
@login_required
def logout():
    """Log out the current user."""
    # Log logout
    AuditLog.log(
        action='USER_LOGOUT',
        user_id=current_user.id,
        ip_address=request.remote_addr
    )
    
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))


@auth_bp.route('/profile')
@login_required
def profile():
    """View user profile and public key."""
    return render_template('auth/profile.html', user=current_user)
