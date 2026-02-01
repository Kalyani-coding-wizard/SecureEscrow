"""
Contract management routes for the Secure Escrow Platform.
Handles file upload, encryption, and escrow vault logic.
"""

import os
import uuid
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, send_file, abort
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from io import BytesIO

from ..models import Contract, User, AuditLog
from .. import db, fernet
from ..crypto_utils import hash_file, encrypt_file, decrypt_file
from .auth import initiator_required

contracts_bp = Blueprint('contracts', __name__)


def allowed_file(filename):
    """Check if file extension is allowed (PDF only)."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']


@contracts_bp.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard showing all contracts relevant to the user."""
    # Get contracts owned by user
    owned_contracts = Contract.query.filter_by(owner_id=current_user.id).order_by(Contract.created_at.desc()).all()
    
    # Get contracts where user is a required signer
    all_contracts = Contract.query.all()
    pending_signatures = [c for c in all_contracts if current_user.id in c.required_signers and c.can_user_sign(current_user.id)]
    signed_contracts = [c for c in all_contracts if current_user.id in c.required_signers and not c.can_user_sign(current_user.id)]
    
    return render_template('contracts/dashboard.html',
                          owned_contracts=owned_contracts,
                          pending_signatures=pending_signatures,
                          signed_contracts=signed_contracts)


@contracts_bp.route('/upload', methods=['GET', 'POST'])
@login_required
@initiator_required
def upload():
    """Upload a new contract document."""
    if request.method == 'POST':
        # Check if file was submitted
        if 'document' not in request.files:
            flash('No file selected.', 'danger')
            return redirect(request.url)
        
        file = request.files['document']
        
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(request.url)
        
        if not allowed_file(file.filename):
            flash('Only PDF files are allowed.', 'danger')
            return redirect(request.url)
        
        # Read file data
        file_data = file.read()
        
        # Calculate SHA-256 hash BEFORE encryption
        file_hash = hash_file(file_data)
        
        # Encrypt file data with server Fernet key
        encrypted_data = encrypt_file(file_data, fernet)
        
        # Generate unique filename
        original_filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{original_filename}.enc"
        encrypted_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
        
        # Save encrypted file
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Get required signers
        signer_ids = request.form.getlist('signers')
        signer_ids = [int(sid) for sid in signer_ids if sid.isdigit()]
        
        # Create contract record
        contract = Contract(
            filename=unique_filename,
            original_filename=original_filename,
            owner_id=current_user.id,
            file_hash=file_hash,
            encrypted_path=encrypted_path,
            description=request.form.get('description', ''),
            status='pending'
        )
        contract.required_signers = signer_ids
        
        db.session.add(contract)
        db.session.commit()
        
        # Log upload
        AuditLog.log(
            action='CONTRACT_UPLOADED',
            user_id=current_user.id,
            ip_address=request.remote_addr,
            resource_type='contract',
            resource_id=contract.id,
            details={
                'filename': original_filename,
                'file_hash': file_hash,
                'required_signers': signer_ids
            }
        )
        
        flash(f'Contract "{original_filename}" uploaded and encrypted successfully!', 'success')
        return redirect(url_for('contracts.view', contract_id=contract.id))
    
    # GET request - show upload form
    # Get all users who can sign (excluding current user)
    potential_signers = User.query.filter(User.id != current_user.id, User.is_active == True).all()
    
    return render_template('contracts/upload.html', potential_signers=potential_signers)


@contracts_bp.route('/<int:contract_id>')
@login_required
def view(contract_id):
    """View contract details and signature status."""
    contract = Contract.query.get_or_404(contract_id)
    
    # Check access: owner, required signer, or auditor
    has_access = (
        contract.owner_id == current_user.id or
        current_user.id in contract.required_signers or
        current_user.is_auditor()
    )
    
    if not has_access:
        flash('You do not have access to this contract.', 'danger')
        return redirect(url_for('contracts.dashboard'))
    
    # Get signature details
    signed_users = contract.get_signed_users()
    pending_users = contract.get_pending_signers()
    can_sign = contract.can_user_sign(current_user.id)
    
    # Get available signers for adding (users not already required to sign)
    current_signers = contract.required_signers
    available_signers = User.query.filter(
        User.id != current_user.id,
        User.is_active == True,
        ~User.id.in_(current_signers) if current_signers else True
    ).all()
    
    return render_template('contracts/view.html',
                          contract=contract,
                          signed_users=signed_users,
                          pending_users=pending_users,
                          can_sign=can_sign,
                          available_signers=available_signers)


@contracts_bp.route('/<int:contract_id>/download')
@login_required
def download(contract_id):
    """Download the decrypted contract (only if finalized)."""
    contract = Contract.query.get_or_404(contract_id)
    
    # ESCROW LOCK CHECK: Only allow download if FINALIZED
    if contract.status != 'finalized':
        AuditLog.log(
            action='DOWNLOAD_BLOCKED',
            user_id=current_user.id,
            ip_address=request.remote_addr,
            resource_type='contract',
            resource_id=contract.id,
            details={'reason': 'Contract not finalized', 'status': contract.status}
        )
        flash('This contract is still in escrow. Download is only available after all parties have signed.', 'warning')
        return redirect(url_for('contracts.view', contract_id=contract.id))
    
    # Check access
    has_access = (
        contract.owner_id == current_user.id or
        current_user.id in contract.required_signers or
        current_user.is_auditor()
    )
    
    if not has_access:
        abort(403)
    
    # Decrypt and stream file
    try:
        with open(contract.encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = decrypt_file(encrypted_data, fernet)
        
        # Verify integrity
        current_hash = hash_file(decrypted_data)
        if current_hash != contract.file_hash:
            AuditLog.log(
                action='INTEGRITY_VIOLATION',
                user_id=current_user.id,
                ip_address=request.remote_addr,
                resource_type='contract',
                resource_id=contract.id,
                details={'expected_hash': contract.file_hash, 'actual_hash': current_hash}
            )
            flash('SECURITY ALERT: File integrity check failed! The file may have been tampered with.', 'danger')
            return redirect(url_for('contracts.view', contract_id=contract.id))
        
        # Log download
        AuditLog.log(
            action='CONTRACT_DOWNLOADED',
            user_id=current_user.id,
            ip_address=request.remote_addr,
            resource_type='contract',
            resource_id=contract.id
        )
        
        # Send file as stream (not saved to disk)
        return send_file(
            BytesIO(decrypted_data),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=contract.original_filename
        )
    except Exception as e:
        flash('Error downloading file.', 'danger')
        return redirect(url_for('contracts.view', contract_id=contract.id))


@contracts_bp.route('/<int:contract_id>/add-signers', methods=['POST'])
@login_required
def add_signers(contract_id):
    """Add additional signers to a contract."""
    contract = Contract.query.get_or_404(contract_id)
    
    # Only owner can add signers
    if contract.owner_id != current_user.id:
        flash('Only the contract owner can add signers.', 'danger')
        return redirect(url_for('contracts.view', contract_id=contract.id))
    
    # Cannot modify finalized contracts
    if contract.status == 'finalized':
        flash('Cannot modify a finalized contract.', 'warning')
        return redirect(url_for('contracts.view', contract_id=contract.id))
    
    new_signer_ids = request.form.getlist('new_signers')
    new_signer_ids = [int(sid) for sid in new_signer_ids if sid.isdigit()]
    
    current_signers = contract.required_signers
    for sid in new_signer_ids:
        if sid not in current_signers:
            current_signers.append(sid)
    
    contract.required_signers = current_signers
    contract.update_status()
    db.session.commit()
    
    AuditLog.log(
        action='SIGNERS_ADDED',
        user_id=current_user.id,
        ip_address=request.remote_addr,
        resource_type='contract',
        resource_id=contract.id,
        details={'added_signers': new_signer_ids}
    )
    
    flash('Signers added successfully.', 'success')
    return redirect(url_for('contracts.view', contract_id=contract.id))
