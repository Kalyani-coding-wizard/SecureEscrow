"""
Digital Signing Engine for the Secure Escrow Platform.
Handles document preview, signing, and signature verification.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file, abort
from flask_login import login_required, current_user
from io import BytesIO

from ..models import Contract, Signature, AuditLog
from .. import db, fernet
from ..crypto_utils import (
    decrypt_file, decrypt_private_key, sign_data, 
    verify_signature, hash_file, hash_data
)

signing_bp = Blueprint('signing', __name__)


@signing_bp.route('/preview/<int:contract_id>')
@login_required
def preview(contract_id):
    """
    Preview a contract document (decrypted stream, not saved to disk).
    Only accessible to required signers and owner.
    """
    contract = Contract.query.get_or_404(contract_id)
    
    # Check access
    has_access = (
        contract.owner_id == current_user.id or
        current_user.id in contract.required_signers or
        current_user.is_auditor()
    )
    
    if not has_access:
        flash('You do not have access to preview this contract.', 'danger')
        return redirect(url_for('contracts.dashboard'))
    
    try:
        # Decrypt file
        with open(contract.encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = decrypt_file(encrypted_data, fernet)
        
        # Verify integrity before showing preview
        current_hash = hash_file(decrypted_data)
        if current_hash != contract.file_hash:
            AuditLog.log(
                action='INTEGRITY_VIOLATION_PREVIEW',
                user_id=current_user.id,
                ip_address=request.remote_addr,
                resource_type='contract',
                resource_id=contract.id
            )
            flash('SECURITY ALERT: File integrity check failed!', 'danger')
            return redirect(url_for('contracts.view', contract_id=contract.id))
        
        # Log preview
        AuditLog.log(
            action='CONTRACT_PREVIEWED',
            user_id=current_user.id,
            ip_address=request.remote_addr,
            resource_type='contract',
            resource_id=contract.id
        )
        
        # Return as inline PDF (don't trigger download)
        return send_file(
            BytesIO(decrypted_data),
            mimetype='application/pdf',
            as_attachment=False,
            download_name=contract.original_filename
        )
    except Exception as e:
        flash('Error loading document preview.', 'danger')
        return redirect(url_for('contracts.view', contract_id=contract.id))


@signing_bp.route('/sign/<int:contract_id>', methods=['GET', 'POST'])
@login_required
def sign(contract_id):
    """Sign a contract with the user's private key."""
    contract = Contract.query.get_or_404(contract_id)
    
    # Check if user can sign
    if not contract.can_user_sign(current_user.id):
        flash('You cannot sign this contract. Either you are not a required signer or you have already signed.', 'warning')
        return redirect(url_for('contracts.view', contract_id=contract.id))
    
    if contract.status == 'finalized':
        flash('This contract has already been finalized.', 'info')
        return redirect(url_for('contracts.view', contract_id=contract.id))
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        
        if not password:
            flash('Password is required to decrypt your signing key.', 'danger')
            return render_template('signing/sign.html', contract=contract)
        
        try:
            # Decrypt user's private key with their password
            private_key_pem = decrypt_private_key(
                current_user.private_key_encrypted,
                password
            )
            
            # Get the document hash (what we're signing)
            document_hash = bytes.fromhex(contract.file_hash)
            
            # Create digital signature
            signature_blob = sign_data(document_hash, private_key_pem)
            
            # Verify our own signature immediately
            is_valid = verify_signature(
                document_hash,
                signature_blob,
                current_user.public_key.encode('utf-8')
            )
            
            if not is_valid:
                flash('Signature verification failed. Please try again.', 'danger')
                return render_template('signing/sign.html', contract=contract)
            
            # Store signature
            signature = Signature(
                contract_id=contract.id,
                user_id=current_user.id,
                signature_blob=signature_blob,
                verified=True
            )
            db.session.add(signature)
            
            # Update contract status
            contract.update_status()
            db.session.commit()
            
            # Log signing
            AuditLog.log(
                action='CONTRACT_SIGNED',
                user_id=current_user.id,
                ip_address=request.remote_addr,
                resource_type='contract',
                resource_id=contract.id,
                details={
                    'signature_id': signature.id,
                    'new_status': contract.status
                }
            )
            
            if contract.status == 'finalized':
                flash('Contract signed and FINALIZED! All required signatures have been collected.', 'success')
            else:
                remaining = contract.get_required_count() - contract.get_signature_count()
                flash(f'Contract signed successfully! {remaining} signature(s) remaining.', 'success')
            
            return redirect(url_for('contracts.view', contract_id=contract.id))
            
        except Exception as e:
            AuditLog.log(
                action='SIGNING_FAILED',
                user_id=current_user.id,
                ip_address=request.remote_addr,
                resource_type='contract',
                resource_id=contract.id,
                details={'error': str(e)}
            )
            flash('Invalid password or signing error. Please check your password and try again.', 'danger')
            return render_template('signing/sign.html', contract=contract)
    
    return render_template('signing/sign.html', contract=contract)


@signing_bp.route('/verify/<int:contract_id>')
@login_required
def verify(contract_id):
    """Verify all signatures on a contract."""
    contract = Contract.query.get_or_404(contract_id)
    
    # Check access
    has_access = (
        contract.owner_id == current_user.id or
        current_user.id in contract.required_signers or
        current_user.is_auditor()
    )
    
    if not has_access:
        abort(403)
    
    verification_results = []
    document_hash = bytes.fromhex(contract.file_hash)
    
    for signature in contract.signatures.all():
        signer = signature.signer
        is_valid = verify_signature(
            document_hash,
            signature.signature_blob,
            signer.public_key.encode('utf-8')
        )
        
        verification_results.append({
            'signer': signer,
            'signature': signature,
            'is_valid': is_valid
        })
        
        # Update verification status if changed
        if signature.verified != is_valid:
            signature.verified = is_valid
            db.session.commit()
    
    # Log verification
    AuditLog.log(
        action='SIGNATURES_VERIFIED',
        user_id=current_user.id,
        ip_address=request.remote_addr,
        resource_type='contract',
        resource_id=contract.id,
        details={'results': [{'user_id': r['signer'].id, 'valid': r['is_valid']} for r in verification_results]}
    )
    
    return render_template('signing/verify.html', contract=contract, results=verification_results)
