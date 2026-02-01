"""
Admin routes for the Secure Escrow Platform.
Handles audit logs, user management, and system administration.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user

from ..models import User, Contract, AuditLog
from .. import db
from .auth import admin_required, auditor_required

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/logs')
@login_required
@auditor_required
def audit_logs():
    """View audit log table (read-only)."""
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    # Filter options
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user_id', '', type=str)
    
    query = AuditLog.query.order_by(AuditLog.timestamp.desc())
    
    if action_filter:
        query = query.filter(AuditLog.action.contains(action_filter))
    if user_filter.isdigit():
        query = query.filter(AuditLog.user_id == int(user_filter))
    
    logs = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Get unique actions for filter dropdown
    actions = db.session.query(AuditLog.action).distinct().all()
    actions = [a[0] for a in actions]
    
    # Get all users for filter dropdown
    users = User.query.all()
    
    return render_template('admin/audit_logs.html', 
                          logs=logs, 
                          actions=actions, 
                          users=users,
                          current_action=action_filter,
                          current_user_id=user_filter)


@admin_bp.route('/users')
@login_required
@admin_required
def users():
    """Manage users and their roles."""
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=all_users)


@admin_bp.route('/users/<int:user_id>/update-role', methods=['POST'])
@login_required
@admin_required
def update_role(user_id):
    """Update a user's role."""
    user = User.query.get_or_404(user_id)
    
    # Prevent self-demotion
    if user.id == current_user.id:
        flash('You cannot change your own role.', 'warning')
        return redirect(url_for('admin.users'))
    
    new_role = request.form.get('role', '')
    valid_roles = ['signatory', 'initiator', 'auditor', 'admin']
    
    if new_role not in valid_roles:
        flash('Invalid role specified.', 'danger')
        return redirect(url_for('admin.users'))
    
    old_role = user.role
    user.role = new_role
    db.session.commit()
    
    AuditLog.log(
        action='USER_ROLE_CHANGED',
        user_id=current_user.id,
        ip_address=request.remote_addr,
        resource_type='user',
        resource_id=user.id,
        details={'old_role': old_role, 'new_role': new_role}
    )
    
    flash(f'User {user.username} role changed from {old_role} to {new_role}.', 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/toggle-active', methods=['POST'])
@login_required
@admin_required
def toggle_active(user_id):
    """Activate or deactivate a user account."""
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('You cannot deactivate your own account.', 'warning')
        return redirect(url_for('admin.users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'activated' if user.is_active else 'deactivated'
    
    AuditLog.log(
        action=f'USER_{status.upper()}',
        user_id=current_user.id,
        ip_address=request.remote_addr,
        resource_type='user',
        resource_id=user.id
    )
    
    flash(f'User {user.username} has been {status}.', 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/integrity-check')
@login_required
@auditor_required
def integrity_check():
    """Check integrity of all stored contracts."""
    from ..crypto_utils import hash_file, decrypt_file
    from .. import fernet
    
    contracts = Contract.query.all()
    results = []
    
    for contract in contracts:
        try:
            with open(contract.encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = decrypt_file(encrypted_data, fernet)
            current_hash = hash_file(decrypted_data)
            
            is_valid = current_hash == contract.file_hash
            
            results.append({
                'contract': contract,
                'is_valid': is_valid,
                'stored_hash': contract.file_hash,
                'current_hash': current_hash,
                'error': None
            })
            
            if not is_valid:
                AuditLog.log(
                    action='INTEGRITY_CHECK_FAILED',
                    user_id=current_user.id,
                    ip_address=request.remote_addr,
                    resource_type='contract',
                    resource_id=contract.id,
                    details={
                        'stored_hash': contract.file_hash,
                        'current_hash': current_hash
                    }
                )
        except Exception as e:
            results.append({
                'contract': contract,
                'is_valid': False,
                'stored_hash': contract.file_hash,
                'current_hash': None,
                'error': str(e)
            })
    
    AuditLog.log(
        action='INTEGRITY_CHECK_RUN',
        user_id=current_user.id,
        ip_address=request.remote_addr,
        details={
            'total_contracts': len(contracts),
            'valid_count': len([r for r in results if r['is_valid']]),
            'invalid_count': len([r for r in results if not r['is_valid']])
        }
    )
    
    return render_template('admin/integrity_check.html', results=results)


@admin_bp.route('/statistics')
@login_required
@admin_required
def statistics():
    """View system statistics."""
    stats = {
        'total_users': User.query.count(),
        'active_users': User.query.filter_by(is_active=True).count(),
        'total_contracts': Contract.query.count(),
        'pending_contracts': Contract.query.filter_by(status='pending').count(),
        'partially_signed': Contract.query.filter_by(status='partially_signed').count(),
        'finalized_contracts': Contract.query.filter_by(status='finalized').count(),
        'total_audit_logs': AuditLog.query.count()
    }
    
    # Recent activity
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    return render_template('admin/statistics.html', stats=stats, recent_logs=recent_logs)
