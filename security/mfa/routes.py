"""
MFA API Endpoints
Flask Blueprint with all MFA-related routes
"""

from flask import Blueprint, request, jsonify, g
from datetime import datetime

from .models import db, User, BackupCode, MFAAttempt
from .mfa_service import mfa_service
from .jwt_service import jwt_required, mfa_required

mfa_bp = Blueprint('mfa', __name__, url_prefix='/api/auth/mfa')


@mfa_bp.route('/setup', methods=['POST'])
@jwt_required
def setup_mfa():
    """
    Step 1: Initialize MFA setup - generates secret and QR code
    
    Returns:
        - secret: TOTP secret (user should save this)
        - qr_code: Base64 encoded QR code image
        - provisioning_uri: Manual entry URI for authenticator apps
    
    Note: MFA is not enabled until /setup/verify is called
    """
    user = User.query.get(g.current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if user.mfa_enabled:
        return jsonify({'error': 'MFA is already enabled'}), 400
    
    # Generate new secret
    secret = mfa_service.generate_secret()
    
    # Generate QR code
    qr_code = mfa_service.generate_qr_code(secret, user.email)
    provisioning_uri = mfa_service.generate_provisioning_uri(secret, user.email)
    
    # Store secret temporarily (not enabled yet)
    user.mfa_secret = secret
    db.session.commit()
    
    return jsonify({
        'message': 'MFA setup initiated. Scan the QR code with your authenticator app.',
        'secret': secret,  # User should save this as backup
        'qr_code': qr_code,
        'qr_code_data_uri': f'data:image/png;base64,{qr_code}',
        'provisioning_uri': provisioning_uri,
        'next_step': 'POST /api/auth/mfa/setup/verify with a code from your authenticator app'
    })


@mfa_bp.route('/setup/verify', methods=['POST'])
@jwt_required
def verify_mfa_setup():
    """
    Step 2: Verify MFA setup with a code from authenticator app
    
    Request body:
        - code: 6-digit TOTP code from authenticator app
    
    Returns:
        - backup_codes: One-time backup codes (SAVE THESE!)
        - message: Success message
    
    This endpoint enables MFA on the account
    """
    user = User.query.get(g.current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if user.mfa_enabled:
        return jsonify({'error': 'MFA is already enabled'}), 400
    
    if not user.mfa_secret:
        return jsonify({'error': 'MFA setup not initiated. Call /setup first'}), 400
    
    data = request.get_json()
    code = data.get('code', '').strip()
    
    if not code:
        return jsonify({'error': 'Verification code is required'}), 400
    
    # Verify the code
    if not mfa_service.verify_totp(user.mfa_secret, code):
        _log_mfa_attempt(user.id, False, 'totp')
        return jsonify({'error': 'Invalid verification code'}), 400
    
    # Generate backup codes
    plain_codes, hashed_codes = mfa_service.generate_backup_codes()
    
    # Clear existing backup codes and save new ones
    BackupCode.query.filter_by(user_id=user.id).delete()
    for code_hash in hashed_codes:
        backup_code = BackupCode(user_id=user.id, code_hash=code_hash)
        db.session.add(backup_code)
    
    # Enable MFA
    user.mfa_enabled = True
    user.mfa_enabled_at = datetime.utcnow()
    db.session.commit()
    
    _log_mfa_attempt(user.id, True, 'totp')
    
    return jsonify({
        'message': 'MFA enabled successfully',
        'backup_codes': plain_codes,
        'warning': 'SAVE THESE BACKUP CODES! They will not be shown again.',
        'backup_codes_count': len(plain_codes)
    })


@mfa_bp.route('/verify', methods=['POST'])
@jwt_required
def verify_mfa():
    """
    Verify MFA code during login flow
    
    Request body:
        - code: 6-digit TOTP code OR backup code (XXXX-XXXX format)
    
    Returns:
        - New JWT tokens with mfa_verified=True
    """
    user = User.query.get(g.current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if not user.mfa_enabled:
        return jsonify({'error': 'MFA is not enabled for this account'}), 400
    
    # Check rate limiting
    if _is_rate_limited(user.id):
        return jsonify({'error': 'Too many failed attempts. Please try again later.'}), 429
    
    data = request.get_json()
    code = data.get('code', '').strip()
    
    if not code:
        return jsonify({'error': 'Verification code is required'}), 400
    
    verified = False
    attempt_type = 'totp'
    
    # Check if it's a backup code (contains dash)
    if '-' in code or len(code) == 8:
        attempt_type = 'backup'
        verified = _verify_backup_code(user, code)
    else:
        # Try TOTP verification
        verified = mfa_service.verify_totp(user.mfa_secret, code)
    
    _log_mfa_attempt(user.id, verified, attempt_type)
    
    if not verified:
        return jsonify({'error': 'Invalid verification code'}), 400
    
    # Generate new tokens with MFA verified
    tokens = g.jwt_service.generate_token_pair(
        user_id=user.id,
        email=user.email,
        mfa_verified=True,
        mfa_required=True
    )
    
    return jsonify({
        'message': 'MFA verification successful',
        **tokens
    })


@mfa_bp.route('/disable', methods=['POST'])
@mfa_required
def disable_mfa():
    """
    Disable MFA on the account
    
    Request body:
        - code: Current TOTP code to confirm identity
        - password: User's password (optional, for extra security)
    
    Returns:
        - Success message
    """
    user = User.query.get(g.current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if not user.mfa_enabled:
        return jsonify({'error': 'MFA is not enabled'}), 400
    
    data = request.get_json()
    code = data.get('code', '').strip()
    
    if not code:
        return jsonify({'error': 'Current MFA code is required to disable MFA'}), 400
    
    # Verify the code before disabling
    if not mfa_service.verify_totp(user.mfa_secret, code):
        _log_mfa_attempt(user.id, False, 'totp')
        return jsonify({'error': 'Invalid verification code'}), 400
    
    # Disable MFA
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_enabled_at = None
    
    # Remove backup codes
    BackupCode.query.filter_by(user_id=user.id).delete()
    
    db.session.commit()
    
    # Generate new tokens without MFA
    tokens = g.jwt_service.generate_token_pair(
        user_id=user.id,
        email=user.email,
        mfa_verified=False,
        mfa_required=False
    )
    
    return jsonify({
        'message': 'MFA has been disabled',
        **tokens
    })


@mfa_bp.route('/status', methods=['GET'])
@jwt_required
def mfa_status():
    """
    Get current MFA status for the user
    
    Returns:
        - enabled: Whether MFA is enabled
        - verified: Whether current session has MFA verified
        - enabled_at: When MFA was enabled
        - backup_codes_remaining: Number of unused backup codes
    """
    user = User.query.get(g.current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    backup_codes_remaining = BackupCode.query.filter_by(
        user_id=user.id,
        used=False
    ).count()
    
    return jsonify({
        'enabled': user.mfa_enabled,
        'verified': g.mfa_verified,
        'enabled_at': user.mfa_enabled_at.isoformat() if user.mfa_enabled_at else None,
        'backup_codes_remaining': backup_codes_remaining if user.mfa_enabled else 0
    })


@mfa_bp.route('/backup-codes/regenerate', methods=['POST'])
@mfa_required
def regenerate_backup_codes():
    """
    Regenerate backup codes (invalidates all existing codes)
    
    Request body:
        - code: Current TOTP code to confirm identity
    
    Returns:
        - New backup codes (SAVE THESE!)
    """
    user = User.query.get(g.current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if not user.mfa_enabled:
        return jsonify({'error': 'MFA is not enabled'}), 400
    
    data = request.get_json()
    code = data.get('code', '').strip()
    
    if not code:
        return jsonify({'error': 'Current MFA code is required'}), 400
    
    if not mfa_service.verify_totp(user.mfa_secret, code):
        return jsonify({'error': 'Invalid verification code'}), 400
    
    # Generate new backup codes
    plain_codes, hashed_codes = mfa_service.generate_backup_codes()
    
    # Replace existing codes
    BackupCode.query.filter_by(user_id=user.id).delete()
    for code_hash in hashed_codes:
        backup_code = BackupCode(user_id=user.id, code_hash=code_hash)
        db.session.add(backup_code)
    
    db.session.commit()
    
    return jsonify({
        'message': 'Backup codes regenerated',
        'backup_codes': plain_codes,
        'warning': 'SAVE THESE BACKUP CODES! Previous codes are now invalid.',
        'backup_codes_count': len(plain_codes)
    })


# Helper functions

def _verify_backup_code(user: User, code: str) -> bool:
    """Verify and consume a backup code"""
    backup_codes = BackupCode.query.filter_by(
        user_id=user.id,
        used=False
    ).all()
    
    for backup_code in backup_codes:
        if mfa_service.verify_backup_code(code, backup_code.code_hash):
            # Mark as used
            backup_code.used = True
            backup_code.used_at = datetime.utcnow()
            db.session.commit()
            return True
    
    return False


def _log_mfa_attempt(user_id: int, success: bool, attempt_type: str):
    """Log MFA verification attempt"""
    attempt = MFAAttempt(
        user_id=user_id,
        ip_address=request.remote_addr,
        success=success,
        attempt_type=attempt_type
    )
    db.session.add(attempt)
    db.session.commit()


def _is_rate_limited(user_id: int, max_attempts: int = 5, window_minutes: int = 15) -> bool:
    """Check if user has exceeded MFA attempt rate limit"""
    window_start = datetime.utcnow() - __import__('datetime').timedelta(minutes=window_minutes)
    
    failed_attempts = MFAAttempt.query.filter(
        MFAAttempt.user_id == user_id,
        MFAAttempt.success == False,
        MFAAttempt.created_at >= window_start
    ).count()
    
    return failed_attempts >= max_attempts
