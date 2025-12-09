"""
JWT API Endpoints
Flask Blueprint with authentication and token management routes
"""

from flask import Blueprint, request, jsonify, g
from werkzeug.security import check_password_hash

from .models import db, User, TokenAuditLog
from .decorators import jwt_required, jwt_refresh_required, fresh_jwt_required

jwt_bp = Blueprint('jwt', __name__, url_prefix='/api/auth')


# ==================== AUTHENTICATION ====================

@jwt_bp.route('/login', methods=['POST'])
def login():
    """
    Login with email/password
    
    Request body:
        - email: User email
        - password: User password
        - device_info: (optional) Device identifier
    
    Returns:
        - access_token: JWT access token (15 min)
        - refresh_token: Refresh token (7 days)
        - expires_in: Access token TTL in seconds
        - refresh_expires_in: Refresh token TTL in seconds
    """
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    device_info = data.get('device_info')
    
    if not email or not password:
        return jsonify({
            'error': 'Email and password required',
            'code': 'MISSING_CREDENTIALS'
        }), 400
    
    user = User.query.filter_by(email=email).first()
    
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({
            'error': 'Invalid email or password',
            'code': 'INVALID_CREDENTIALS'
        }), 401
    
    if not user.is_active:
        return jsonify({
            'error': 'Account is disabled',
            'code': 'ACCOUNT_DISABLED'
        }), 403
    
    # Generate tokens
    tokens = g.jwt_service.generate_token_pair(user, device_info=device_info)
    
    return jsonify({
        'message': 'Login successful',
        'user': {
            'id': user.id,
            'email': user.email
        },
        **tokens
    })


@jwt_bp.route('/refresh', methods=['POST'])
@jwt_refresh_required
def refresh():
    """
    Refresh access token
    
    Request body:
        - refresh_token: Valid refresh token
    
    Returns:
        - access_token: New JWT access token
        - refresh_token: New refresh token (if rotation enabled)
    
    Note: With token rotation enabled (default), the old refresh token
    is invalidated and a new one is returned.
    """
    result = g.jwt_service.refresh_tokens(g.refresh_token)
    
    if not result:
        return jsonify({
            'error': 'Invalid or expired refresh token',
            'code': 'REFRESH_TOKEN_INVALID'
        }), 401
    
    return jsonify(result)


@jwt_bp.route('/logout', methods=['POST'])
@jwt_required
def logout():
    """
    Logout - revoke current tokens
    
    Request body:
        - refresh_token: (optional) Refresh token to revoke
    
    Revokes the access token used in Authorization header
    and optionally the refresh token if provided.
    """
    data = request.get_json() or {}
    refresh_token = data.get('refresh_token')
    
    g.jwt_service.logout(g.access_token, refresh_token)
    
    return jsonify({'message': 'Logged out successfully'})


@jwt_bp.route('/logout-all', methods=['POST'])
@jwt_required
def logout_all():
    """
    Logout from all devices
    
    Revokes all tokens for the current user.
    All active sessions will be terminated.
    """
    g.jwt_service.revoke_all_user_tokens(g.current_user_id, reason='user_logout_all')
    
    return jsonify({'message': 'Logged out from all devices'})


# ==================== TOKEN VERIFICATION ====================

@jwt_bp.route('/verify', methods=['POST'])
def verify_token():
    """
    Verify an access token
    
    Request body:
        - token: Access token to verify
    
    Returns:
        - valid: Whether token is valid
        - payload: Decoded token payload (if valid)
    """
    data = request.get_json()
    token = data.get('token', '')
    
    if not token:
        return jsonify({
            'valid': False,
            'error': 'Token required'
        })
    
    payload = g.jwt_service.decode_access_token(token)
    
    if payload:
        # Remove sensitive fields
        safe_payload = {
            'sub': payload['sub'],
            'email': payload['email'],
            'iat': payload['iat'],
            'exp': payload['exp']
        }
        return jsonify({
            'valid': True,
            'payload': safe_payload
        })
    
    return jsonify({
        'valid': False,
        'error': 'Invalid or expired token'
    })


@jwt_bp.route('/me', methods=['GET'])
@jwt_required
def get_current_user():
    """
    Get current user info from token
    """
    user = User.query.get(g.current_user_id)
    
    return jsonify({
        'id': user.id,
        'email': user.email,
        'is_active': user.is_active,
        'last_login': user.last_login.isoformat() if user.last_login else None
    })


# ==================== SESSION MANAGEMENT ====================

@jwt_bp.route('/sessions', methods=['GET'])
@jwt_required
def list_sessions():
    """
    List all active sessions for current user
    
    Returns list of active refresh tokens (sessions)
    """
    sessions = g.jwt_service.get_user_sessions(g.current_user_id)
    
    return jsonify({
        'sessions': sessions,
        'count': len(sessions)
    })


@jwt_bp.route('/sessions/<int:session_id>', methods=['DELETE'])
@jwt_required
def revoke_session(session_id):
    """
    Revoke a specific session
    
    Use this to log out a specific device
    """
    success = g.jwt_service.revoke_session(g.current_user_id, session_id)
    
    if success:
        return jsonify({'message': 'Session revoked'})
    
    return jsonify({
        'error': 'Session not found',
        'code': 'SESSION_NOT_FOUND'
    }), 404


# ==================== SECURITY OPERATIONS ====================

@jwt_bp.route('/revoke-all-tokens', methods=['POST'])
@fresh_jwt_required
def revoke_all_tokens():
    """
    Revoke all tokens (emergency security action)
    
    Requires fresh authentication (token issued within last 10 minutes)
    """
    g.jwt_service.revoke_all_user_tokens(g.current_user_id, reason='security_revoke')
    
    return jsonify({
        'message': 'All tokens revoked. Please log in again.'
    })


@jwt_bp.route('/token-audit', methods=['GET'])
@jwt_required
def get_token_audit():
    """
    Get token audit log for current user
    
    Query params:
        - limit: Max records (default 50, max 100)
    """
    limit = min(request.args.get('limit', 50, type=int), 100)
    
    logs = TokenAuditLog.query.filter_by(
        user_id=g.current_user_id
    ).order_by(
        TokenAuditLog.created_at.desc()
    ).limit(limit).all()
    
    return jsonify({
        'audit_log': [{
            'action': log.action,
            'token_type': log.token_type,
            'ip_address': log.ip_address,
            'success': log.success,
            'failure_reason': log.failure_reason,
            'created_at': log.created_at.isoformat()
        } for log in logs]
    })


# ==================== ERROR HANDLERS ====================

@jwt_bp.errorhandler(401)
def unauthorized(e):
    return jsonify({
        'error': 'Unauthorized',
        'code': 'UNAUTHORIZED'
    }), 401


@jwt_bp.errorhandler(403)
def forbidden(e):
    return jsonify({
        'error': 'Forbidden',
        'code': 'FORBIDDEN'
    }), 403
