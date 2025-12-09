"""
JWT Decorators
Route protection decorators for JWT authentication
"""

from functools import wraps
from flask import request, jsonify, g
from typing import Optional


def get_token_from_header() -> Optional[str]:
    """Extract JWT from Authorization header"""
    auth_header = request.headers.get('Authorization', '')
    
    if auth_header.startswith('Bearer '):
        return auth_header[7:]
    
    return None


def jwt_required(f):
    """
    Decorator: Require valid JWT access token
    
    Sets:
        g.current_user_id
        g.current_user_email
        g.jwt_payload
    
    Usage:
        @app.route('/api/protected')
        @jwt_required
        def protected():
            user_id = g.current_user_id
            return jsonify({'user_id': user_id})
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_header()
        
        if not token:
            return jsonify({
                'error': 'Missing authorization token',
                'code': 'TOKEN_MISSING'
            }), 401
        
        if not hasattr(g, 'jwt_service'):
            return jsonify({
                'error': 'JWT service not configured',
                'code': 'SERVICE_ERROR'
            }), 500
        
        payload = g.jwt_service.decode_access_token(token)
        
        if not payload:
            return jsonify({
                'error': 'Invalid or expired token',
                'code': 'TOKEN_INVALID'
            }), 401
        
        # Set user context
        g.current_user_id = payload['sub']
        g.current_user_email = payload['email']
        g.jwt_payload = payload
        g.access_token = token
        
        return f(*args, **kwargs)
    return decorated


def jwt_optional(f):
    """
    Decorator: JWT is optional - sets user context if token present
    
    Usage:
        @app.route('/api/products')
        @jwt_optional
        def products():
            if g.current_user_id:
                # Show personalized products
            else:
                # Show generic products
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_header()
        
        g.current_user_id = None
        g.current_user_email = None
        g.jwt_payload = None
        g.access_token = None
        
        if token and hasattr(g, 'jwt_service'):
            payload = g.jwt_service.decode_access_token(token)
            if payload:
                g.current_user_id = payload['sub']
                g.current_user_email = payload['email']
                g.jwt_payload = payload
                g.access_token = token
        
        return f(*args, **kwargs)
    return decorated


def jwt_refresh_required(f):
    """
    Decorator: Require valid refresh token in request body
    
    Expects JSON body with 'refresh_token' field
    
    Usage:
        @app.route('/api/auth/refresh', methods=['POST'])
        @jwt_refresh_required
        def refresh():
            # g.refresh_token contains the validated token string
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        data = request.get_json()
        
        if not data or 'refresh_token' not in data:
            return jsonify({
                'error': 'Refresh token required',
                'code': 'REFRESH_TOKEN_MISSING'
            }), 400
        
        g.refresh_token = data['refresh_token']
        
        return f(*args, **kwargs)
    return decorated


def fresh_jwt_required(f):
    """
    Decorator: Require fresh JWT (just issued, not refreshed)
    
    Use for sensitive operations like password change
    
    Usage:
        @app.route('/api/user/password', methods=['PUT'])
        @fresh_jwt_required
        def change_password():
            # Only accessible with freshly issued token
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_header()
        
        if not token:
            return jsonify({
                'error': 'Missing authorization token',
                'code': 'TOKEN_MISSING'
            }), 401
        
        if not hasattr(g, 'jwt_service'):
            return jsonify({
                'error': 'JWT service not configured',
                'code': 'SERVICE_ERROR'
            }), 500
        
        payload = g.jwt_service.decode_access_token(token)
        
        if not payload:
            return jsonify({
                'error': 'Invalid or expired token',
                'code': 'TOKEN_INVALID'
            }), 401
        
        # Check if token is fresh (issued within last 10 minutes)
        from datetime import datetime
        issued_at = datetime.utcfromtimestamp(payload['iat'])
        age_minutes = (datetime.utcnow() - issued_at).total_seconds() / 60
        
        if age_minutes > 10:
            return jsonify({
                'error': 'Fresh authentication required',
                'code': 'TOKEN_NOT_FRESH'
            }), 401
        
        g.current_user_id = payload['sub']
        g.current_user_email = payload['email']
        g.jwt_payload = payload
        g.access_token = token
        
        return f(*args, **kwargs)
    return decorated


def claims_required(*required_claims):
    """
    Decorator: Require specific claims in JWT
    
    Usage:
        @app.route('/api/admin')
        @jwt_required
        @claims_required('is_admin', 'mfa_verified')
        def admin():
            # Only accessible if token has is_admin=True and mfa_verified=True
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'jwt_payload') or not g.jwt_payload:
                return jsonify({
                    'error': 'Authentication required',
                    'code': 'NOT_AUTHENTICATED'
                }), 401
            
            missing_claims = []
            for claim in required_claims:
                if not g.jwt_payload.get(claim):
                    missing_claims.append(claim)
            
            if missing_claims:
                return jsonify({
                    'error': 'Missing required claims',
                    'code': 'CLAIMS_MISSING',
                    'missing': missing_claims
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator


def verify_claims(**expected_claims):
    """
    Decorator: Verify specific claim values
    
    Usage:
        @app.route('/api/premium')
        @jwt_required
        @verify_claims(subscription='premium', email_verified=True)
        def premium_content():
            # Only accessible if subscription='premium' and email_verified=True
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'jwt_payload') or not g.jwt_payload:
                return jsonify({
                    'error': 'Authentication required',
                    'code': 'NOT_AUTHENTICATED'
                }), 401
            
            failed_claims = {}
            for claim, expected_value in expected_claims.items():
                actual_value = g.jwt_payload.get(claim)
                if actual_value != expected_value:
                    failed_claims[claim] = {
                        'expected': expected_value,
                        'actual': actual_value
                    }
            
            if failed_claims:
                return jsonify({
                    'error': 'Claim verification failed',
                    'code': 'CLAIMS_INVALID',
                    'details': failed_claims
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator
