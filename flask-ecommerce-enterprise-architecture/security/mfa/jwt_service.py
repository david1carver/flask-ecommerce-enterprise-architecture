"""
JWT Service with MFA Integration
Handles token generation with MFA verification status
"""

import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from functools import wraps
from flask import request, jsonify, g


class JWTService:
    """JWT service with MFA-aware token handling"""
    
    def __init__(
        self,
        secret_key: str,
        access_token_expires: int = 15,      # 15 minutes
        refresh_token_expires: int = 7,       # 7 days
        mfa_token_expires: int = 5,           # 5 minutes for MFA pending tokens
        algorithm: str = 'HS256'
    ):
        self.secret_key = secret_key
        self.access_token_expires = access_token_expires
        self.refresh_token_expires = refresh_token_expires
        self.mfa_token_expires = mfa_token_expires
        self.algorithm = algorithm
    
    def generate_access_token(
        self,
        user_id: int,
        email: str,
        mfa_verified: bool = False,
        mfa_required: bool = False
    ) -> str:
        """
        Generate access token
        
        Args:
            user_id: User's database ID
            email: User's email
            mfa_verified: Whether MFA has been completed
            mfa_required: Whether user has MFA enabled
        
        Returns:
            JWT access token
        """
        # If MFA required but not verified, use shorter expiry
        if mfa_required and not mfa_verified:
            expires = datetime.utcnow() + timedelta(minutes=self.mfa_token_expires)
        else:
            expires = datetime.utcnow() + timedelta(minutes=self.access_token_expires)
        
        payload = {
            'sub': user_id,
            'email': email,
            'type': 'access',
            'mfa_verified': mfa_verified,
            'mfa_required': mfa_required,
            'iat': datetime.utcnow(),
            'exp': expires
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def generate_refresh_token(self, user_id: int, email: str) -> str:
        """Generate refresh token (longer lived)"""
        payload = {
            'sub': user_id,
            'email': email,
            'type': 'refresh',
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(days=self.refresh_token_expires)
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode and validate a JWT token
        
        Returns:
            Decoded payload if valid, None otherwise
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def generate_token_pair(
        self,
        user_id: int,
        email: str,
        mfa_verified: bool = False,
        mfa_required: bool = False
    ) -> Dict[str, str]:
        """Generate both access and refresh tokens"""
        return {
            'access_token': self.generate_access_token(user_id, email, mfa_verified, mfa_required),
            'refresh_token': self.generate_refresh_token(user_id, email),
            'token_type': 'Bearer',
            'expires_in': self.access_token_expires * 60,  # Convert to seconds
            'mfa_required': mfa_required and not mfa_verified
        }


def create_jwt_service(app) -> JWTService:
    """Factory function to create JWTService from Flask app config"""
    return JWTService(
        secret_key=app.config.get('JWT_SECRET_KEY', app.config.get('SECRET_KEY')),
        access_token_expires=app.config.get('JWT_ACCESS_TOKEN_EXPIRES', 15),
        refresh_token_expires=app.config.get('JWT_REFRESH_TOKEN_EXPIRES', 7),
        mfa_token_expires=app.config.get('JWT_MFA_TOKEN_EXPIRES', 5)
    )


# Decorators for route protection

def jwt_required(f):
    """Decorator: Require valid JWT (MFA not checked)"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _get_token_from_header()
        if not token:
            return jsonify({'error': 'Missing authorization token'}), 401
        
        payload = g.jwt_service.decode_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        if payload.get('type') != 'access':
            return jsonify({'error': 'Invalid token type'}), 401
        
        g.current_user_id = payload['sub']
        g.current_user_email = payload['email']
        g.mfa_verified = payload.get('mfa_verified', False)
        g.mfa_required = payload.get('mfa_required', False)
        
        return f(*args, **kwargs)
    return decorated


def mfa_required(f):
    """Decorator: Require valid JWT AND completed MFA verification"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _get_token_from_header()
        if not token:
            return jsonify({'error': 'Missing authorization token'}), 401
        
        payload = g.jwt_service.decode_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        if payload.get('type') != 'access':
            return jsonify({'error': 'Invalid token type'}), 401
        
        # Check MFA status
        if payload.get('mfa_required') and not payload.get('mfa_verified'):
            return jsonify({
                'error': 'MFA verification required',
                'mfa_required': True
            }), 403
        
        g.current_user_id = payload['sub']
        g.current_user_email = payload['email']
        g.mfa_verified = payload.get('mfa_verified', False)
        g.mfa_required = payload.get('mfa_required', False)
        
        return f(*args, **kwargs)
    return decorated


def _get_token_from_header() -> Optional[str]:
    """Extract JWT from Authorization header"""
    auth_header = request.headers.get('Authorization', '')
    
    if auth_header.startswith('Bearer '):
        return auth_header[7:]
    
    return None
