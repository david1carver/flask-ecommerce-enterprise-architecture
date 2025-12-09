"""
JWT Service
Comprehensive JWT handling with access/refresh tokens, rotation, and blacklisting
"""

import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from uuid import uuid4
from flask import request

from .models import db, User, RefreshToken, TokenBlacklist, TokenAuditLog


class JWTConfig:
    """JWT Configuration"""
    def __init__(
        self,
        secret_key: str,
        access_token_expires: int = 15,           # 15 minutes
        refresh_token_expires: int = 7,            # 7 days
        algorithm: str = 'HS256',
        issuer: str = 'flask-ecommerce',
        audience: str = 'flask-ecommerce-api',
        token_rotation: bool = True,               # Issue new refresh token on use
        reuse_detection: bool = True,              # Detect refresh token reuse attacks
        max_refresh_tokens_per_user: int = 10,     # Max concurrent sessions
    ):
        self.secret_key = secret_key
        self.access_token_expires = access_token_expires
        self.refresh_token_expires = refresh_token_expires
        self.algorithm = algorithm
        self.issuer = issuer
        self.audience = audience
        self.token_rotation = token_rotation
        self.reuse_detection = reuse_detection
        self.max_refresh_tokens_per_user = max_refresh_tokens_per_user


class JWTService:
    """
    JWT Service with enterprise security features:
    - Short-lived access tokens (15 min)
    - Long-lived refresh tokens (7 days) with rotation
    - Token family tracking for reuse detection
    - Blacklisting for immediate revocation
    - Device/session tracking
    - Audit logging
    """
    
    def __init__(self, config: JWTConfig):
        self.config = config
    
    # ==================== TOKEN GENERATION ====================
    
    def generate_access_token(
        self,
        user_id: int,
        email: str,
        token_version: int = 1,
        additional_claims: Dict[str, Any] = None
    ) -> Tuple[str, str]:
        """
        Generate access token
        
        Returns:
            Tuple of (token, jti)
        """
        jti = str(uuid4())
        now = datetime.utcnow()
        expires = now + timedelta(minutes=self.config.access_token_expires)
        
        payload = {
            'sub': user_id,
            'email': email,
            'type': 'access',
            'jti': jti,
            'ver': token_version,  # Token version for mass invalidation
            'iss': self.config.issuer,
            'aud': self.config.audience,
            'iat': now,
            'exp': expires,
        }
        
        if additional_claims:
            payload.update(additional_claims)
        
        token = jwt.encode(payload, self.config.secret_key, algorithm=self.config.algorithm)
        return token, jti
    
    def generate_refresh_token(
        self,
        user_id: int,
        token_family: str = None,
        device_info: str = None,
        ip_address: str = None,
        user_agent: str = None
    ) -> Tuple[str, str, str]:
        """
        Generate refresh token and store in database
        
        Args:
            user_id: User ID
            token_family: Existing token family (for rotation) or None for new
            device_info: Device identifier
            ip_address: Client IP
            user_agent: Browser/client user agent
        
        Returns:
            Tuple of (token, jti, token_family)
        """
        jti = str(uuid4())
        token_family = token_family or str(uuid4())
        now = datetime.utcnow()
        expires = now + timedelta(days=self.config.refresh_token_expires)
        
        # Generate opaque refresh token
        raw_token = f"{user_id}.{jti}.{secrets.token_urlsafe(32)}"
        token_hash = self._hash_token(raw_token)
        
        # Enforce max sessions per user
        self._enforce_max_sessions(user_id)
        
        # Store refresh token
        refresh_token = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            token_family=token_family,
            device_info=device_info,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires
        )
        db.session.add(refresh_token)
        db.session.commit()
        
        return raw_token, jti, token_family
    
    def generate_token_pair(
        self,
        user: User,
        device_info: str = None,
        additional_claims: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Generate access + refresh token pair
        
        Returns:
            Dict with tokens and metadata
        """
        ip_address = request.remote_addr if request else None
        user_agent = request.headers.get('User-Agent') if request else None
        
        # Generate tokens
        access_token, access_jti = self.generate_access_token(
            user.id, 
            user.email, 
            user.token_version,
            additional_claims
        )
        
        refresh_token, refresh_jti, token_family = self.generate_refresh_token(
            user.id,
            device_info=device_info,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Update user last login
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Audit log
        self._log_action(user.id, 'login', 'access', access_jti, ip_address, user_agent)
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': self.config.access_token_expires * 60,  # Seconds
            'refresh_expires_in': self.config.refresh_token_expires * 24 * 60 * 60,  # Seconds
        }
    
    # ==================== TOKEN VALIDATION ====================
    
    def decode_access_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode and validate access token
        
        Returns:
            Decoded payload if valid, None otherwise
        """
        try:
            payload = jwt.decode(
                token,
                self.config.secret_key,
                algorithms=[self.config.algorithm],
                audience=self.config.audience,
                issuer=self.config.issuer
            )
            
            # Verify token type
            if payload.get('type') != 'access':
                return None
            
            # Check blacklist
            if TokenBlacklist.is_blacklisted(payload.get('jti')):
                return None
            
            # Verify token version
            user = User.query.get(payload.get('sub'))
            if not user or user.token_version != payload.get('ver'):
                return None
            
            if not user.is_active:
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def validate_refresh_token(self, token: str) -> Optional[RefreshToken]:
        """
        Validate refresh token
        
        Returns:
            RefreshToken model if valid, None otherwise
        """
        token_hash = self._hash_token(token)
        
        refresh_token = RefreshToken.query.filter_by(token_hash=token_hash).first()
        
        if not refresh_token:
            return None
        
        if not refresh_token.is_valid:
            # Token reuse detection
            if self.config.reuse_detection and refresh_token.is_revoked:
                # Possible token theft - revoke entire family
                self._revoke_token_family(refresh_token.user_id, refresh_token.token_family)
                self._log_action(
                    refresh_token.user_id, 
                    'reuse_detected', 
                    'refresh',
                    failure_reason='Token reuse detected - family revoked'
                )
            return None
        
        # Verify user is still active
        user = User.query.get(refresh_token.user_id)
        if not user or not user.is_active:
            return None
        
        return refresh_token
    
    # ==================== TOKEN REFRESH ====================
    
    def refresh_tokens(self, refresh_token_str: str) -> Optional[Dict[str, Any]]:
        """
        Refresh access token using refresh token
        
        Implements token rotation: old refresh token is revoked,
        new refresh token is issued
        
        Returns:
            New token pair if valid, None otherwise
        """
        refresh_token = self.validate_refresh_token(refresh_token_str)
        
        if not refresh_token:
            return None
        
        user = User.query.get(refresh_token.user_id)
        ip_address = request.remote_addr if request else None
        user_agent = request.headers.get('User-Agent') if request else None
        
        # Generate new access token
        access_token, access_jti = self.generate_access_token(
            user.id,
            user.email,
            user.token_version
        )
        
        result = {
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': self.config.access_token_expires * 60,
        }
        
        # Token rotation: issue new refresh token
        if self.config.token_rotation:
            # Revoke old refresh token
            refresh_token.revoke(reason='rotated')
            refresh_token.last_used_at = datetime.utcnow()
            
            # Issue new refresh token in same family
            new_refresh_token, _, _ = self.generate_refresh_token(
                user.id,
                token_family=refresh_token.token_family,
                device_info=refresh_token.device_info,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            result['refresh_token'] = new_refresh_token
            result['refresh_expires_in'] = self.config.refresh_token_expires * 24 * 60 * 60
        else:
            # Update last used timestamp
            refresh_token.last_used_at = datetime.utcnow()
        
        # Update user
        user.last_token_refresh = datetime.utcnow()
        db.session.commit()
        
        # Audit log
        self._log_action(user.id, 'refresh', 'access', access_jti, ip_address, user_agent)
        
        return result
    
    # ==================== TOKEN REVOCATION ====================
    
    def revoke_access_token(self, token: str, reason: str = None) -> bool:
        """Revoke an access token by adding to blacklist"""
        try:
            # Decode without verification to get claims
            payload = jwt.decode(
                token,
                self.config.secret_key,
                algorithms=[self.config.algorithm],
                options={'verify_exp': False}
            )
            
            jti = payload.get('jti')
            exp = datetime.utcfromtimestamp(payload.get('exp'))
            user_id = payload.get('sub')
            
            # Add to blacklist
            blacklist_entry = TokenBlacklist(
                jti=jti,
                token_type='access',
                user_id=user_id,
                expires_at=exp,
                reason=reason
            )
            db.session.add(blacklist_entry)
            db.session.commit()
            
            self._log_action(user_id, 'revoke', 'access', jti)
            return True
            
        except jwt.InvalidTokenError:
            return False
    
    def revoke_refresh_token(self, token: str, reason: str = None) -> bool:
        """Revoke a refresh token"""
        token_hash = self._hash_token(token)
        refresh_token = RefreshToken.query.filter_by(token_hash=token_hash).first()
        
        if refresh_token:
            refresh_token.revoke(reason=reason)
            db.session.commit()
            
            self._log_action(refresh_token.user_id, 'revoke', 'refresh')
            return True
        
        return False
    
    def revoke_all_user_tokens(self, user_id: int, reason: str = None) -> bool:
        """
        Revoke all tokens for a user
        Increments token version to invalidate all access tokens
        Revokes all refresh tokens
        """
        user = User.query.get(user_id)
        if not user:
            return False
        
        # Invalidate all access tokens by incrementing version
        user.increment_token_version()
        
        # Revoke all refresh tokens
        RefreshToken.query.filter_by(
            user_id=user_id,
            is_revoked=False
        ).update({
            'is_revoked': True,
            'revoked_at': datetime.utcnow(),
            'revoked_reason': reason or 'revoke_all'
        })
        
        db.session.commit()
        
        ip_address = request.remote_addr if request else None
        self._log_action(user_id, 'revoke_all', ip_address=ip_address)
        
        return True
    
    def logout(self, access_token: str, refresh_token: str = None) -> bool:
        """
        Logout user - revoke current tokens
        """
        success = True
        
        # Revoke access token
        if access_token:
            success = self.revoke_access_token(access_token, reason='logout') and success
        
        # Revoke refresh token
        if refresh_token:
            success = self.revoke_refresh_token(refresh_token, reason='logout') and success
        
        return success
    
    # ==================== SESSION MANAGEMENT ====================
    
    def get_user_sessions(self, user_id: int) -> list:
        """Get all active sessions (refresh tokens) for a user"""
        tokens = RefreshToken.query.filter_by(
            user_id=user_id,
            is_revoked=False
        ).filter(
            RefreshToken.expires_at > datetime.utcnow()
        ).order_by(
            RefreshToken.last_used_at.desc()
        ).all()
        
        return [{
            'id': t.id,
            'device_info': t.device_info,
            'ip_address': t.ip_address,
            'issued_at': t.issued_at.isoformat(),
            'last_used_at': t.last_used_at.isoformat() if t.last_used_at else None,
            'expires_at': t.expires_at.isoformat()
        } for t in tokens]
    
    def revoke_session(self, user_id: int, session_id: int) -> bool:
        """Revoke a specific session"""
        token = RefreshToken.query.filter_by(
            id=session_id,
            user_id=user_id,
            is_revoked=False
        ).first()
        
        if token:
            token.revoke(reason='session_revoked')
            db.session.commit()
            return True
        
        return False
    
    # ==================== PRIVATE METHODS ====================
    
    def _hash_token(self, token: str) -> str:
        """Hash a token for secure storage"""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def _enforce_max_sessions(self, user_id: int):
        """Remove oldest sessions if user exceeds max"""
        active_count = RefreshToken.query.filter_by(
            user_id=user_id,
            is_revoked=False
        ).filter(
            RefreshToken.expires_at > datetime.utcnow()
        ).count()
        
        if active_count >= self.config.max_refresh_tokens_per_user:
            # Revoke oldest session
            oldest = RefreshToken.query.filter_by(
                user_id=user_id,
                is_revoked=False
            ).order_by(
                RefreshToken.issued_at.asc()
            ).first()
            
            if oldest:
                oldest.revoke(reason='max_sessions_exceeded')
    
    def _revoke_token_family(self, user_id: int, token_family: str):
        """Revoke all tokens in a family (for reuse detection)"""
        RefreshToken.query.filter_by(
            user_id=user_id,
            token_family=token_family,
            is_revoked=False
        ).update({
            'is_revoked': True,
            'revoked_at': datetime.utcnow(),
            'revoked_reason': 'reuse_detected'
        })
        db.session.commit()
    
    def _log_action(
        self,
        user_id: int,
        action: str,
        token_type: str = None,
        jti: str = None,
        ip_address: str = None,
        user_agent: str = None,
        success: bool = True,
        failure_reason: str = None
    ):
        """Log token operation"""
        log = TokenAuditLog(
            user_id=user_id,
            action=action,
            token_type=token_type,
            jti=jti,
            ip_address=ip_address or (request.remote_addr if request else None),
            user_agent=user_agent or (request.headers.get('User-Agent') if request else None),
            success=success,
            failure_reason=failure_reason
        )
        db.session.add(log)
        db.session.commit()
    
    # ==================== MAINTENANCE ====================
    
    def cleanup_expired_tokens(self):
        """
        Cleanup expired tokens (run periodically via scheduler)
        """
        now = datetime.utcnow()
        
        # Remove expired blacklist entries
        TokenBlacklist.query.filter(TokenBlacklist.expires_at < now).delete()
        
        # Remove expired refresh tokens
        RefreshToken.query.filter(RefreshToken.expires_at < now).delete()
        
        db.session.commit()


def create_jwt_service(app) -> JWTService:
    """Factory function to create JWTService from Flask app config"""
    config = JWTConfig(
        secret_key=app.config.get('JWT_SECRET_KEY', app.config.get('SECRET_KEY')),
        access_token_expires=app.config.get('JWT_ACCESS_TOKEN_EXPIRES', 15),
        refresh_token_expires=app.config.get('JWT_REFRESH_TOKEN_EXPIRES', 7),
        algorithm=app.config.get('JWT_ALGORITHM', 'HS256'),
        issuer=app.config.get('JWT_ISSUER', 'flask-ecommerce'),
        audience=app.config.get('JWT_AUDIENCE', 'flask-ecommerce-api'),
        token_rotation=app.config.get('JWT_TOKEN_ROTATION', True),
        reuse_detection=app.config.get('JWT_REUSE_DETECTION', True),
        max_refresh_tokens_per_user=app.config.get('JWT_MAX_SESSIONS', 10),
    )
    return JWTService(config)
