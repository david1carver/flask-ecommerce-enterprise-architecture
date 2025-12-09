"""
JWT Database Models
SQLAlchemy models for token management, refresh tokens, and blacklisting
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Index
from sqlalchemy.orm import relationship
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    """User model with JWT support"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # JWT tracking
    token_version = Column(Integer, default=1, nullable=False)  # Increment to invalidate all tokens
    last_login = Column(DateTime, nullable=True)
    last_token_refresh = Column(DateTime, nullable=True)
    
    # Relationships
    refresh_tokens = relationship('RefreshToken', back_populates='user', cascade='all, delete-orphan')
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def increment_token_version(self):
        """Invalidate all existing tokens for this user"""
        self.token_version += 1
    
    def __repr__(self):
        return f'<User {self.email}>'


class RefreshToken(db.Model):
    """
    Refresh token storage for token rotation
    Stores hashed refresh tokens to enable:
    - Token rotation (new refresh token on each use)
    - Device/session tracking
    - Selective revocation
    """
    __tablename__ = 'refresh_tokens'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)  # SHA256 hash
    token_family = Column(String(36), nullable=False, index=True)  # UUID for token family (rotation chain)
    
    # Device/session info
    device_info = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    
    # Status
    is_revoked = Column(Boolean, default=False, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String(100), nullable=True)
    
    # Timestamps
    issued_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship('User', back_populates='refresh_tokens')
    
    __table_args__ = (
        Index('ix_refresh_tokens_user_family', 'user_id', 'token_family'),
    )
    
    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at
    
    @property
    def is_valid(self) -> bool:
        return not self.is_revoked and not self.is_expired
    
    def revoke(self, reason: str = None):
        self.is_revoked = True
        self.revoked_at = datetime.utcnow()
        self.revoked_reason = reason
    
    def __repr__(self):
        return f'<RefreshToken {self.id} user={self.user_id}>'


class TokenBlacklist(db.Model):
    """
    Blacklist for revoked access tokens
    Used for immediate token invalidation before expiry
    """
    __tablename__ = 'token_blacklist'
    
    id = Column(Integer, primary_key=True)
    jti = Column(String(36), unique=True, nullable=False, index=True)  # JWT ID
    token_type = Column(String(20), nullable=False)  # 'access' or 'refresh'
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    revoked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)  # When token would have expired (for cleanup)
    reason = Column(String(100), nullable=True)
    
    @classmethod
    def is_blacklisted(cls, jti: str) -> bool:
        return cls.query.filter_by(jti=jti).first() is not None
    
    @classmethod
    def cleanup_expired(cls):
        """Remove blacklist entries for tokens that have expired anyway"""
        cls.query.filter(cls.expires_at < datetime.utcnow()).delete()
    
    def __repr__(self):
        return f'<TokenBlacklist {self.jti}>'


class TokenAuditLog(db.Model):
    """Audit log for token operations"""
    __tablename__ = 'token_audit_log'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    action = Column(String(50), nullable=False)  # 'login', 'refresh', 'logout', 'revoke', 'revoke_all'
    token_type = Column(String(20), nullable=True)
    jti = Column(String(36), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    success = Column(Boolean, default=True, nullable=False)
    failure_reason = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f'<TokenAuditLog {self.action} user={self.user_id}>'
