"""
MFA Database Models
SQLAlchemy models for storing MFA secrets and backup codes
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    """User model with MFA support"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    
    # MFA fields
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(32), nullable=True)  # Base32 encoded TOTP secret
    mfa_enabled_at = Column(DateTime, nullable=True)
    
    # Backup codes
    backup_codes = relationship('BackupCode', back_populates='user', cascade='all, delete-orphan')
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.email}>'


class BackupCode(db.Model):
    """Backup codes for MFA recovery"""
    __tablename__ = 'backup_codes'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    code_hash = Column(String(255), nullable=False)  # Hashed backup code
    used = Column(Boolean, default=False, nullable=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship('User', back_populates='backup_codes')
    
    def __repr__(self):
        return f'<BackupCode {self.id} used={self.used}>'


class MFAAttempt(db.Model):
    """Track MFA verification attempts for rate limiting"""
    __tablename__ = 'mfa_attempts'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    ip_address = Column(String(45), nullable=True)
    success = Column(Boolean, nullable=False)
    attempt_type = Column(String(20), nullable=False)  # 'totp' or 'backup'
    created_at = Column(DateTime, default=datetime.utcnow)
