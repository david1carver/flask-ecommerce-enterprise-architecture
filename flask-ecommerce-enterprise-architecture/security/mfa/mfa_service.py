"""
MFA Service
Core MFA logic: TOTP generation, QR codes, verification, backup codes
"""

import pyotp
import qrcode
import secrets
import hashlib
import io
import base64
from datetime import datetime, timedelta
from typing import Tuple, List, Optional


class MFAService:
    """Service for handling TOTP-based MFA operations"""
    
    def __init__(self, app_name: str = "FlaskEcommerce", issuer: str = "FlaskEcommerce"):
        self.app_name = app_name
        self.issuer = issuer
        self.backup_code_count = 10
        self.totp_valid_window = 1  # Allow 1 period before/after for clock drift
    
    def generate_secret(self) -> str:
        """Generate a new TOTP secret (Base32 encoded)"""
        return pyotp.random_base32()
    
    def get_totp(self, secret: str) -> pyotp.TOTP:
        """Get TOTP object for a secret"""
        return pyotp.TOTP(secret)
    
    def generate_provisioning_uri(self, secret: str, user_email: str) -> str:
        """Generate the otpauth:// URI for authenticator apps"""
        totp = self.get_totp(secret)
        return totp.provisioning_uri(name=user_email, issuer_name=self.issuer)
    
    def generate_qr_code(self, secret: str, user_email: str) -> str:
        """
        Generate QR code as base64 encoded PNG
        Returns: Base64 string ready for <img src="data:image/png;base64,{result}">
        """
        uri = self.generate_provisioning_uri(secret, user_email)
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode('utf-8')
    
    def verify_totp(self, secret: str, code: str) -> bool:
        """
        Verify a TOTP code
        Args:
            secret: User's TOTP secret
            code: 6-digit code from authenticator app
        Returns:
            True if valid, False otherwise
        """
        if not code or not secret:
            return False
        
        # Remove any spaces/dashes user might have entered
        code = code.replace(' ', '').replace('-', '')
        
        if not code.isdigit() or len(code) != 6:
            return False
        
        totp = self.get_totp(secret)
        return totp.verify(code, valid_window=self.totp_valid_window)
    
    def generate_backup_codes(self) -> Tuple[List[str], List[str]]:
        """
        Generate backup codes for MFA recovery
        Returns:
            Tuple of (plain_codes, hashed_codes)
            - plain_codes: Show to user ONCE for them to save
            - hashed_codes: Store in database
        """
        plain_codes = []
        hashed_codes = []
        
        for _ in range(self.backup_code_count):
            # Generate 8-character alphanumeric code
            code = secrets.token_hex(4).upper()  # 8 hex characters
            formatted_code = f"{code[:4]}-{code[4:]}"  # Format: XXXX-XXXX
            
            plain_codes.append(formatted_code)
            hashed_codes.append(self._hash_backup_code(formatted_code))
        
        return plain_codes, hashed_codes
    
    def _hash_backup_code(self, code: str) -> str:
        """Hash a backup code for secure storage"""
        # Normalize: remove dashes, uppercase
        normalized = code.replace('-', '').upper()
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    def verify_backup_code(self, code: str, stored_hash: str) -> bool:
        """Verify a backup code against stored hash"""
        if not code or not stored_hash:
            return False
        
        code_hash = self._hash_backup_code(code)
        return secrets.compare_digest(code_hash, stored_hash)
    
    def get_current_code(self, secret: str) -> str:
        """Get current TOTP code (for testing/debugging only)"""
        totp = self.get_totp(secret)
        return totp.now()


# Singleton instance
mfa_service = MFAService()
