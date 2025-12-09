# Flask MFA Module

TOTP-based Multi-Factor Authentication for Flask with JWT integration.

## Features

- **TOTP Authentication** — Google Authenticator, Authy, etc.
- **QR Code Generation** — Easy setup via camera scan
- **Backup Codes** — 10 one-time recovery codes
- **JWT Integration** — MFA-aware token flow with step-up authentication
- **Rate Limiting** — Protection against brute force attempts
- **Audit Logging** — Track all MFA verification attempts

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

```bash
python app.py
```

Server runs on `http://localhost:5000`

## Authentication Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Login     │────▶│ Check MFA   │────▶│ MFA Verify  │────▶│ Full Access │
│  (email/pw) │     │  Enabled?   │     │  (TOTP)     │     │  (JWT)      │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                          │                                        
                          │ No MFA                                 
                          ▼                                        
                    ┌─────────────┐                               
                    │ Full Access │                               
                    │   (JWT)     │                               
                    └─────────────┘                               
```

## API Endpoints

### Authentication

#### POST `/api/auth/register`
Register a new user.

```json
// Request
{
  "email": "user@example.com",
  "password": "securepassword"
}

// Response 201
{
  "message": "User registered successfully"
}
```

#### POST `/api/auth/login`
Login with email/password. Returns JWT tokens.

```json
// Request
{
  "email": "user@example.com",
  "password": "securepassword"
}

// Response 200 (MFA disabled)
{
  "message": "Login successful",
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "mfa_required": false
}

// Response 200 (MFA enabled)
{
  "message": "MFA verification required",
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "mfa_required": true,
  "next_step": "POST /api/auth/mfa/verify with your authenticator code"
}
```

---

### MFA Setup

#### POST `/api/auth/mfa/setup`
Initialize MFA setup. Returns QR code for authenticator app.

**Headers:** `Authorization: Bearer <access_token>`

```json
// Response 200
{
  "message": "MFA setup initiated...",
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "iVBORw0KGgo...",
  "qr_code_data_uri": "data:image/png;base64,iVBORw0KGgo...",
  "provisioning_uri": "otpauth://totp/FlaskEcommerce:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=FlaskEcommerce"
}
```

#### POST `/api/auth/mfa/setup/verify`
Complete MFA setup by verifying a code from authenticator app.

**Headers:** `Authorization: Bearer <access_token>`

```json
// Request
{
  "code": "123456"
}

// Response 200
{
  "message": "MFA enabled successfully",
  "backup_codes": [
    "A1B2-C3D4",
    "E5F6-G7H8",
    ...
  ],
  "warning": "SAVE THESE BACKUP CODES! They will not be shown again.",
  "backup_codes_count": 10
}
```

---

### MFA Verification

#### POST `/api/auth/mfa/verify`
Verify MFA code during login (after receiving `mfa_required: true`).

**Headers:** `Authorization: Bearer <access_token>`

```json
// Request (TOTP code)
{
  "code": "123456"
}

// Request (Backup code)
{
  "code": "A1B2-C3D4"
}

// Response 200
{
  "message": "MFA verification successful",
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "mfa_required": false
}
```

---

### MFA Management

#### GET `/api/auth/mfa/status`
Get current MFA status.

**Headers:** `Authorization: Bearer <access_token>`

```json
// Response 200
{
  "enabled": true,
  "verified": true,
  "enabled_at": "2025-12-09T10:30:00",
  "backup_codes_remaining": 8
}
```

#### POST `/api/auth/mfa/disable`
Disable MFA (requires current TOTP code).

**Headers:** `Authorization: Bearer <access_token>`

```json
// Request
{
  "code": "123456"
}

// Response 200
{
  "message": "MFA has been disabled",
  "access_token": "eyJ...",
  "refresh_token": "eyJ..."
}
```

#### POST `/api/auth/mfa/backup-codes/regenerate`
Generate new backup codes (invalidates existing codes).

**Headers:** `Authorization: Bearer <access_token>`

```json
// Request
{
  "code": "123456"
}

// Response 200
{
  "message": "Backup codes regenerated",
  "backup_codes": ["A1B2-C3D4", ...],
  "warning": "SAVE THESE BACKUP CODES! Previous codes are now invalid."
}
```

---

## Protected Routes

### `@jwt_required` Decorator
Requires valid JWT token. Does NOT check MFA status.

```python
@app.route('/api/profile')
@jwt_required
def profile():
    # Accessible with valid JWT, even if MFA pending
    return jsonify({'user_id': g.current_user_id})
```

### `@mfa_required` Decorator  
Requires valid JWT AND completed MFA verification.

```python
@app.route('/api/sensitive-action')
@mfa_required
def sensitive_action():
    # Only accessible after MFA verification
    return jsonify({'data': 'sensitive'})
```

---

## JWT Token Structure

```json
{
  "sub": 1,                    // User ID
  "email": "user@example.com",
  "type": "access",            // "access" or "refresh"
  "mfa_verified": true,        // MFA completed this session
  "mfa_required": true,        // User has MFA enabled
  "iat": 1702123456,
  "exp": 1702124356
}
```

---

## Frontend Integration Example

```javascript
// 1. Login
const loginResponse = await fetch('/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password })
});

const data = await loginResponse.json();

if (data.mfa_required) {
  // 2. Show MFA input screen
  const mfaCode = prompt('Enter your authenticator code:');
  
  // 3. Verify MFA
  const mfaResponse = await fetch('/api/auth/mfa/verify', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${data.access_token}`
    },
    body: JSON.stringify({ code: mfaCode })
  });
  
  const tokens = await mfaResponse.json();
  // Store tokens.access_token - now fully authenticated
}
```

---

## Security Considerations

1. **Store secrets securely** — Use environment variables for `JWT_SECRET_KEY`
2. **Use HTTPS** — Never transmit tokens over HTTP
3. **Token expiry** — Access tokens: 15min, Refresh tokens: 7 days
4. **Rate limiting** — 5 failed MFA attempts triggers 15-minute lockout
5. **Backup codes** — Hash before storing, one-time use only

---

## File Structure

```
flask_mfa/
├── app.py              # Main Flask application
├── models.py           # SQLAlchemy models (User, BackupCode, MFAAttempt)
├── mfa_service.py      # TOTP generation, QR codes, verification
├── jwt_service.py      # JWT handling with MFA awareness
├── routes.py           # MFA API endpoints blueprint
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## License

MIT
