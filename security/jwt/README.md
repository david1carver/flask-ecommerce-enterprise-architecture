# Flask JWT Module

Enterprise JWT authentication with 15min access tokens, 7-day refresh tokens, and token rotation.

## Features

- **Short-Lived Access Tokens** — 15 minute expiry for security
- **Long-Lived Refresh Tokens** — 7 day expiry for convenience
- **Token Rotation** — New refresh token issued on each use
- **Reuse Detection** — Detects token theft and revokes entire token family
- **Session Management** — Track and revoke individual sessions/devices
- **Token Blacklisting** — Immediate revocation of access tokens
- **Audit Logging** — Track all authentication events
- **Mass Revocation** — Invalidate all user tokens instantly

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

```bash
python app.py
```

Server runs on `http://localhost:5000`

---

## Token Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        AUTHENTICATION FLOW                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │  Login   │───▶│  Access  │───▶│  API     │───▶│ Response │  │
│  │ (email/  │    │  Token   │    │ Request  │    │          │  │
│  │  pass)   │    │ (15 min) │    │          │    │          │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘  │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────┐                                                   │
│  │ Refresh  │    ← Store securely (httpOnly cookie / secure)   │
│  │  Token   │                                                   │
│  │ (7 days) │                                                   │
│  └──────────┘                                                   │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                   TOKEN REFRESH FLOW                      │  │
│  │                                                           │  │
│  │   Access Token Expired?                                   │  │
│  │          │                                                │  │
│  │          ▼                                                │  │
│  │   ┌──────────────┐     ┌───────────────────┐             │  │
│  │   │ POST /refresh │────▶│ Validate Refresh  │             │  │
│  │   │ + refresh_token│    │ Token             │             │  │
│  │   └──────────────┘     └───────────────────┘             │  │
│  │                                │                          │  │
│  │                                ▼                          │  │
│  │                        ┌───────────────┐                  │  │
│  │                        │ Token Rotation │                 │  │
│  │                        │ (old revoked)  │                 │  │
│  │                        └───────────────┘                  │  │
│  │                                │                          │  │
│  │                                ▼                          │  │
│  │                    ┌─────────────────────┐                │  │
│  │                    │ New Access Token    │                │  │
│  │                    │ New Refresh Token   │                │  │
│  │                    └─────────────────────┘                │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Configuration

```python
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 15       # Minutes
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 7       # Days
app.config['JWT_ALGORITHM'] = 'HS256'
app.config['JWT_ISSUER'] = 'flask-ecommerce'
app.config['JWT_AUDIENCE'] = 'flask-ecommerce-api'
app.config['JWT_TOKEN_ROTATION'] = True           # New refresh token on use
app.config['JWT_REUSE_DETECTION'] = True          # Detect token theft
app.config['JWT_MAX_SESSIONS'] = 10               # Max devices per user
```

---

## API Endpoints

### POST `/api/auth/login`
Login with email/password.

```json
// Request
{
  "email": "user@example.com",
  "password": "password123",
  "device_info": "iPhone 15"  // optional
}

// Response 200
{
  "message": "Login successful",
  "user": {
    "id": 1,
    "email": "user@example.com"
  },
  "access_token": "eyJ...",
  "refresh_token": "1.abc123...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_expires_in": 604800
}
```

### POST `/api/auth/refresh`
Refresh access token.

```json
// Request
{
  "refresh_token": "1.abc123..."
}

// Response 200
{
  "access_token": "eyJ...",
  "refresh_token": "1.xyz789...",  // New token (rotation)
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_expires_in": 604800
}
```

### POST `/api/auth/logout`
Logout current session.

**Headers:** `Authorization: Bearer <access_token>`

```json
// Request (optional)
{
  "refresh_token": "1.abc123..."  // Revoke refresh token too
}

// Response 200
{
  "message": "Logged out successfully"
}
```

### POST `/api/auth/logout-all`
Logout from all devices.

**Headers:** `Authorization: Bearer <access_token>`

```json
// Response 200
{
  "message": "Logged out from all devices"
}
```

### POST `/api/auth/verify`
Verify a token.

```json
// Request
{
  "token": "eyJ..."
}

// Response 200
{
  "valid": true,
  "payload": {
    "sub": 1,
    "email": "user@example.com",
    "iat": 1702123456,
    "exp": 1702124356
  }
}
```

### GET `/api/auth/me`
Get current user from token.

**Headers:** `Authorization: Bearer <access_token>`

```json
// Response 200
{
  "id": 1,
  "email": "user@example.com",
  "is_active": true,
  "last_login": "2025-12-09T10:30:00"
}
```

### GET `/api/auth/sessions`
List active sessions.

**Headers:** `Authorization: Bearer <access_token>`

```json
// Response 200
{
  "sessions": [
    {
      "id": 1,
      "device_info": "iPhone 15",
      "ip_address": "192.168.1.1",
      "issued_at": "2025-12-09T10:30:00",
      "last_used_at": "2025-12-09T11:00:00",
      "expires_at": "2025-12-16T10:30:00"
    }
  ],
  "count": 1
}
```

### DELETE `/api/auth/sessions/<session_id>`
Revoke specific session.

**Headers:** `Authorization: Bearer <access_token>`

```json
// Response 200
{
  "message": "Session revoked"
}
```

### GET `/api/auth/token-audit`
Get authentication audit log.

**Headers:** `Authorization: Bearer <access_token>`

```json
// Response 200
{
  "audit_log": [
    {
      "action": "login",
      "token_type": "access",
      "ip_address": "192.168.1.1",
      "success": true,
      "created_at": "2025-12-09T10:30:00"
    }
  ]
}
```

---

## Decorators

### `@jwt_required`
Require valid access token.

```python
@app.route('/api/profile')
@jwt_required
def profile():
    user_id = g.current_user_id
    email = g.current_user_email
    return jsonify({'user_id': user_id})
```

### `@jwt_optional`
JWT is optional - set context if present.

```python
@app.route('/api/products')
@jwt_optional
def products():
    if g.current_user_id:
        # Personalized response
    else:
        # Generic response
```

### `@fresh_jwt_required`
Require fresh JWT (issued within 10 minutes).

```python
@app.route('/api/password', methods=['PUT'])
@fresh_jwt_required
def change_password():
    # Sensitive operation
```

### `@claims_required(*claims)`
Require specific claims in token.

```python
@app.route('/api/admin')
@jwt_required
@claims_required('is_admin')
def admin():
    # Only if token has is_admin=True
```

### `@verify_claims(**claims)`
Verify claim values.

```python
@app.route('/api/premium')
@jwt_required
@verify_claims(subscription='premium')
def premium():
    # Only if subscription='premium'
```

---

## Token Rotation & Reuse Detection

### How It Works

1. Each refresh token belongs to a "token family"
2. When refreshed, old token is revoked, new token issued (same family)
3. If someone tries to use a revoked refresh token:
   - **Entire token family is revoked** (all sessions in that chain)
   - This indicates the original token was likely stolen

### Example Attack Scenario

```
1. User logs in → gets refresh_token_v1
2. Attacker steals refresh_token_v1
3. User refreshes → gets refresh_token_v2 (v1 revoked)
4. Attacker tries to use refresh_token_v1
5. System detects reuse → revokes ENTIRE family
6. Both user and attacker are logged out
7. User must re-authenticate
```

---

## Frontend Integration

```javascript
// Store tokens
let accessToken = null;
let refreshToken = null;

// Login
async function login(email, password) {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  
  const data = await response.json();
  accessToken = data.access_token;
  refreshToken = data.refresh_token;
  
  // Schedule refresh before expiry
  scheduleTokenRefresh(data.expires_in);
}

// API request with auto-refresh
async function apiRequest(url, options = {}) {
  options.headers = {
    ...options.headers,
    'Authorization': `Bearer ${accessToken}`
  };
  
  let response = await fetch(url, options);
  
  // If 401, try refresh
  if (response.status === 401) {
    const refreshed = await refreshTokens();
    if (refreshed) {
      options.headers['Authorization'] = `Bearer ${accessToken}`;
      response = await fetch(url, options);
    }
  }
  
  return response;
}

// Refresh tokens
async function refreshTokens() {
  const response = await fetch('/api/auth/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken })
  });
  
  if (response.ok) {
    const data = await response.json();
    accessToken = data.access_token;
    refreshToken = data.refresh_token;  // New token (rotation)
    scheduleTokenRefresh(data.expires_in);
    return true;
  }
  
  // Refresh failed - redirect to login
  window.location.href = '/login';
  return false;
}

// Schedule refresh before expiry
function scheduleTokenRefresh(expiresIn) {
  // Refresh 1 minute before expiry
  const refreshTime = (expiresIn - 60) * 1000;
  setTimeout(refreshTokens, refreshTime);
}
```

---

## Security Best Practices

1. **Store refresh tokens securely** — httpOnly cookies or secure storage
2. **Use HTTPS** — Never transmit tokens over HTTP
3. **Short access token TTL** — 15 minutes limits exposure window
4. **Token rotation** — Each refresh invalidates previous token
5. **Reuse detection** — Revoke family on suspicious activity
6. **Max sessions** — Limit concurrent sessions per user
7. **Audit logging** — Track all authentication events

---

## File Structure

```
flask_jwt/
├── app.py              # Main Flask application
├── models.py           # User, RefreshToken, TokenBlacklist, AuditLog
├── jwt_service.py      # Core JWT logic with rotation
├── decorators.py       # @jwt_required, @fresh_jwt_required, etc.
├── routes.py           # Authentication API endpoints
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## License

MIT
