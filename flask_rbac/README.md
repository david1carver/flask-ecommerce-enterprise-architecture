# Flask RBAC Module

Role-Based Access Control (RBAC) for Flask with Flask-Principal integration.

## Features

- **Role-Based Access** — Assign roles to users (customer, staff, manager, admin, super_admin)
- **Fine-Grained Permissions** — Resource:action permission model (e.g., `orders:read`, `products:delete`)
- **Flask-Principal Integration** — Identity management and permission checking
- **Privilege Escalation Prevention** — Users can only assign roles lower than their own
- **Audit Logging** — Track all RBAC changes
- **Decorators** — Easy route protection with `@role_required`, `@permission_required`

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

```bash
python app.py
```

Server runs on `http://localhost:5000`

## Default Roles & Permissions

### Role Hierarchy

| Role | Priority | Description |
|------|----------|-------------|
| super_admin | 100 | Full system access (all permissions) |
| admin | 80 | Administrative access |
| manager | 60 | Management access |
| staff | 40 | Staff access |
| customer | 10 | Customer access |

### Default Permissions

```
users:read, users:create, users:update, users:delete
roles:read, roles:create, roles:update, roles:delete, roles:assign
orders:read, orders:create, orders:update, orders:delete, orders:refund
products:read, products:create, products:update, products:delete
inventory:read, inventory:update
reports:read, analytics:read
settings:read, settings:update
```

---

## Decorators

### `@role_required(*roles)`
Require user to have at least one of the specified roles.

```python
@app.route('/api/reports')
@role_required('manager', 'admin')
def reports():
    return jsonify({'report': 'data'})
```

### `@permission_required(*permissions)`
Require user to have at least one of the specified permissions.

```python
@app.route('/api/orders', methods=['POST'])
@permission_required('orders:create')
def create_order():
    return jsonify({'order': 'created'})
```

### `@all_permissions_required(*permissions)`
Require user to have ALL specified permissions.

```python
@app.route('/api/orders/<id>/refund')
@all_permissions_required('orders:read', 'orders:refund')
def refund_order(id):
    return jsonify({'refunded': True})
```

### `@resource_access(resource, action)`
Check permission using resource:action format.

```python
@app.route('/api/products/<id>', methods=['DELETE'])
@resource_access('products', 'delete')
def delete_product(id):
    return jsonify({'deleted': True})
```

### `@admin_required`
Shortcut for requiring admin or super_admin role.

```python
@app.route('/api/admin/users')
@admin_required
def list_users():
    return jsonify({'users': []})
```

### `@super_admin_required`
Require super_admin role (highest privilege).

```python
@app.route('/api/admin/settings')
@super_admin_required
def update_settings():
    return jsonify({'updated': True})
```

---

## API Endpoints

### Roles

#### GET `/api/rbac/roles`
List all roles with permissions.

**Required:** `roles:read` permission

```json
{
  "roles": [
    {
      "id": 1,
      "name": "super_admin",
      "description": "Full system access",
      "is_system": true,
      "priority": 100,
      "permissions": ["*"],
      "user_count": 1
    }
  ]
}
```

#### POST `/api/rbac/roles`
Create a new role.

**Required:** `roles:create` permission

```json
// Request
{
  "name": "moderator",
  "description": "Content moderator",
  "priority": 50
}

// Response 201
{
  "message": "Role created successfully",
  "role": {
    "id": 6,
    "name": "moderator",
    "priority": 50
  }
}
```

#### DELETE `/api/rbac/roles/<role_id>`
Delete a role (system roles cannot be deleted).

**Required:** `roles:delete` permission

---

### Permissions

#### GET `/api/rbac/permissions`
List all permissions grouped by resource.

**Required:** `roles:read` permission

```json
{
  "permissions": [...],
  "by_resource": {
    "orders": [
      {"id": 1, "name": "orders:read", "action": "read"},
      {"id": 2, "name": "orders:create", "action": "create"}
    ],
    "products": [...]
  }
}
```

#### POST `/api/rbac/permissions`
Create a new permission.

**Required:** `super_admin` role

```json
// Request
{
  "name": "reports:export",
  "resource": "reports",
  "action": "export",
  "description": "Export reports to CSV"
}
```

---

### Role-Permission Management

#### POST `/api/rbac/roles/<role_id>/permissions`
Grant permission to role.

**Required:** `roles:update` permission

```json
// Request
{
  "permission_id": 5
}
```

#### DELETE `/api/rbac/roles/<role_id>/permissions/<permission_id>`
Revoke permission from role.

---

### User-Role Management

#### GET `/api/rbac/users/<user_id>/roles`
Get all roles and permissions for a user.

**Required:** `users:read` permission

```json
{
  "user_id": 1,
  "email": "user@example.com",
  "roles": [
    {"id": 1, "name": "admin", "description": "Administrative access"}
  ],
  "permissions": ["users:read", "orders:read", ...]
}
```

#### POST `/api/rbac/users/<user_id>/roles`
Assign role to user.

**Required:** `roles:assign` permission

```json
// Request
{
  "role_id": 3
}
```

**Note:** Cannot assign roles with higher priority than your own (privilege escalation prevention).

#### DELETE `/api/rbac/users/<user_id>/roles/<role_id>`
Revoke role from user.

---

### Current User

#### GET `/api/rbac/me/permissions`
Get current user's roles and permissions.

```json
{
  "user_id": 1,
  "email": "admin@example.com",
  "roles": ["admin"],
  "permissions": ["users:read", "orders:read", ...],
  "is_admin": true,
  "is_super_admin": false
}
```

#### POST `/api/rbac/me/can`
Check if current user has specific permission.

```json
// Request
{
  "permission": "orders:refund"
}
// OR
{
  "resource": "orders",
  "action": "refund"
}

// Response
{
  "permission": "orders:refund",
  "allowed": true
}
```

---

### Audit Log

#### GET `/api/rbac/audit-log`
Get RBAC audit log.

**Required:** `admin` role

```json
{
  "logs": [
    {
      "id": 1,
      "action": "role_assigned",
      "actor_id": 1,
      "target_user_id": 2,
      "role_id": 3,
      "details": "{\"user\": \"staff@example.com\", \"role\": \"staff\"}",
      "ip_address": "192.168.1.1",
      "created_at": "2025-12-09T10:30:00"
    }
  ]
}
```

---

## Usage Examples

### Checking Permissions in Code

```python
from flask_rbac.rbac_service import rbac_service

# Check if user has permission
if rbac_service.user_has_permission(user_id, 'orders:refund'):
    process_refund(order_id)

# Check if user has role
if rbac_service.user_has_role(user_id, 'manager'):
    show_manager_dashboard()

# Get all user permissions
permissions = rbac_service.get_user_permissions(user_id)
```

### User Model Methods

```python
user = User.query.get(user_id)

# Check role
if user.has_role('admin'):
    ...

# Check permission
if user.has_permission('products:delete'):
    ...

# Get all permissions
permissions = user.get_permissions()  # Returns set of permission names
```

---

## Frontend Integration

```javascript
// Store permissions after login
const { permissions, roles } = loginResponse.user;

// Check permission
function canAccess(permission) {
  return permissions.includes(permission) || roles.includes('super_admin');
}

// Use in UI
{canAccess('products:delete') && (
  <button onClick={deleteProduct}>Delete</button>
)}

// Dynamic permission check
const response = await fetch('/api/rbac/me/can', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({ permission: 'orders:refund' })
});
const { allowed } = await response.json();
```

---

## File Structure

```
flask_rbac/
├── app.py              # Main Flask application
├── models.py           # SQLAlchemy models (User, Role, Permission, AuditLog)
├── rbac_service.py     # Core RBAC logic with Flask-Principal
├── decorators.py       # Route protection decorators
├── routes.py           # RBAC API endpoints
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## Security Considerations

1. **Privilege Escalation Prevention** — Users cannot assign roles higher than their own priority
2. **System Roles Protection** — System roles (super_admin, admin, customer) cannot be deleted
3. **Audit Trail** — All RBAC changes are logged with actor, target, and timestamp
4. **Permission Caching** — Permissions are loaded into Flask-Principal identity for efficient checking
5. **Super Admin Bypass** — Super admin role automatically has all permissions

---

## License

MIT
