"""
RBAC API Endpoints
Flask Blueprint with all RBAC management routes
"""

from flask import Blueprint, request, jsonify, g

from .models import db, User, Role, Permission, AuditLog
from .rbac_service import rbac_service
from .decorators import admin_required, super_admin_required, permission_required

rbac_bp = Blueprint('rbac', __name__, url_prefix='/api/rbac')


# ==================== ROLE ENDPOINTS ====================

@rbac_bp.route('/roles', methods=['GET'])
@permission_required('roles:read')
def list_roles():
    """
    Get all roles
    
    Returns:
        List of roles with their permissions
    """
    roles = rbac_service.get_all_roles()
    
    return jsonify({
        'roles': [{
            'id': role.id,
            'name': role.name,
            'description': role.description,
            'is_system': role.is_system,
            'priority': role.priority,
            'permissions': [p.name for p in role.permissions],
            'user_count': len(role.users)
        } for role in roles]
    })


@rbac_bp.route('/roles/<int:role_id>', methods=['GET'])
@permission_required('roles:read')
def get_role(role_id):
    """Get single role details"""
    role = rbac_service.get_role(role_id=role_id)
    
    if not role:
        return jsonify({'error': 'Role not found'}), 404
    
    return jsonify({
        'id': role.id,
        'name': role.name,
        'description': role.description,
        'is_system': role.is_system,
        'priority': role.priority,
        'permissions': [{
            'id': p.id,
            'name': p.name,
            'description': p.description
        } for p in role.permissions],
        'users': [{
            'id': u.id,
            'email': u.email
        } for u in role.users]
    })


@rbac_bp.route('/roles', methods=['POST'])
@permission_required('roles:create')
def create_role():
    """
    Create a new role
    
    Request body:
        - name: Role name (required)
        - description: Role description
        - priority: Role priority (higher = more authority)
    """
    data = request.get_json()
    name = data.get('name', '').strip()
    description = data.get('description', '')
    priority = data.get('priority', 0)
    
    if not name:
        return jsonify({'error': 'Role name is required'}), 400
    
    try:
        role = rbac_service.create_role(name, description, priority)
        return jsonify({
            'message': 'Role created successfully',
            'role': {
                'id': role.id,
                'name': role.name,
                'description': role.description,
                'priority': role.priority
            }
        }), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@rbac_bp.route('/roles/<int:role_id>', methods=['PUT'])
@permission_required('roles:update')
def update_role(role_id):
    """Update a role"""
    role = Role.query.get(role_id)
    
    if not role:
        return jsonify({'error': 'Role not found'}), 404
    
    if role.is_system:
        return jsonify({'error': 'System roles cannot be modified'}), 403
    
    data = request.get_json()
    
    if 'description' in data:
        role.description = data['description']
    if 'priority' in data:
        role.priority = data['priority']
    
    db.session.commit()
    
    return jsonify({
        'message': 'Role updated successfully',
        'role': {
            'id': role.id,
            'name': role.name,
            'description': role.description,
            'priority': role.priority
        }
    })


@rbac_bp.route('/roles/<int:role_id>', methods=['DELETE'])
@permission_required('roles:delete')
def delete_role(role_id):
    """Delete a role"""
    try:
        rbac_service.delete_role(role_id)
        return jsonify({'message': 'Role deleted successfully'})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


# ==================== PERMISSION ENDPOINTS ====================

@rbac_bp.route('/permissions', methods=['GET'])
@permission_required('roles:read')
def list_permissions():
    """Get all permissions"""
    permissions = rbac_service.get_all_permissions()
    
    # Group by resource
    by_resource = {}
    for perm in permissions:
        resource = perm.resource or 'other'
        if resource not in by_resource:
            by_resource[resource] = []
        by_resource[resource].append({
            'id': perm.id,
            'name': perm.name,
            'action': perm.action,
            'description': perm.description
        })
    
    return jsonify({
        'permissions': [{
            'id': p.id,
            'name': p.name,
            'resource': p.resource,
            'action': p.action,
            'description': p.description
        } for p in permissions],
        'by_resource': by_resource
    })


@rbac_bp.route('/permissions', methods=['POST'])
@super_admin_required
def create_permission():
    """Create a new permission (super admin only)"""
    data = request.get_json()
    name = data.get('name', '').strip()
    resource = data.get('resource', '')
    action = data.get('action', '')
    description = data.get('description', '')
    
    if not name:
        return jsonify({'error': 'Permission name is required'}), 400
    
    try:
        permission = rbac_service.create_permission(name, resource, action, description)
        return jsonify({
            'message': 'Permission created successfully',
            'permission': {
                'id': permission.id,
                'name': permission.name,
                'resource': permission.resource,
                'action': permission.action
            }
        }), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


# ==================== ROLE-PERMISSION MANAGEMENT ====================

@rbac_bp.route('/roles/<int:role_id>/permissions', methods=['POST'])
@permission_required('roles:update')
def grant_permission(role_id):
    """
    Grant permission to role
    
    Request body:
        - permission_id: Permission ID to grant
    """
    data = request.get_json()
    permission_id = data.get('permission_id')
    
    if not permission_id:
        return jsonify({'error': 'Permission ID is required'}), 400
    
    try:
        rbac_service.grant_permission_to_role(role_id, permission_id)
        return jsonify({'message': 'Permission granted successfully'})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@rbac_bp.route('/roles/<int:role_id>/permissions/<int:permission_id>', methods=['DELETE'])
@permission_required('roles:update')
def revoke_permission(role_id, permission_id):
    """Revoke permission from role"""
    try:
        rbac_service.revoke_permission_from_role(role_id, permission_id)
        return jsonify({'message': 'Permission revoked successfully'})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


# ==================== USER-ROLE MANAGEMENT ====================

@rbac_bp.route('/users/<int:user_id>/roles', methods=['GET'])
@permission_required('users:read')
def get_user_roles(user_id):
    """Get all roles for a user"""
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'user_id': user_id,
        'email': user.email,
        'roles': [{
            'id': role.id,
            'name': role.name,
            'description': role.description
        } for role in user.roles],
        'permissions': list(user.get_permissions())
    })


@rbac_bp.route('/users/<int:user_id>/roles', methods=['POST'])
@permission_required('roles:assign')
def assign_role(user_id):
    """
    Assign role to user
    
    Request body:
        - role_id: Role ID to assign
    """
    data = request.get_json()
    role_id = data.get('role_id')
    
    if not role_id:
        return jsonify({'error': 'Role ID is required'}), 400
    
    # Prevent privilege escalation
    if not _can_assign_role(g.current_user_id, role_id):
        return jsonify({'error': 'Cannot assign role with higher privilege than your own'}), 403
    
    try:
        rbac_service.assign_role_to_user(user_id, role_id, assigned_by=g.current_user_id)
        return jsonify({'message': 'Role assigned successfully'})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@rbac_bp.route('/users/<int:user_id>/roles/<int:role_id>', methods=['DELETE'])
@permission_required('roles:assign')
def revoke_role(user_id, role_id):
    """Revoke role from user"""
    # Prevent privilege escalation
    if not _can_assign_role(g.current_user_id, role_id):
        return jsonify({'error': 'Cannot revoke role with higher privilege than your own'}), 403
    
    try:
        rbac_service.revoke_role_from_user(user_id, role_id)
        return jsonify({'message': 'Role revoked successfully'})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


# ==================== CURRENT USER ENDPOINTS ====================

@rbac_bp.route('/me/permissions', methods=['GET'])
def my_permissions():
    """Get current user's roles and permissions"""
    if not hasattr(g, 'current_user_id'):
        return jsonify({'error': 'Authentication required'}), 401
    
    user = User.query.get(g.current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'user_id': user.id,
        'email': user.email,
        'roles': [role.name for role in user.roles],
        'permissions': list(user.get_permissions()),
        'is_admin': user.has_role('admin') or user.has_role('super_admin'),
        'is_super_admin': user.has_role('super_admin')
    })


@rbac_bp.route('/me/can', methods=['POST'])
def check_permission():
    """
    Check if current user has specific permission
    
    Request body:
        - permission: Permission to check (e.g., 'orders:read')
        OR
        - resource: Resource name
        - action: Action name
    """
    if not hasattr(g, 'current_user_id'):
        return jsonify({'error': 'Authentication required'}), 401
    
    data = request.get_json()
    permission = data.get('permission')
    
    if not permission:
        resource = data.get('resource')
        action = data.get('action')
        if resource and action:
            permission = f"{resource}:{action}"
    
    if not permission:
        return jsonify({'error': 'Permission or resource/action required'}), 400
    
    has_permission = rbac_service.user_has_permission(g.current_user_id, permission)
    
    return jsonify({
        'permission': permission,
        'allowed': has_permission
    })


# ==================== AUDIT LOG ENDPOINTS ====================

@rbac_bp.route('/audit-log', methods=['GET'])
@admin_required
def get_audit_log():
    """Get RBAC audit log"""
    limit = request.args.get('limit', 100, type=int)
    logs = rbac_service.get_audit_logs(limit=limit)
    
    return jsonify({
        'logs': [{
            'id': log.id,
            'action': log.action,
            'actor_id': log.actor_id,
            'target_user_id': log.target_user_id,
            'role_id': log.role_id,
            'details': log.details,
            'ip_address': log.ip_address,
            'created_at': log.created_at.isoformat()
        } for log in logs]
    })


# ==================== INITIALIZATION ENDPOINT ====================

@rbac_bp.route('/init', methods=['POST'])
@super_admin_required
def initialize_rbac():
    """Initialize default roles and permissions (super admin only)"""
    rbac_service.init_default_roles_and_permissions()
    return jsonify({'message': 'RBAC initialized with default roles and permissions'})


# ==================== HELPER FUNCTIONS ====================

def _can_assign_role(actor_id: int, role_id: int) -> bool:
    """Check if actor can assign/revoke the specified role (privilege escalation prevention)"""
    actor = User.query.get(actor_id)
    target_role = Role.query.get(role_id)
    
    if not actor or not target_role:
        return False
    
    # Super admin can assign any role
    if actor.has_role('super_admin'):
        return True
    
    # Get actor's highest priority role
    actor_max_priority = max((role.priority for role in actor.roles), default=0)
    
    # Can only assign roles with lower priority
    return target_role.priority < actor_max_priority
