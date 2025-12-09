"""
RBAC Decorators
Route protection decorators for role and permission-based access control
"""

from functools import wraps
from flask import g, jsonify, request
from typing import List, Union

from .models import User


def role_required(*roles: str):
    """
    Decorator: Require user to have at least one of the specified roles
    
    Usage:
        @role_required('admin')
        @role_required('admin', 'manager')  # Either role works
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user_id'):
                return jsonify({'error': 'Authentication required'}), 401
            
            user = User.query.get(g.current_user_id)
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            if not user.is_active:
                return jsonify({'error': 'Account is disabled'}), 403
            
            # Check if user has any of the required roles
            user_role_names = [role.name for role in user.roles]
            
            # Super admin bypasses role checks
            if 'super_admin' in user_role_names:
                return f(*args, **kwargs)
            
            if not any(role in user_role_names for role in roles):
                return jsonify({
                    'error': 'Access denied',
                    'required_roles': list(roles),
                    'your_roles': user_role_names
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator


def permission_required(*permissions: str):
    """
    Decorator: Require user to have at least one of the specified permissions
    
    Usage:
        @permission_required('orders:read')
        @permission_required('orders:update', 'orders:delete')  # Either works
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user_id'):
                return jsonify({'error': 'Authentication required'}), 401
            
            user = User.query.get(g.current_user_id)
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            if not user.is_active:
                return jsonify({'error': 'Account is disabled'}), 403
            
            # Super admin has all permissions
            if user.has_role('super_admin'):
                return f(*args, **kwargs)
            
            # Check if user has any of the required permissions
            user_permissions = user.get_permissions()
            
            if not any(perm in user_permissions for perm in permissions):
                return jsonify({
                    'error': 'Permission denied',
                    'required_permissions': list(permissions)
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator


def all_permissions_required(*permissions: str):
    """
    Decorator: Require user to have ALL specified permissions
    
    Usage:
        @all_permissions_required('orders:read', 'orders:update')  # Both needed
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user_id'):
                return jsonify({'error': 'Authentication required'}), 401
            
            user = User.query.get(g.current_user_id)
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            if not user.is_active:
                return jsonify({'error': 'Account is disabled'}), 403
            
            # Super admin has all permissions
            if user.has_role('super_admin'):
                return f(*args, **kwargs)
            
            # Check if user has ALL required permissions
            user_permissions = user.get_permissions()
            missing = [perm for perm in permissions if perm not in user_permissions]
            
            if missing:
                return jsonify({
                    'error': 'Permission denied',
                    'missing_permissions': missing
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator


def resource_access(resource: str, action: str):
    """
    Decorator: Check permission using resource:action format
    
    Usage:
        @resource_access('orders', 'read')  # Checks 'orders:read' permission
        @resource_access('products', 'update')
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user_id'):
                return jsonify({'error': 'Authentication required'}), 401
            
            user = User.query.get(g.current_user_id)
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            if not user.is_active:
                return jsonify({'error': 'Account is disabled'}), 403
            
            # Super admin has all permissions
            if user.has_role('super_admin'):
                return f(*args, **kwargs)
            
            permission_name = f"{resource}:{action}"
            if not user.has_permission(permission_name):
                return jsonify({
                    'error': 'Permission denied',
                    'required': permission_name
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator


def admin_required(f):
    """
    Decorator: Shortcut for requiring admin or super_admin role
    
    Usage:
        @admin_required
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(g, 'current_user_id'):
            return jsonify({'error': 'Authentication required'}), 401
        
        user = User.query.get(g.current_user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if not user.is_active:
            return jsonify({'error': 'Account is disabled'}), 403
        
        if not (user.has_role('admin') or user.has_role('super_admin')):
            return jsonify({'error': 'Admin access required'}), 403
        
        return f(*args, **kwargs)
    return decorated


def super_admin_required(f):
    """
    Decorator: Require super_admin role (highest privilege)
    
    Usage:
        @super_admin_required
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(g, 'current_user_id'):
            return jsonify({'error': 'Authentication required'}), 401
        
        user = User.query.get(g.current_user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if not user.is_active:
            return jsonify({'error': 'Account is disabled'}), 403
        
        if not user.has_role('super_admin'):
            return jsonify({'error': 'Super admin access required'}), 403
        
        return f(*args, **kwargs)
    return decorated


class RBACContext:
    """
    Context manager for temporary permission elevation
    
    Usage:
        with RBACContext(user_id, 'orders:delete'):
            # Code that requires temporary permission
    """
    def __init__(self, user_id: int, *permissions: str):
        self.user_id = user_id
        self.permissions = permissions
        self.original_permissions = None
    
    def __enter__(self):
        # Store original state (for auditing, not actual elevation)
        user = User.query.get(self.user_id)
        if user:
            self.original_permissions = user.get_permissions()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Log the elevated access
        pass
