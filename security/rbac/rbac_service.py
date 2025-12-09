"""
RBAC Service
Core RBAC logic with Flask-Principal integration
"""

from flask import g, current_app
from flask_principal import Principal, Identity, RoleNeed, Permission, PermissionDenied
from flask_principal import identity_loaded, identity_changed
from functools import wraps
from typing import List, Optional, Set
import json

from .models import db, User, Role, Permission as PermissionModel, AuditLog


class RBACService:
    """Service for handling Role-Based Access Control operations"""
    
    def __init__(self, app=None):
        self.principal = Principal()
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize RBAC with Flask app"""
        self.principal.init_app(app)
        
        @identity_loaded.connect_via(app)
        def on_identity_loaded(sender, identity):
            """Load user permissions into identity when identity is set"""
            if hasattr(g, 'current_user_id'):
                user = User.query.get(g.current_user_id)
                if user:
                    # Add role needs
                    for role in user.roles:
                        identity.provides.add(RoleNeed(role.name))
                    
                    # Add permission needs
                    for permission in user.get_permissions():
                        identity.provides.add(PermissionNeed(permission))
    
    # ==================== ROLE MANAGEMENT ====================
    
    def create_role(self, name: str, description: str = None, priority: int = 0) -> Role:
        """Create a new role"""
        if Role.query.filter_by(name=name).first():
            raise ValueError(f"Role '{name}' already exists")
        
        role = Role(name=name, description=description, priority=priority)
        db.session.add(role)
        db.session.commit()
        
        self._log_action('role_created', role_id=role.id, details={'name': name})
        return role
    
    def delete_role(self, role_id: int) -> bool:
        """Delete a role (system roles cannot be deleted)"""
        role = Role.query.get(role_id)
        if not role:
            raise ValueError("Role not found")
        
        if role.is_system:
            raise ValueError("System roles cannot be deleted")
        
        role_name = role.name
        db.session.delete(role)
        db.session.commit()
        
        self._log_action('role_deleted', details={'name': role_name})
        return True
    
    def get_role(self, role_id: int = None, name: str = None) -> Optional[Role]:
        """Get role by ID or name"""
        if role_id:
            return Role.query.get(role_id)
        if name:
            return Role.query.filter_by(name=name).first()
        return None
    
    def get_all_roles(self) -> List[Role]:
        """Get all roles ordered by priority"""
        return Role.query.order_by(Role.priority.desc()).all()
    
    # ==================== PERMISSION MANAGEMENT ====================
    
    def create_permission(self, name: str, resource: str = None, 
                         action: str = None, description: str = None) -> PermissionModel:
        """Create a new permission"""
        if PermissionModel.query.filter_by(name=name).first():
            raise ValueError(f"Permission '{name}' already exists")
        
        permission = PermissionModel(
            name=name, 
            resource=resource, 
            action=action, 
            description=description
        )
        db.session.add(permission)
        db.session.commit()
        
        self._log_action('permission_created', permission_id=permission.id, details={'name': name})
        return permission
    
    def get_all_permissions(self) -> List[PermissionModel]:
        """Get all permissions"""
        return PermissionModel.query.order_by(PermissionModel.resource, PermissionModel.action).all()
    
    def grant_permission_to_role(self, role_id: int, permission_id: int) -> bool:
        """Grant a permission to a role"""
        role = Role.query.get(role_id)
        permission = PermissionModel.query.get(permission_id)
        
        if not role or not permission:
            raise ValueError("Role or permission not found")
        
        if permission not in role.permissions:
            role.permissions.append(permission)
            db.session.commit()
            
            self._log_action('permission_granted', role_id=role_id, 
                           permission_id=permission_id,
                           details={'role': role.name, 'permission': permission.name})
        return True
    
    def revoke_permission_from_role(self, role_id: int, permission_id: int) -> bool:
        """Revoke a permission from a role"""
        role = Role.query.get(role_id)
        permission = PermissionModel.query.get(permission_id)
        
        if not role or not permission:
            raise ValueError("Role or permission not found")
        
        if permission in role.permissions:
            role.permissions.remove(permission)
            db.session.commit()
            
            self._log_action('permission_revoked', role_id=role_id,
                           permission_id=permission_id,
                           details={'role': role.name, 'permission': permission.name})
        return True
    
    # ==================== USER-ROLE MANAGEMENT ====================
    
    def assign_role_to_user(self, user_id: int, role_id: int, assigned_by: int = None) -> bool:
        """Assign a role to a user"""
        user = User.query.get(user_id)
        role = Role.query.get(role_id)
        
        if not user or not role:
            raise ValueError("User or role not found")
        
        if role not in user.roles:
            user.roles.append(role)
            db.session.commit()
            
            self._log_action('role_assigned', target_user_id=user_id, role_id=role_id,
                           details={'user': user.email, 'role': role.name})
        return True
    
    def revoke_role_from_user(self, user_id: int, role_id: int) -> bool:
        """Revoke a role from a user"""
        user = User.query.get(user_id)
        role = Role.query.get(role_id)
        
        if not user or not role:
            raise ValueError("User or role not found")
        
        if role in user.roles:
            user.roles.remove(role)
            db.session.commit()
            
            self._log_action('role_revoked', target_user_id=user_id, role_id=role_id,
                           details={'user': user.email, 'role': role.name})
        return True
    
    def get_user_roles(self, user_id: int) -> List[Role]:
        """Get all roles for a user"""
        user = User.query.get(user_id)
        if not user:
            return []
        return user.roles
    
    def get_user_permissions(self, user_id: int) -> Set[str]:
        """Get all permissions for a user"""
        user = User.query.get(user_id)
        if not user:
            return set()
        return user.get_permissions()
    
    # ==================== PERMISSION CHECKS ====================
    
    def user_has_role(self, user_id: int, role_name: str) -> bool:
        """Check if user has a specific role"""
        user = User.query.get(user_id)
        if not user:
            return False
        return user.has_role(role_name)
    
    def user_has_permission(self, user_id: int, permission_name: str) -> bool:
        """Check if user has a specific permission"""
        user = User.query.get(user_id)
        if not user:
            return False
        
        # Super admin has all permissions
        if user.has_role('super_admin'):
            return True
        
        return user.has_permission(permission_name)
    
    def user_can_access_resource(self, user_id: int, resource: str, action: str) -> bool:
        """Check if user can perform action on resource"""
        permission_name = f"{resource}:{action}"
        return self.user_has_permission(user_id, permission_name)
    
    # ==================== INITIALIZATION ====================
    
    def init_default_roles_and_permissions(self):
        """Initialize default roles and permissions"""
        from .models import DEFAULT_ROLES, DEFAULT_PERMISSIONS, ROLE_PERMISSIONS
        
        # Create permissions
        for perm_data in DEFAULT_PERMISSIONS:
            if not PermissionModel.query.filter_by(name=perm_data['name']).first():
                permission = PermissionModel(**perm_data)
                db.session.add(permission)
        
        db.session.commit()
        
        # Create roles
        for role_data in DEFAULT_ROLES:
            if not Role.query.filter_by(name=role_data['name']).first():
                role = Role(**role_data)
                db.session.add(role)
        
        db.session.commit()
        
        # Assign permissions to roles
        for role_name, permissions in ROLE_PERMISSIONS.items():
            role = Role.query.filter_by(name=role_name).first()
            if role:
                if '*' in permissions:
                    # Super admin gets all permissions
                    role.permissions = PermissionModel.query.all()
                else:
                    for perm_name in permissions:
                        perm = PermissionModel.query.filter_by(name=perm_name).first()
                        if perm and perm not in role.permissions:
                            role.permissions.append(perm)
        
        db.session.commit()
    
    # ==================== AUDIT LOGGING ====================
    
    def _log_action(self, action: str, target_user_id: int = None, 
                   role_id: int = None, permission_id: int = None, 
                   details: dict = None):
        """Log RBAC action for audit trail"""
        from flask import request
        
        log = AuditLog(
            action=action,
            actor_id=getattr(g, 'current_user_id', None),
            target_user_id=target_user_id,
            role_id=role_id,
            permission_id=permission_id,
            details=json.dumps(details) if details else None,
            ip_address=request.remote_addr if request else None
        )
        db.session.add(log)
        db.session.commit()
    
    def get_audit_logs(self, limit: int = 100) -> List[AuditLog]:
        """Get recent audit logs"""
        return AuditLog.query.order_by(AuditLog.created_at.desc()).limit(limit).all()


# Custom Permission Need for fine-grained permissions
class PermissionNeed:
    """Custom need for permission-based access control"""
    def __init__(self, permission_name: str):
        self.permission_name = permission_name
    
    def __eq__(self, other):
        return isinstance(other, PermissionNeed) and self.permission_name == other.permission_name
    
    def __hash__(self):
        return hash(('permission', self.permission_name))
    
    def __repr__(self):
        return f'PermissionNeed({self.permission_name})'


# Singleton instance
rbac_service = RBACService()
