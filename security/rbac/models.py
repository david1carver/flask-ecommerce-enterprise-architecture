"""
RBAC Database Models
SQLAlchemy models for roles, permissions, and user associations
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Table, Text
from sqlalchemy.orm import relationship
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


# Association tables for many-to-many relationships
user_roles = Table(
    'user_roles',
    db.Model.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('assigned_at', DateTime, default=datetime.utcnow),
    Column('assigned_by', Integer, ForeignKey('users.id'), nullable=True)
)

role_permissions = Table(
    'role_permissions',
    db.Model.metadata,
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permissions.id'), primary_key=True)
)


class User(db.Model):
    """User model with RBAC support"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # RBAC relationships
    roles = relationship('Role', secondary=user_roles, back_populates='users', lazy='joined')
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def has_role(self, role_name: str) -> bool:
        """Check if user has a specific role"""
        return any(role.name == role_name for role in self.roles)
    
    def has_permission(self, permission_name: str) -> bool:
        """Check if user has a specific permission through any of their roles"""
        for role in self.roles:
            if role.has_permission(permission_name):
                return True
        return False
    
    def get_permissions(self) -> set:
        """Get all permissions for this user across all roles"""
        permissions = set()
        for role in self.roles:
            for perm in role.permissions:
                permissions.add(perm.name)
        return permissions
    
    def __repr__(self):
        return f'<User {self.email}>'


class Role(db.Model):
    """Role model for grouping permissions"""
    __tablename__ = 'roles'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(80), unique=True, nullable=False, index=True)
    description = Column(String(255), nullable=True)
    is_system = Column(Boolean, default=False)  # System roles can't be deleted
    priority = Column(Integer, default=0)  # Higher = more authority
    
    # Relationships
    users = relationship('User', secondary=user_roles, back_populates='roles')
    permissions = relationship('Permission', secondary=role_permissions, back_populates='roles', lazy='joined')
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def has_permission(self, permission_name: str) -> bool:
        """Check if role has a specific permission"""
        return any(perm.name == permission_name for perm in self.permissions)
    
    def __repr__(self):
        return f'<Role {self.name}>'


class Permission(db.Model):
    """Permission model for fine-grained access control"""
    __tablename__ = 'permissions'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(120), unique=True, nullable=False, index=True)
    description = Column(String(255), nullable=True)
    resource = Column(String(80), nullable=True)  # e.g., 'orders', 'users', 'products'
    action = Column(String(80), nullable=True)    # e.g., 'create', 'read', 'update', 'delete'
    
    # Relationships
    roles = relationship('Role', secondary=role_permissions, back_populates='permissions')
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Permission {self.name}>'


class AuditLog(db.Model):
    """Audit log for RBAC changes"""
    __tablename__ = 'rbac_audit_log'
    
    id = Column(Integer, primary_key=True)
    action = Column(String(50), nullable=False)  # 'role_assigned', 'role_revoked', 'permission_granted', etc.
    actor_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    target_user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    role_id = Column(Integer, ForeignKey('roles.id'), nullable=True)
    permission_id = Column(Integer, ForeignKey('permissions.id'), nullable=True)
    details = Column(Text, nullable=True)  # JSON string with additional context
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<AuditLog {self.action} at {self.created_at}>'


# Default roles and permissions
DEFAULT_ROLES = [
    {'name': 'super_admin', 'description': 'Full system access', 'is_system': True, 'priority': 100},
    {'name': 'admin', 'description': 'Administrative access', 'is_system': True, 'priority': 80},
    {'name': 'manager', 'description': 'Management access', 'is_system': False, 'priority': 60},
    {'name': 'staff', 'description': 'Staff access', 'is_system': False, 'priority': 40},
    {'name': 'customer', 'description': 'Customer access', 'is_system': True, 'priority': 10},
]

DEFAULT_PERMISSIONS = [
    # User management
    {'name': 'users:read', 'resource': 'users', 'action': 'read', 'description': 'View users'},
    {'name': 'users:create', 'resource': 'users', 'action': 'create', 'description': 'Create users'},
    {'name': 'users:update', 'resource': 'users', 'action': 'update', 'description': 'Update users'},
    {'name': 'users:delete', 'resource': 'users', 'action': 'delete', 'description': 'Delete users'},
    
    # Role management
    {'name': 'roles:read', 'resource': 'roles', 'action': 'read', 'description': 'View roles'},
    {'name': 'roles:create', 'resource': 'roles', 'action': 'create', 'description': 'Create roles'},
    {'name': 'roles:update', 'resource': 'roles', 'action': 'update', 'description': 'Update roles'},
    {'name': 'roles:delete', 'resource': 'roles', 'action': 'delete', 'description': 'Delete roles'},
    {'name': 'roles:assign', 'resource': 'roles', 'action': 'assign', 'description': 'Assign roles to users'},
    
    # Order management
    {'name': 'orders:read', 'resource': 'orders', 'action': 'read', 'description': 'View orders'},
    {'name': 'orders:create', 'resource': 'orders', 'action': 'create', 'description': 'Create orders'},
    {'name': 'orders:update', 'resource': 'orders', 'action': 'update', 'description': 'Update orders'},
    {'name': 'orders:delete', 'resource': 'orders', 'action': 'delete', 'description': 'Cancel/delete orders'},
    {'name': 'orders:refund', 'resource': 'orders', 'action': 'refund', 'description': 'Process refunds'},
    
    # Product management
    {'name': 'products:read', 'resource': 'products', 'action': 'read', 'description': 'View products'},
    {'name': 'products:create', 'resource': 'products', 'action': 'create', 'description': 'Create products'},
    {'name': 'products:update', 'resource': 'products', 'action': 'update', 'description': 'Update products'},
    {'name': 'products:delete', 'resource': 'products', 'action': 'delete', 'description': 'Delete products'},
    
    # Inventory management
    {'name': 'inventory:read', 'resource': 'inventory', 'action': 'read', 'description': 'View inventory'},
    {'name': 'inventory:update', 'resource': 'inventory', 'action': 'update', 'description': 'Update inventory'},
    
    # Reports & Analytics
    {'name': 'reports:read', 'resource': 'reports', 'action': 'read', 'description': 'View reports'},
    {'name': 'analytics:read', 'resource': 'analytics', 'action': 'read', 'description': 'View analytics'},
    
    # Settings
    {'name': 'settings:read', 'resource': 'settings', 'action': 'read', 'description': 'View settings'},
    {'name': 'settings:update', 'resource': 'settings', 'action': 'update', 'description': 'Update settings'},
]

# Role-Permission mappings
ROLE_PERMISSIONS = {
    'super_admin': ['*'],  # All permissions
    'admin': [
        'users:read', 'users:create', 'users:update',
        'roles:read', 'roles:assign',
        'orders:read', 'orders:update', 'orders:refund',
        'products:read', 'products:create', 'products:update', 'products:delete',
        'inventory:read', 'inventory:update',
        'reports:read', 'analytics:read',
        'settings:read', 'settings:update',
    ],
    'manager': [
        'users:read',
        'orders:read', 'orders:update', 'orders:refund',
        'products:read', 'products:update',
        'inventory:read', 'inventory:update',
        'reports:read', 'analytics:read',
    ],
    'staff': [
        'orders:read', 'orders:update',
        'products:read',
        'inventory:read',
    ],
    'customer': [
        'orders:read', 'orders:create',
        'products:read',
    ],
}
