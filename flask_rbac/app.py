"""
Flask App with RBAC Integration
Complete example showing how to integrate Role-Based Access Control
"""

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta

from models import db, User, Role
from rbac_service import rbac_service
from routes import rbac_bp
from decorators import (
    role_required, 
    permission_required, 
    admin_required, 
    super_admin_required,
    resource_access
)


def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rbac_app.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize extensions
    db.init_app(app)
    CORS(app)
    rbac_service.init_app(app)
    
    # Register RBAC blueprint
    app.register_blueprint(rbac_bp)
    
    # Create tables and initialize RBAC
    with app.app_context():
        db.create_all()
        rbac_service.init_default_roles_and_permissions()
    
    # ==================== JWT MIDDLEWARE ====================
    
    @app.before_request
    def load_user():
        """Load user from JWT token"""
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if token:
            try:
                payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                g.current_user_id = payload['sub']
                g.current_user_email = payload['email']
            except jwt.InvalidTokenError:
                pass
    
    # ==================== AUTH ROUTES ====================
    
    @app.route('/api/auth/register', methods=['POST'])
    def register():
        """Register a new user"""
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        user = User(
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        # Assign default 'customer' role
        customer_role = Role.query.filter_by(name='customer').first()
        if customer_role:
            user.roles.append(customer_role)
            db.session.commit()
        
        return jsonify({'message': 'User registered successfully'}), 201
    
    
    @app.route('/api/auth/login', methods=['POST'])
    def login():
        """Login and get JWT token"""
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'Account is disabled'}), 403
        
        # Generate token
        token = jwt.encode({
            'sub': user.id,
            'email': user.email,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'message': 'Login successful',
            'access_token': token,
            'user': {
                'id': user.id,
                'email': user.email,
                'roles': [role.name for role in user.roles],
                'permissions': list(user.get_permissions())
            }
        })
    
    
    @app.route('/api/auth/create-admin', methods=['POST'])
    def create_admin():
        """Create first admin user (only works if no admins exist)"""
        # Check if any admin exists
        admin_role = Role.query.filter_by(name='super_admin').first()
        if admin_role and admin_role.users:
            return jsonify({'error': 'Admin already exists'}), 400
        
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(
                email=email,
                password_hash=generate_password_hash(password)
            )
            db.session.add(user)
        
        # Assign super_admin role
        if admin_role and admin_role not in user.roles:
            user.roles.append(admin_role)
        
        db.session.commit()
        
        return jsonify({'message': 'Super admin created successfully'}), 201
    
    
    # ==================== PROTECTED ROUTE EXAMPLES ====================
    
    @app.route('/api/products', methods=['GET'])
    @permission_required('products:read')
    def list_products():
        """List products - requires products:read permission"""
        return jsonify({
            'products': [
                {'id': 1, 'name': 'Product A', 'price': 99.99},
                {'id': 2, 'name': 'Product B', 'price': 149.99}
            ]
        })
    
    
    @app.route('/api/products', methods=['POST'])
    @permission_required('products:create')
    def create_product():
        """Create product - requires products:create permission"""
        data = request.get_json()
        return jsonify({
            'message': 'Product created',
            'product': data
        }), 201
    
    
    @app.route('/api/products/<int:product_id>', methods=['DELETE'])
    @permission_required('products:delete')
    def delete_product(product_id):
        """Delete product - requires products:delete permission"""
        return jsonify({'message': f'Product {product_id} deleted'})
    
    
    @app.route('/api/orders', methods=['GET'])
    @resource_access('orders', 'read')
    def list_orders():
        """List orders - uses resource:action decorator"""
        return jsonify({
            'orders': [
                {'id': 1, 'status': 'pending', 'total': 199.99},
                {'id': 2, 'status': 'completed', 'total': 349.99}
            ]
        })
    
    
    @app.route('/api/orders/<int:order_id>/refund', methods=['POST'])
    @permission_required('orders:refund')
    def refund_order(order_id):
        """Refund order - requires orders:refund permission (manager+)"""
        return jsonify({'message': f'Order {order_id} refunded'})
    
    
    @app.route('/api/reports/sales', methods=['GET'])
    @role_required('manager', 'admin', 'super_admin')
    def sales_report():
        """Sales report - requires manager role or higher"""
        return jsonify({
            'report': 'Sales Report',
            'total_sales': 50000,
            'orders': 150
        })
    
    
    @app.route('/api/admin/users', methods=['GET'])
    @admin_required
    def list_users():
        """List all users - admin only"""
        users = User.query.all()
        return jsonify({
            'users': [{
                'id': u.id,
                'email': u.email,
                'roles': [r.name for r in u.roles],
                'is_active': u.is_active
            } for u in users]
        })
    
    
    @app.route('/api/admin/settings', methods=['POST'])
    @super_admin_required
    def update_settings():
        """Update system settings - super admin only"""
        data = request.get_json()
        return jsonify({
            'message': 'Settings updated',
            'settings': data
        })
    
    
    # ==================== HEALTH CHECK ====================
    
    @app.route('/health', methods=['GET'])
    def health():
        return jsonify({'status': 'healthy'})
    
    
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)
