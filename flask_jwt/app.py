"""
Flask App with JWT Integration
Complete example showing JWT authentication flow
"""

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash

from models import db, User
from jwt_service import create_jwt_service
from routes import jwt_bp
from decorators import jwt_required, jwt_optional, fresh_jwt_required


def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jwt_app.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # JWT Configuration
    app.config['JWT_SECRET_KEY'] = 'your-jwt-secret-change-in-production'
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 15       # 15 minutes
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 7       # 7 days
    app.config['JWT_ALGORITHM'] = 'HS256'
    app.config['JWT_ISSUER'] = 'flask-ecommerce'
    app.config['JWT_AUDIENCE'] = 'flask-ecommerce-api'
    app.config['JWT_TOKEN_ROTATION'] = True           # New refresh token on each use
    app.config['JWT_REUSE_DETECTION'] = True          # Detect token theft
    app.config['JWT_MAX_SESSIONS'] = 10               # Max concurrent sessions
    
    # Initialize extensions
    db.init_app(app)
    CORS(app)
    
    # Create JWT service
    jwt_service = create_jwt_service(app)
    
    @app.before_request
    def before_request():
        g.jwt_service = jwt_service
    
    # Register blueprints
    app.register_blueprint(jwt_bp)
    
    # Create tables
    with app.app_context():
        db.create_all()
    
    # ==================== AUTH ROUTES ====================
    
    @app.route('/api/auth/register', methods=['POST'])
    def register():
        """Register a new user"""
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        user = User(
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'message': 'User registered successfully',
            'user': {
                'id': user.id,
                'email': user.email
            }
        }), 201
    
    
    # ==================== PROTECTED ROUTES ====================
    
    @app.route('/api/profile', methods=['GET'])
    @jwt_required
    def get_profile():
        """Get user profile - requires valid JWT"""
        user = User.query.get(g.current_user_id)
        
        return jsonify({
            'id': user.id,
            'email': user.email,
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'created_at': user.created_at.isoformat()
        })
    
    
    @app.route('/api/profile', methods=['PUT'])
    @jwt_required
    def update_profile():
        """Update user profile"""
        user = User.query.get(g.current_user_id)
        data = request.get_json()
        
        # Update allowed fields
        # (Add more fields as needed)
        
        db.session.commit()
        
        return jsonify({
            'message': 'Profile updated',
            'user': {
                'id': user.id,
                'email': user.email
            }
        })
    
    
    @app.route('/api/password', methods=['PUT'])
    @fresh_jwt_required
    def change_password():
        """
        Change password - requires fresh JWT
        User must have logged in within last 10 minutes
        """
        user = User.query.get(g.current_user_id)
        data = request.get_json()
        
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Current and new password required'}), 400
        
        from werkzeug.security import check_password_hash
        if not check_password_hash(user.password_hash, current_password):
            return jsonify({'error': 'Current password is incorrect'}), 400
        
        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        user.password_hash = generate_password_hash(new_password)
        
        # Invalidate all tokens (force re-login)
        jwt_service.revoke_all_user_tokens(user.id, reason='password_changed')
        
        db.session.commit()
        
        return jsonify({
            'message': 'Password changed. Please log in again.'
        })
    
    
    @app.route('/api/products', methods=['GET'])
    @jwt_optional
    def list_products():
        """
        List products - JWT optional
        Returns personalized results if authenticated
        """
        products = [
            {'id': 1, 'name': 'Product A', 'price': 99.99},
            {'id': 2, 'name': 'Product B', 'price': 149.99},
            {'id': 3, 'name': 'Product C', 'price': 199.99},
        ]
        
        return jsonify({
            'products': products,
            'authenticated': g.current_user_id is not None,
            'user_id': g.current_user_id
        })
    
    
    @app.route('/api/orders', methods=['GET'])
    @jwt_required
    def list_orders():
        """List user's orders - requires JWT"""
        # In real app, fetch from database
        orders = [
            {'id': 1, 'status': 'completed', 'total': 199.99},
            {'id': 2, 'status': 'pending', 'total': 349.99},
        ]
        
        return jsonify({
            'orders': orders,
            'user_id': g.current_user_id
        })
    
    
    @app.route('/api/orders', methods=['POST'])
    @jwt_required
    def create_order():
        """Create order - requires JWT"""
        data = request.get_json()
        
        return jsonify({
            'message': 'Order created',
            'order': {
                'id': 12345,
                'status': 'pending',
                'items': data.get('items', [])
            }
        }), 201
    
    
    # ==================== HEALTH CHECK ====================
    
    @app.route('/health', methods=['GET'])
    def health():
        return jsonify({'status': 'healthy'})
    
    
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)
