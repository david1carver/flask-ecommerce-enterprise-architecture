"""
Flask App with MFA Integration
Complete example showing how to integrate MFA into your authentication flow
"""

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

from models import db, User
from mfa_service import mfa_service
from jwt_service import JWTService, jwt_required, mfa_required
from routes import mfa_bp


def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
    app.config['JWT_SECRET_KEY'] = 'your-jwt-secret-change-in-production'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # JWT settings
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 15  # 15 minutes
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 7  # 7 days
    app.config['JWT_MFA_TOKEN_EXPIRES'] = 5      # 5 minutes for MFA pending
    
    # Initialize extensions
    db.init_app(app)
    CORS(app)
    
    # Create JWT service and attach to app context
    jwt_service = JWTService(
        secret_key=app.config['JWT_SECRET_KEY'],
        access_token_expires=app.config['JWT_ACCESS_TOKEN_EXPIRES'],
        refresh_token_expires=app.config['JWT_REFRESH_TOKEN_EXPIRES'],
        mfa_token_expires=app.config['JWT_MFA_TOKEN_EXPIRES']
    )
    
    @app.before_request
    def before_request():
        g.jwt_service = jwt_service
    
    # Register MFA blueprint
    app.register_blueprint(mfa_bp)
    
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
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        user = User(
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'message': 'User registered successfully'}), 201
    
    
    @app.route('/api/auth/login', methods=['POST'])
    def login():
        """
        Login endpoint with MFA support
        
        Returns tokens with mfa_required flag if user has MFA enabled.
        Client must then call /api/auth/mfa/verify to complete login.
        """
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Generate tokens
        # If MFA enabled, tokens will have mfa_verified=False
        tokens = jwt_service.generate_token_pair(
            user_id=user.id,
            email=user.email,
            mfa_verified=False,
            mfa_required=user.mfa_enabled
        )
        
        response = {
            'message': 'Login successful',
            'user': {
                'id': user.id,
                'email': user.email,
                'mfa_enabled': user.mfa_enabled
            },
            **tokens
        }
        
        if user.mfa_enabled:
            response['message'] = 'MFA verification required'
            response['next_step'] = 'POST /api/auth/mfa/verify with your authenticator code'
        
        return jsonify(response)
    
    
    @app.route('/api/auth/refresh', methods=['POST'])
    def refresh_token():
        """Refresh access token using refresh token"""
        data = request.get_json()
        refresh_token = data.get('refresh_token', '')
        
        if not refresh_token:
            return jsonify({'error': 'Refresh token required'}), 400
        
        payload = jwt_service.decode_token(refresh_token)
        
        if not payload or payload.get('type') != 'refresh':
            return jsonify({'error': 'Invalid refresh token'}), 401
        
        user = User.query.get(payload['sub'])
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Generate new token pair
        # Note: MFA status resets on refresh - user must re-verify
        tokens = jwt_service.generate_token_pair(
            user_id=user.id,
            email=user.email,
            mfa_verified=False,
            mfa_required=user.mfa_enabled
        )
        
        return jsonify(tokens)
    
    
    # ==================== PROTECTED ROUTES ====================
    
    @app.route('/api/user/profile', methods=['GET'])
    @jwt_required
    def get_profile():
        """Get user profile - requires valid JWT only"""
        user = User.query.get(g.current_user_id)
        return jsonify({
            'id': user.id,
            'email': user.email,
            'mfa_enabled': user.mfa_enabled,
            'mfa_verified_this_session': g.mfa_verified
        })
    
    
    @app.route('/api/user/sensitive-data', methods=['GET'])
    @mfa_required
    def get_sensitive_data():
        """
        Get sensitive data - requires valid JWT AND completed MFA
        This demonstrates step-up authentication for sensitive operations
        """
        return jsonify({
            'message': 'This is sensitive data',
            'data': {
                'secret_info': 'Only visible after MFA verification'
            }
        })
    
    
    @app.route('/api/orders', methods=['POST'])
    @mfa_required
    def create_order():
        """Create order - requires MFA (example of protected transaction)"""
        data = request.get_json()
        return jsonify({
            'message': 'Order created successfully',
            'order_id': '12345',
            'mfa_verified': True
        })
    
    
    # ==================== HEALTH CHECK ====================
    
    @app.route('/health', methods=['GET'])
    def health():
        return jsonify({'status': 'healthy'})
    
    
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)
