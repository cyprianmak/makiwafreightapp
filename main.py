# main.py - FIXED VERSION
from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import uuid
import json
import os
from sqlalchemy import text
from sqlalchemy.orm import Session
import psycopg2
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates', static_folder='static')

# Configure database properly for Render PostgreSQL
database_url = os.environ.get('DATABASE_URL')
if database_url:
    # Fix old postgres:// URLs
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    logger.info(f"✅ Using PostgreSQL database")
else:
    # Fallback to SQLite for local development
    basedir = os.path.abspath(os.path.dirname(__file__))
    db_path = os.path.join(basedir, 'makiwafreight.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    logger.info(f"⚙️ Using SQLite at: {db_path}")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True
}

# Initialize db with error handling
db = SQLAlchemy()
db.init_app(app)

# Define database models (keep your existing models)
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    company = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    vehicle_info = db.Column(db.String(200))
    membership_number = db.Column(db.String(20), unique=True, nullable=True)
    token = db.Column(db.String(36))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Load(db.Model):
    __tablename__ = 'loads'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ref = db.Column(db.String(10), nullable=False)
    origin = db.Column(db.String(100), nullable=False)
    destination = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    cargo_type = db.Column(db.String(50), nullable=False)
    weight = db.Column(db.Float, nullable=False)
    notes = db.Column(db.Text)
    shipper_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationship to get shipper info
    shipper = db.relationship('User', foreign_keys=[shipper_id])
    
    def to_dict(self):
        return {
            "id": self.id,
            "ref": self.ref,
            "origin": self.origin,
            "destination": self.destination,
            "date": self.date,
            "cargo_type": self.cargo_type,
            "weight": self.weight,
            "notes": self.notes,
            "shipper_id": self.shipper_id,
            "shipper_name": self.shipper.name if self.shipper else "Unknown",
            "shipper_membership": self.shipper.membership_number if self.shipper else "Unknown",
            "expires_at": self.expires_at.isoformat(),
            "created_at": self.created_at.isoformat()
        }

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_membership = db.Column(db.String(20), nullable=False)
    recipient_membership = db.Column(db.String(20), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def to_dict(self):
        return {
            "id": self.id,
            "sender_membership": self.sender_membership,
            "recipient_membership": self.recipient_membership,
            "body": self.body,
            "created_at": self.created_at.isoformat()
        }

class AccessControl(db.Model):
    __tablename__ = 'access_control'
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Text)  # JSON string containing access control data

class UserAccessControl(db.Model):
    __tablename__ = 'user_access_control'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    pages = db.Column(db.Text)  # JSON string containing page access data
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    user = db.relationship('User', backref=db.backref('access_controls', lazy=True))

class Banner(db.Model):
    __tablename__ = 'banners'
    id = db.Column(db.Integer, primary_key=True)
    index = db.Column(db.String(200))
    dashboard = db.Column(db.String(200))

# DB helper: generate membership number MF000001 style
def generate_membership_number():
    """
    Generates a unique membership number in the format MF000001.
    It finds the highest existing number and increments it.
    """
    try:
        # Query for the highest numeric part of the membership number
        last_membership = db.session.query(User.membership_number).filter(
            User.membership_number.like('MF%')
        ).order_by(User.membership_number.desc()).first()
        
        if not last_membership:
            next_id = 1
        else:
            # Extract numeric part and increment
            try:
                # Remove 'MF' prefix and convert to int
                last_num = int(last_membership[0][2:])
                next_id = last_num + 1
            except (ValueError, IndexError):
                # Fallback if format is unexpected
                next_id = 1
        
        return f"MF{str(next_id).zfill(6)}"
    except Exception as e:
        logger.error(f"Error generating membership number: {e}")
        # If anything goes wrong (e.g., table doesn't exist yet), start from 1
        return f"MF000001"

# Helper functions
def check_auth(request):
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return None
    token = token.split(' ')[1]
    
    try:
        return User.query.filter_by(token=token).first()
    except Exception as e:
        logger.error(f"Auth error: {e}")
        return None

def get_default_access_control_data():
    return {
        'pages': {
            'post_load': {
                'allowed_roles': ['admin', 'shipper', 'transporter']
            },
            'market': {
                'allowed_roles': ['admin', 'shipper', 'transporter']
            }
        },
        'banners': {
            'index': '',
            'dashboard': ''
        },
        'post_loads_enabled': True,
        'user_access': {}
    }

def get_access_control():
    try:
        ac = AccessControl.query.first()
        if not ac:
            # Initialize with default structure
            default_data = get_default_access_control_data()
            ac = AccessControl(data=json.dumps(default_data))
            db.session.add(ac)
            db.session.commit()
            return default_data
        
        try:
            data = json.loads(ac.data)
        except:
            # If data is corrupted, reset to default
            default_data = get_default_access_control_data()
            ac.data = json.dumps(default_data)
            db.session.commit()
            return default_data
            
        default_data = get_default_access_control_data()
        updated = False
        
        # Ensure pages exists and has required structure
        if 'pages' not in data or not isinstance(data['pages'], dict):
            data['pages'] = default_data['pages']
            updated = True
        else:
            # Ensure post_load and market exist
            if 'post_load' not in data['pages'] or not isinstance(data['pages'].get('post_load'), dict):
                data['pages']['post_load'] = default_data['pages']['post_load']
                updated = True
            if 'market' not in data['pages'] or not isinstance(data['pages'].get('market'), dict):
                data['pages']['market'] = default_data['pages']['market']
                updated = True
        
        # Ensure banners exists and has required structure
        if 'banners' not in data or not isinstance(data['banners'], dict):
            data['banners'] = default_data['banners']
            updated = True
        else:
            for key in ['index', 'dashboard']:
                if key not in data['banners']:
                    data['banners'][key] = default_data['banners'][key]
                    updated = True
        
        # Ensure post_loads_enabled exists
        if 'post_loads_enabled' not in data:
            data['post_loads_enabled'] = default_data['post_loads_enabled']
            updated = True
        
        # Ensure user_access exists
        if 'user_access' not in data:
            data['user_access'] = default_data['user_access']
            updated = True
        
        if updated:
            ac.data = json.dumps(data)
            db.session.commit()
        return data
    except Exception as e:
        logger.error(f"Error in get_access_control: {e}")
        return get_default_access_control_data()

def update_access_control(data):
    try:
        ac = AccessControl.query.first()
        if not ac:
            ac = AccessControl()
            db.session.add(ac)
        
        ac.data = json.dumps(data)
        db.session.commit()
        return data
    except Exception as e:
        logger.error(f"Error updating access control: {e}")
        db.session.rollback()
        return data

def get_banners():
    try:
        ac_data = get_access_control()
        return {
            'index': ac_data.get('banners', {}).get('index', ''),
            'dashboard': ac_data.get('banners', {}).get('dashboard', '')
        }
    except Exception as e:
        logger.error(f"Error getting banners: {e}")
        return {'index': '', 'dashboard': ''}

def update_banners(banners):
    try:
        ac_data = get_access_control()
        if 'banners' not in ac_data:
            ac_data['banners'] = {}
        
        ac_data['banners']['index'] = banners.get('index', '')
        ac_data['banners']['dashboard'] = banners.get('dashboard', '')
        
        return update_access_control(ac_data)
    except Exception as e:
        logger.error(f"Error updating banners: {e}")
        return banners

# Initialize database
def initialize_data():
    with app.app_context():
        try:
            logger.info("Initializing database...")
            
            # Create all tables
            db.create_all()
            logger.info("✅ Database tables created")
            
            # Check if admin user exists
            admin_email = 'cyprianmak@gmail.com'
            admin = User.query.filter_by(email=admin_email).first()
            
            if not admin:
                logger.info("Creating admin user...")
                admin = User(
                    name="Admin",
                    email=admin_email,
                    role="admin",
                    membership_number="MF000001"
                )
                admin.set_password("Muchandida@1")
                db.session.add(admin)
                db.session.commit()
                logger.info("✅ Admin user created")
            else:
                logger.info("✅ Admin user already exists")
                
            logger.info("✅ Database initialization complete")
            
        except Exception as e:
            logger.error(f"❌ Database initialization error: {e}")
            import traceback
            logger.error(f"❌ Detailed traceback: {traceback.format_exc()}")
            db.session.rollback()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api')
def api_info():
    return jsonify({
        "success": True,
        "message": "API is running",
        "data": {
            "endpoints": {
                "auth": "/api/auth/login",
                "register": "/api/auth/register",
                "health": "/api/health",
                "loads": "/api/loads",
                "messages": "/api/messages",
                "users": "/api/users",
                "users_me": "/api/users/me",
                "admin_banners": "/api/admin/banners",
                "admin_access_control": "/api/admin/access-control",
                "admin_user_access": "/api/admin/users/<user_id>/access",
                "debug_db": "/api/debug/db"
            },
            "status": "running",
            "version": "1.0.0"
        }
    })

@app.route('/api/health')
def health():
    try:
        # Test database connection
        db.session.execute(text("SELECT 1"))
        return jsonify({
            "success": True,
            "message": "Service is healthy",
            "data": {
                "status": "healthy",
                "database": "connected"
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Service has issues",
            "error": str(e)
        }), 500

# Auth endpoints (keep your existing endpoints, they look good)
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "message": "Registration failed",
                "error": "No JSON data provided"
            }), 400
            
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'shipper')  # Default to shipper
        
        # Validate required fields
        if not name or not email or not password:
            return jsonify({
                "success": False,
                "message": "Registration failed",
                "error": "name, email, and password are required"
            }), 400
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            return jsonify({
                "success": False,
                "message": "Registration failed",
                "error": "Email already registered"
            }), 400
        
        # Generate unique membership number
        membership_number = generate_membership_number()
        
        # Create new user
        new_user = User(
            name=name,
            email=email,
            role=role,
            membership_number=membership_number,
            company=data.get('company', ''),
            phone=data.get('phone', ''),
            address=data.get('address', ''),
            vehicle_info=data.get('vehicle_info', '')
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Registration successful",
            "data": {
                "user": {
                    "id": new_user.id,
                    "name": new_user.name,
                    "email": new_user.email,
                    "role": new_user.role,
                    "membership_number": new_user.membership_number
                }
            },
            "membership_number": membership_number
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error: {e}")
        return jsonify({
            "success": False,
            "message": "Registration failed",
            "error": str(e)
        }), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "message": "Login failed",
                "error": "No JSON data provided"
            }), 400
            
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({
                "success": False,
                "message": "Login failed",
                "error": "Email and password required"
            }), 400
        
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            token = str(uuid.uuid4())
            user.token = token
            db.session.commit()
            return jsonify({
                "success": True,
                "message": "Login successful",
                "data": {
                    "token": token,
                    "user": {
                        "id": user.id,
                        "name": user.name,
                        "email": user.email,
                        "role": user.role,
                        "membership_number": user.membership_number
                    }
                }
            })
        else:
            return jsonify({
                "success": False,
                "message": "Login failed",
                "error": "Invalid credentials"
            }), 401
    except Exception as e:
        db.session.rollback()
        logger.error(f"Login error: {e}")
        return jsonify({
            "success": False,
            "message": "Login failed",
            "error": str(e)
        }), 500

# Keep all your other routes as they are...
# [Include all your existing routes here - they look correct]

# Initialize the application
with app.app_context():
    initialize_data()

# Application entry point
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"🚀 Starting MakiwaFreight server on port {port}")
    
    # Use Gunicorn in production, development server locally
    if os.environ.get('RENDER'):
        # Production
        app.run(host='0.0.0.0', port=port)
    else:
        # Development
        app.run(debug=True, host='0.0.0.0', port=port)
