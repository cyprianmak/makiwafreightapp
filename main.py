from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import uuid
import json
import os
from sqlalchemy import text
from sqlalchemy.orm import Session
from functools import wraps
import time
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configure database properly for Render PostgreSQL
if os.environ.get('RENDER'):
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        # Fix old postgres:// URLs
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        logger.info(f"✅ Using PostgreSQL database at: {database_url}")
    else:
        # Fallback to persistent SQLite if DATABASE_URL not found
        persistent_dir = '/opt/render/project/.render/data'
        os.makedirs(persistent_dir, exist_ok=True)
        db_path = os.path.join(persistent_dir, 'makiwafreight.db')
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
        logger.info(f"⚠️ DATABASE_URL not found, using SQLite fallback at: {db_path}")
else:
    # Local development: check for DATABASE_URL first, else fallback to SQLite
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        logger.info(f"✅ Using local PostgreSQL database at: {database_url}")
    else:
        basedir = os.path.abspath(os.path.dirname(__file__))
        db_dir = os.path.join(basedir, 'data')
        os.makedirs(db_dir, exist_ok=True)
        db_path = os.path.join(db_dir, 'makiwafreight.db')
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
        logger.info(f"⚙️ Using local SQLite at: {db_path}")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True,
    'pool_size': 10,
    'max_overflow': 20,
    'pool_timeout': 30
}
db = SQLAlchemy(app)

# Define database models
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
    shipper_email = db.Column(db.String(100), nullable=False)
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
            "shipper_email": self.shipper_email,
            "shipper_name": self.shipper.name if self.shipper else "Unknown",
            "shipper_membership": self.shipper.membership_number if self.shipper else "Unknown",
            "posted_by": self.shipper.membership_number if self.shipper else "Unknown",
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

# Helper function to ensure timezone-aware datetime
def get_current_time():
    return datetime.now(timezone.utc)

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            user = check_auth(request)
            if not user:
                return jsonify({
                    "success": False,
                    "message": "Authentication required",
                    "error": "Please login to continue"
                }), 401
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return jsonify({
                "success": False,
                "message": "Authentication failed",
                "error": "Please login again"
            }), 401
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            user = check_auth(request)
            if not user:
                return jsonify({
                    "success": False,
                    "message": "Authentication required",
                    "error": "Please login to continue"
                }), 401
            
            if user.role != 'admin':
                return jsonify({
                    "success": False,
                    "message": "Access denied",
                    "error": "Admin access required"
                }), 403
            
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Admin authentication error: {e}")
            return jsonify({
                "success": False,
                "message": "Authentication failed",
                "error": "Please login again"
            }), 401
    return decorated_function

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
            },
            'dashboard': {
                'allowed_roles': ['admin', 'shipper', 'transporter']
            },
            'profile': {
                'allowed_roles': ['admin', 'shipper', 'transporter']
            },
            'messages': {
                'allowed_roles': ['admin', 'shipper', 'transporter']
            },
            'admin': {
                'allowed_roles': ['admin']
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
            # Ensure all required pages exist
            for page in ['post_load', 'market', 'dashboard', 'profile', 'messages', 'admin']:
                if page not in data['pages'] or not isinstance(data['pages'].get(page), dict):
                    data['pages'][page] = default_data['pages'][page]
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

def can_access_page(user, page_name):
    """Check if user can access a specific page"""
    if user.role == 'admin':
        return True  # Admin has access to everything
    ac_data = get_access_control()
    allowed_roles = ac_data.get('pages', {}).get(page_name, {}).get('allowed_roles', [])
    return user.role in allowed_roles

# Database connection health check
def check_db_connection():
    """Check if database connection is healthy"""
    try:
        db.session.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return False

# Initialize database - FIXED VERSION with better error handling
def initialize_data():
    with app.app_context():
        max_retries = 3
        for attempt in range(max_retries):
            try:
                logger.info(f"Initializing database... Attempt {attempt + 1}")
                
                # Test database connection first
                if not check_db_connection():
                    logger.warning("Database connection failed, retrying...")
                    time.sleep(2)
                    continue
                
                # Create all tables if they don't exist (instead of dropping)
                db.create_all()
                logger.info("✅ Database tables ensured")
                
                # Check if admin user exists and create if not
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
                    db.session.commit()  # Commit to get the ID
                    logger.info("✅ Admin user created")
                else:
                    # Ensure admin password is correct (in case it was changed)
                    if not admin.check_password("Muchandida@1"):
                        admin.set_password("Muchandida@1")
                        db.session.commit()
                        logger.info("✅ Admin password reset")
                    logger.info("✅ Admin user already exists")
                
                # Check if access control data exists
                ac = AccessControl.query.first()
                if not ac:
                    logger.info("Creating access control data...")
                    default_data = get_default_access_control_data()
                    ac = AccessControl(data=json.dumps(default_data))
                    db.session.add(ac)
                    db.session.commit()
                    logger.info("✅ Access control data created")
                else:
                    logger.info("✅ Access control data already exists")
                
                # Create user access control for admin AFTER user exists
                if admin:
                    user_access = UserAccessControl.query.filter_by(user_id=admin.id).first()
                    if not user_access:
                        logger.info("Creating admin access control...")
                        user_access = UserAccessControl(
                            user_id=admin.id,
                            pages=json.dumps({
                                "market": {"enabled": True},
                                "shipper-post": {"enabled": True},
                                "admin": {"enabled": True},
                                "dashboard": {"enabled": True},
                                "profile": {"enabled": True},
                                "messages": {"enabled": True}
                            })
                        )
                        db.session.add(user_access)
                        db.session.commit()
                        logger.info("✅ Admin access control created")
                    else:
                        logger.info("✅ Admin access control already exists")
                    
                logger.info("✅ Database initialization complete")
                break  # Success, break out of retry loop
                
            except Exception as e:
                logger.error(f"❌ Error during database initialization (attempt {attempt + 1}): {e}")
                db.session.rollback()
                if attempt == max_retries - 1:
                    logger.error("❌ All retries failed for database initialization")
                else:
                    time.sleep(2)  # Wait before retry

# Error handlers
@app.errorhandler(401)
def unauthorized(error):
    return jsonify({
        "success": False,
        "message": "Authentication required",
        "error": "Please log in with valid credentials"
    }), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({
        "success": False,
        "message": "Insufficient permissions",
        "error": "You don't have permission to access this resource"
    }), 403

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "message": "Resource not found",
        "error": "The requested resource was not found"
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "success": False,
        "message": "Internal server error",
        "error": "Something went wrong on our end"
    }), 500

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
                "user_loads": "/api/users/me/loads",
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
        db_healthy = check_db_connection()
        status = "healthy" if db_healthy else "degraded"
        
        return jsonify({
            "success": True,
            "message": "Service status",
            "data": {
                "status": status,
                "database": "connected" if db_healthy else "disconnected",
                "timestamp": get_current_time().isoformat()
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Service has issues",
            "error": str(e)
        }), 500

# Auth endpoints
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
        
        # Create default access control for new user
        user_access = UserAccessControl(
            user_id=new_user.id,
            pages=json.dumps({
                "market": {"enabled": True},
                "shipper-post": {"enabled": True},
                "dashboard": {"enabled": True},
                "profile": {"enabled": True},
                "messages": {"enabled": True}
            })
        )
        db.session.add(user_access)
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
                    "membership_number": new_user.membership_number,
                    "created_at": new_user.created_at.isoformat()
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
                        "membership_number": user.membership_number,
                        "created_at": user.created_at.isoformat()
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

# Get current user endpoint
@app.route('/api/users/me', methods=['GET'])
@login_required
def get_current_user():
    try:
        user = check_auth(request)
        return jsonify({
            "success": True,
            "message": "User data retrieved",
            "data": {
                "user": {
                    "id": user.id,
                    "name": user.name,
                    "email": user.email,
                    "role": user.role,
                    "company": user.company,
                    "phone": user.phone,
                    "address": user.address,
                    "vehicle_info": user.vehicle_info,
                    "membership_number": user.membership_number,
                    "membership_date": user.created_at.strftime("%Y-%m-%d"),
                    "join_date": user.created_at.strftime("%B %d, %Y"),
                    "created_at": user.created_at.isoformat()
                }
            }
        })
    except Exception as e:
        logger.error(f"Get current user error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to retrieve user data",
            "error": str(e)
        }), 500

# Update current user endpoint
@app.route('/api/users/me', methods=['PUT'])
@login_required
def update_current_user():
    try:
        user = check_auth(request)
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "message": "Update failed",
                "error": "No JSON data provided"
            }), 400
        
        # Update fields if provided
        editable_fields = ['name', 'company', 'phone', 'address', 'vehicle_info']
        for field in editable_fields:
            if field in data:
                setattr(user, field, data[field])
        
        # Handle password separately
        if 'password' in data and data['password']:
            user.set_password(data['password'])
        
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Profile updated successfully",
            "data": {
                "user": {
                    "id": user.id,
                    "name": user.name,
                    "email": user.email,
                    "role": user.role,
                    "company": user.company,
                    "phone": user.phone,
                    "address": user.address,
                    "vehicle_info": user.vehicle_info,
                    "membership_number": user.membership_number,
                    "membership_date": user.created_at.strftime("%Y-%m-%d"),
                    "created_at": user.created_at.isoformat()
                }
            }
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update user error: {e}")
        return jsonify({
            "success": False,
            "message": "Profile update failed",
            "error": str(e)
        }), 500

# Get user's posted loads - FIXED with timezone handling
@app.route('/api/users/me/loads', methods=['GET'])
@login_required
def get_my_loads():
    try:
        user = check_auth(request)
        # Get loads posted by current user
        loads = Load.query.filter_by(shipper_id=user.id).order_by(Load.created_at.desc()).all()
        
        result = []
        current_time = get_current_time()
        for load in loads:
            # Ensure both datetimes are timezone-aware for comparison
            expires_at = load.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            
            days_remaining = 0
            status = "expired"
            if expires_at >= current_time:
                days_remaining = (expires_at - current_time).days
                status = "active"
            
            result.append({
                "id": load.id,
                "ref": load.ref,
                "origin": load.origin,
                "destination": load.destination,
                "date": load.date,
                "cargo_type": load.cargo_type,
                "weight": load.weight,
                "notes": load.notes,
                "expires_at": expires_at.isoformat(),
                "created_at": load.created_at.isoformat(),
                "status": status,
                "days_remaining": days_remaining
            })
        
        return jsonify({
            "success": True,
            "message": "Your loads retrieved",
            "data": {"loads": result}
        })
    except Exception as e:
        logger.error(f"Get my loads error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to retrieve your loads",
            "error": "Database connection issue"
        }), 500

# Load endpoints - FIXED with timezone handling and access control
@app.route('/api/loads', methods=['GET'])
def get_loads():
    try:
        # Check if user is logged in and has market access
        user = check_auth(request)
        if user and user.role != 'admin':
            user_access = UserAccessControl.query.filter_by(user_id=user.id).first()
            if user_access:
                try:
                    pages_data = json.loads(user_access.pages) if user_access.pages else {}
                    if 'market' in pages_data and not pages_data['market'].get('enabled', True):
                        return jsonify({
                            "success": False,
                            "message": "Access denied",
                            "error": "You do not have permission to view the market"
                        }), 403
                except:
                    # If there's an error parsing, allow by default
                    pass
        
        # Get all active loads (public access)
        current_time = get_current_time()
        # Ensure we're comparing timezone-aware datetimes
        loads = Load.query.filter(Load.expires_at >= current_time).order_by(Load.created_at.desc()).all()
        
        result = []
        for load in loads:
            # Ensure both datetimes are timezone-aware for comparison
            expires_at = load.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            
            days_remaining = (expires_at - current_time).days
            
            result.append({
                "id": load.id,
                "ref": load.ref,
                "origin": load.origin,
                "destination": load.destination,
                "date": load.date,
                "cargo_type": load.cargo_type,
                "weight": load.weight,
                "notes": load.notes,
                "shipper_name": load.shipper.name if load.shipper else "Unknown",
                "shipper_membership": load.shipper.membership_number if load.shipper else "Unknown",
                "posted_by": load.shipper.membership_number if load.shipper else "Unknown",
                "expires_at": expires_at.isoformat(),
                "created_at": load.created_at.isoformat(),
                "days_remaining": days_remaining
            })
        return jsonify({
            "success": True,
            "message": "Loads retrieved",
            "data": {"loads": result}
        })
    except Exception as e:
        logger.error(f"Get loads error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to retrieve loads",
            "error": str(e)
        }), 500

@app.route('/api/loads', methods=['POST'])
@login_required
def create_load():
    try:
        user = check_auth(request)
        
        # Check if user has permission to post loads
        if user.role != 'admin':
            user_access = UserAccessControl.query.filter_by(user_id=user.id).first()
            if user_access:
                try:
                    pages_data = json.loads(user_access.pages) if user_access.pages else {}
                    if 'shipper-post' in pages_data and not pages_data['shipper-post'].get('enabled', True):
                        return jsonify({
                            "success": False,
                            "message": "Access denied",
                            "error": "You do not have permission to post loads"
                        }), 403
                except:
                    # If there's an error parsing, allow by default
                    pass
        
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "message": "Load creation failed",
                "error": "No JSON data provided"
            }), 400
        
        required_fields = ['origin', 'destination', 'date', 'cargo_type', 'weight']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    "success": False,
                    "message": "Load creation failed",
                    "error": f"Missing field: {field}"
                }), 400
        
        # Set expiration date (7 days from creation) - ensure timezone-aware
        expires_at = get_current_time() + timedelta(days=7)
        
        # Generate reference
        ref = 'LD' + str(int(get_current_time().timestamp()))[-6:]
        
        # Auto-populate shipper information from logged-in user
        new_load = Load(
            ref=ref,
            origin=data['origin'],
            destination=data['destination'],
            date=data['date'],
            cargo_type=data['cargo_type'],
            weight=float(data['weight']),
            notes=data.get('notes', ''),
            shipper_id=user.id,  # Auto-populated
            shipper_email=user.email,  # Auto-populated
            expires_at=expires_at
        )
        
        db.session.add(new_load)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Load created successfully",
            "data": {
                "load": {
                    "id": new_load.id,
                    "ref": new_load.ref,
                    "origin": new_load.origin,
                    "destination": new_load.destination,
                    "expires_at": new_load.expires_at.isoformat()
                }
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create load error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to create load",
            "error": str(e)
        }), 500

# Update load endpoint
@app.route('/api/loads/<load_id>', methods=['PUT'])
@login_required
def update_load_endpoint(load_id):
    try:
        user = check_auth(request)
        load = db.session.get(Load, load_id)
        if not load:
            return jsonify({
                "success": False,
                "message": "Load not found",
                "error": "Load does not exist"
            }), 404
        
        # Only shipper who posted load can update it
        if load.shipper_id != user.id:
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "You can only update your own loads"
            }), 403
        
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "message": "Update failed",
                "error": "No JSON data provided"
            }), 400
        
        # Update fields if provided
        if 'origin' in data:
            load.origin = data['origin']
        if 'destination' in data:
            load.destination = data['destination']
        if 'date' in data:
            load.date = data['date']
        if 'cargo_type' in data:
            load.cargo_type = data['cargo_type']
        if 'weight' in data:
            load.weight = float(data['weight'])
        if 'notes' in data:
            load.notes = data['notes']
        
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Load updated successfully",
            "data": {
                "load": {
                    "id": load.id,
                    "ref": load.ref,
                    "origin": load.origin,
                    "destination": load.destination,
                    "expires_at": load.expires_at.isoformat()
                }
            }
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update load error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to update load",
            "error": str(e)
        }), 500

# Delete load endpoint
@app.route('/api/loads/<load_id>', methods=['DELETE'])
@login_required
def delete_load_endpoint(load_id):
    try:
        user = check_auth(request)
        load = db.session.get(Load, load_id)
        if not load:
            return jsonify({
                "success": False,
                "message": "Load not found",
                "error": "Load does not exist"
            }), 404
        
        # Only shipper who posted load can delete it
        if load.shipper_id != user.id:
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "You can only delete your own loads"
            }), 403
        
        db.session.delete(load)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Load deleted successfully",
            "data": {"load_id": load_id}
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete load error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to delete load",
            "error": str(e)
        }), 500

# Message endpoints - FIXED VERSION
@app.route('/api/messages', methods=['GET'])
@login_required
def get_messages():
    try:
        user = check_auth(request)
        # Get user's messages using membership number - FIXED: proper filtering
        user_membership = user.membership_number
        
        if not user_membership:
            return jsonify({
                "success": False,
                "message": "No membership number found",
                "error": "User doesn't have a valid membership number"
            }), 400
        
        # Get messages where user is sender OR recipient
        messages = Message.query.filter(
            (Message.sender_membership == user_membership) | 
            (Message.recipient_membership == user_membership)
        ).order_by(Message.created_at.desc()).all()
        
        result = []
        for msg in messages:
            result.append({
                "id": msg.id,
                "sender_membership": msg.sender_membership,
                "recipient_membership": msg.recipient_membership,
                "body": msg.body,
                "created_at": msg.created_at.isoformat(),
                "direction": "sent" if msg.sender_membership == user_membership else "received"
            })
        return jsonify({
            "success": True,
            "message": "Messages retrieved",
            "data": {"messages": result}
        })
    except Exception as e:
        logger.error(f"Get messages error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to retrieve messages",
            "error": str(e)
        }), 500

@app.route('/api/messages', methods=['POST'])
@login_required
def send_message():
    try:
        user = check_auth(request)
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "message": "Message not sent",
                "error": "No JSON data provided"
            }), 400
            
        recipient_membership = data.get('recipient_membership')
        body = data.get('body')
        
        if not recipient_membership or not body:
            return jsonify({
                "success": False,
                "message": "Message not sent",
                "error": "Recipient membership number and message body required"
            }), 400
        
        # Verify recipient exists (check by membership number)
        recipient = User.query.filter_by(membership_number=recipient_membership).first()
        if not recipient and recipient_membership != 'Admin':
            return jsonify({
                "success": False,
                "message": "Message not sent",
                "error": "Recipient not found"
            }), 404
        
        # Use current user's membership number
        sender_membership = user.membership_number
        if not sender_membership:
            return jsonify({
                "success": False,
                "message": "Message not sent",
                "error": "You don't have a valid membership number"
            }), 400
        
        new_message = Message(
            sender_membership=sender_membership,
            recipient_membership=recipient_membership,
            body=body
        )
        
        db.session.add(new_message)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Message sent successfully",
            "data": {"message_id": new_message.id}
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Send message error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to send message",
            "error": str(e)
        }), 500

# Banner endpoints
@app.route('/api/banners/active')
def get_active_banners():
    """Get banners for current page context"""
    try:
        referrer = request.headers.get('Referer', '')
        current_path = request.args.get('page', '')
        
        banners = get_banners()
        
        # Determine which banner to show based on current page
        if current_path == 'index' or current_path == '' or referrer.endswith('/'):
            return jsonify({
                "success": True,
                "data": {"banner": banners.get('index', '')}
            })
        elif current_path == 'dashboard' or 'dashboard' in referrer:
            return jsonify({
                "success": True,
                "data": {"banner": banners.get('dashboard', '')}
            })
        
        # Default: no banner for other pages
        return jsonify({
            "success": True,
            "data": {"banner": ""}
        })
    except Exception as e:
        logger.error(f"Get banners error: {e}")
        return jsonify({
            "success": True,
            "data": {"banner": ""}
        })

# Admin endpoints
@app.route('/api/admin/banners', methods=['GET'])
@admin_required
def get_admin_banners():
    try:
        return jsonify({
            "success": True,
            "message": "Banners retrieved",
            "data": get_banners()
        })
    except Exception as e:
        logger.error(f"Get admin banners error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to retrieve banners",
            "error": str(e)
        }), 500

@app.route('/api/admin/banners', methods=['POST'])
@admin_required
def update_admin_banners():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "message": "Update failed",
                "error": "No JSON data provided"
            }), 400
        
        updated_banners = update_banners(data)
        return jsonify({
            "success": True,
            "message": "Banners updated successfully",
            "data": updated_banners
        })
    except Exception as e:
        logger.error(f"Update admin banners error: {e}")
        return jsonify({
            "success": False,
            "message": "Banner update failed",
            "error": str(e)
        }), 500

# Admin access control endpoints - FIXED VERSION
@app.route('/api/admin/access-control', methods=['GET'])
@admin_required
def get_admin_access_control():
    try:
        ac_data = get_access_control()
        
        # Ensure proper structure for frontend
        if 'pages' not in ac_data:
            ac_data['pages'] = get_default_access_control_data()['pages']
        
        return jsonify({
            "success": True,
            "message": "Access control data retrieved",
            "data": ac_data
        })
    except Exception as e:
        logger.error(f"Get access control error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to retrieve access control data",
            "error": str(e)
        }), 500

@app.route('/api/admin/access-control', methods=['PUT'])
@admin_required
def update_admin_access_control():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "message": "Update failed",
                "error": "No JSON data provided"
            }), 400
        
        # Ensure proper structure
        if 'pages' not in data:
            data['pages'] = get_default_access_control_data()['pages']
        
        updated_data = update_access_control(data)
        
        return jsonify({
            "success": True,
            "message": "Access control updated successfully",
            "data": updated_data
        })
    except Exception as e:
        logger.error(f"Update access control error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to update access control",
            "error": str(e)
        }), 500

# User-specific access control endpoints - FIXED VERSION with independent page toggles
@app.route('/api/admin/users/<string:user_id>/access', methods=['GET'])
@admin_required
def get_user_access(user_id):
    try:
        # First verify the user exists
        target_user = User.query.filter_by(id=user_id).first()
        if not target_user:
            return jsonify({
                "success": False,
                "message": "User not found",
                "error": "User does not exist"
            }), 404
        
        # Get user access control settings
        user_access = UserAccessControl.query.filter_by(user_id=user_id).first()
        
        # Define ALL available pages with their default states
        default_pages = {
            'market': {'enabled': True},
            'shipper-post': {'enabled': True},  # This controls "Post Load" access
            'dashboard': {'enabled': True},
            'profile': {'enabled': True},
            'messages': {'enabled': True}
        }
        
        if not user_access:
            return jsonify({
                "success": True,
                "message": "User access retrieved",
                "data": {
                    "user_id": user_id,
                    "user_name": target_user.name,
                    "user_email": target_user.email,
                    "user_role": target_user.role,
                    "pages": default_pages
                }
            })
        
        # Parse pages JSON and ensure all required pages exist
        try:
            pages_data = json.loads(user_access.pages) if user_access.pages else {}
            # Merge with defaults to ensure all pages are present
            for page, settings in default_pages.items():
                if page not in pages_data:
                    pages_data[page] = settings
        except:
            pages_data = default_pages
        
        return jsonify({
            "success": True,
            "message": "User access retrieved",
            "data": {
                "user_id": user_id,
                "user_name": target_user.name,
                "user_email": target_user.email,
                "user_role": target_user.role,
                "pages": pages_data
            }
        })
    except Exception as e:
        logger.error(f"Get user access error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to retrieve user access",
            "error": str(e)
        }), 500

@app.route('/api/admin/users/<string:user_id>/access', methods=['PUT'])
@admin_required
def update_user_access(user_id):
    try:
        data = request.get_json()
        if not data or 'pages' not in data:
            return jsonify({
                "success": False,
                "message": "Pages data is required",
                "error": "Invalid request format"
            }), 400
        
        # First verify the user exists
        target_user = User.query.filter_by(id=user_id).first()
        if not target_user:
            return jsonify({
                "success": False,
                "message": "User not found",
                "error": "User does not exist"
            }), 404
        
        # Validate the pages data structure
        if not isinstance(data['pages'], dict):
            return jsonify({
                "success": False,
                "message": "Invalid pages format",
                "error": "Pages must be an object"
            }), 400
        
        # Ensure all required pages are present with proper structure
        required_pages = ['market', 'shipper-post', 'dashboard', 'profile', 'messages']
        for page in required_pages:
            if page not in data['pages']:
                data['pages'][page] = {'enabled': True}
            elif not isinstance(data['pages'][page], dict) or 'enabled' not in data['pages'][page]:
                data['pages'][page] = {'enabled': True}
        
        # Get or create user access control
        user_access = UserAccessControl.query.filter_by(user_id=user_id).first()
        if not user_access:
            user_access = UserAccessControl(
                user_id=user_id,
                pages=json.dumps(data['pages'])
            )
            db.session.add(user_access)
        else:
            user_access.pages = json.dumps(data['pages'])
        
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "User access updated successfully",
            "data": {
                "user_id": user_id,
                "user_name": target_user.name,
                "user_email": target_user.email,
                "pages": data['pages']
            }
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update user access error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to update user access",
            "error": str(e)
        }), 500

# Add this new endpoint to check if a user can access specific features
@app.route('/api/users/me/access', methods=['GET'])
@login_required
def get_my_access():
    """Get current user's access permissions"""
    try:
        user = check_auth(request)
        
        # Get user access control settings
        user_access = UserAccessControl.query.filter_by(user_id=user.id).first()
        
        # Default access for all pages
        default_pages = {
            'market': {'enabled': True},
            'shipper-post': {'enabled': True},
            'dashboard': {'enabled': True},
            'profile': {'enabled': True},
            'messages': {'enabled': True}
        }
        
        if user_access:
            try:
                pages_data = json.loads(user_access.pages) if user_access.pages else {}
                # Merge with defaults
                for page, settings in default_pages.items():
                    if page not in pages_data:
                        pages_data[page] = settings
                access_data = pages_data
            except:
                access_data = default_pages
        else:
            access_data = default_pages
        
        # Admin always has full access
        if user.role == 'admin':
            for page in access_data:
                access_data[page]['enabled'] = True
        
        return jsonify({
            "success": True,
            "message": "User access retrieved",
            "data": {
                "access": access_data,
                "user_role": user.role
            }
        })
    except Exception as e:
        logger.error(f"Get my access error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to retrieve user access",
            "error": str(e)
        }), 500

# User management (admin only)
@app.route('/api/users', methods=['GET'])
@admin_required
def get_users():
    try:
        users = User.query.all()
        result = []
        for u in users:
            result.append({
                "id": u.id,
                "name": u.name,
                "email": u.email,
                "role": u.role,
                "company": u.company,
                "phone": u.phone,
                "membership_number": u.membership_number,
                "membership_date": u.created_at.strftime("%Y-%m-%d"),
                "created_at": u.created_at.isoformat()
            })
        
        return jsonify({
            "success": True,
            "message": "Users retrieved",
            "data": {"users": result}
        })
    except Exception as e:
        logger.error(f"Get users error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to retrieve users",
            "error": str(e)
        }), 500

# Delete user endpoint
@app.route('/api/admin/users/<email>', methods=['DELETE'])
@admin_required
def delete_user_endpoint(email):
    try:
        user_to_delete = User.query.filter_by(email=email).first()
        if not user_to_delete:
            return jsonify({
                "success": False,
                "message": "User not found",
                "error": "User does not exist"
            }), 404
        
        # Delete user's loads and messages
        Load.query.filter_by(shipper_id=user_to_delete.id).delete()
        
        # Delete messages using membership number
        user_membership = user_to_delete.membership_number or 'Admin'
        Message.query.filter(
            (Message.sender_membership == user_membership) | 
            (Message.recipient_membership == user_membership)
        ).delete()
        
        # Delete user access controls
        UserAccessControl.query.filter_by(user_id=user_to_delete.id).delete()
        
        db.session.delete(user_to_delete)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "User deleted successfully",
            "data": {"email": email}
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete user error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to delete user",
            "error": str(e)
        }), 500

# Reset password endpoint
@app.route('/api/admin/reset-password', methods=['POST'])
@admin_required
def reset_password():
    try:
        data = request.get_json()
        email = data.get('email')
        new_password = data.get('new_password')
        
        if not email or not new_password:
            return jsonify({
                "success": False,
                "message": "Password reset failed",
                "error": "Email and new password are required"
            }), 400
        
        user_to_update = User.query.filter_by(email=email).first()
        if not user_to_update:
            return jsonify({
                "success": False,
                "message": "Password reset failed",
                "error": "User not found"
            }), 404
        
        user_to_update.set_password(new_password)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Password reset successfully",
            "data": {"email": email}
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Reset password error: {e}")
        return jsonify({
            "success": False,
            "message": "Password reset failed",
            "error": str(e)
        }), 500

# Debug database endpoint
@app.route("/api/debug/db")
def debug_db():
    try:
        # First, test basic database connection
        db_healthy = check_db_connection()
        connection_status = "OK" if db_healthy else "ERROR"
        
        if not db_healthy:
            return jsonify({
                "database_type": "PostgreSQL",
                "connection_status": "ERROR",
                "error": "Database connection failed"
            }), 500

    except Exception as e:
        db.session.rollback()
        connection_status = "ERROR"
        connection_error = str(e)

    # Now gather detailed database information
    try:
        # Count records in each table
        user_count = User.query.count()
        load_count = Load.query.count()
        message_count = Message.query.count()
        access_control_count = AccessControl.query.count()
        user_access_control_count = UserAccessControl.query.count()
        banner_count = Banner.query.count()
        
        # List users
        users = []
        for user in User.query.all():
            users.append({
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role,
                "membership_number": user.membership_number,
                "created_at": user.created_at.isoformat()
            })
        
        # Get database type
        database_type = "PostgreSQL" if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI'] else "SQLite"
        
        # Prepare response
        response = {
            "database_type": database_type,
            "database_uri": app.config['SQLALCHEMY_DATABASE_URI'],
            "connection_status": connection_status,
            "user_count": user_count,
            "load_count": load_count,
            "message_count": message_count,
            "access_control_count": access_control_count,
            "user_access_control_count": user_access_control_count,
            "banner_count": banner_count,
            "users": users,
            "environment": os.environ.get('RENDER', 'local')
        }
        
        # Add connection error if there was one
        if connection_status == "ERROR":
            response["connection_error"] = connection_error
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Debug DB error: {e}")
        return jsonify({
            "database_type": db.engine.name if hasattr(db, 'engine') else "Unknown",
            "connection_status": "ERROR",
            "error": str(e)
        }), 500

# Initialize application
if __name__ == '__main__':
    initialize_data()
    port = int(os.environ.get('PORT', 10000))
    logger.info(f"🚀 Starting MakiwaFreight server on port {port}")
    # Turn off debug mode for production
    app.run(debug=False, host='0.0.0.0', port=port)
