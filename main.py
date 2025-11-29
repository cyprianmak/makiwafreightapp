# main.py - PRODUCTION-READY VERSION
from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import uuid
import json
import os
from sqlalchemy import text
import psycopg2
import logging
from functools import wraps

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates', static_folder='static')

# Configure database - PRODUCTION READY
def get_database_url():
    """Get database URL with PostgreSQL requirement"""
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        logger.error("❌ DATABASE_URL environment variable is required but not set!")
        raise ValueError("DATABASE_URL environment variable is required but not set!")
    
    # Fix old postgres:// URLs for SQLAlchemy
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    
    logger.info("✅ Using PostgreSQL from DATABASE_URL")
    return database_url

app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True,
    'pool_size': 10,
    'max_overflow': 20
}

# Security configurations
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Initialize db
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, index=True)
    company = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    vehicle_info = db.Column(db.String(200))
    membership_number = db.Column(db.String(20), unique=True, nullable=True, index=True)
    token = db.Column(db.String(36), index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Load(db.Model):
    __tablename__ = 'loads'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ref = db.Column(db.String(10), nullable=False, index=True)
    origin = db.Column(db.String(100), nullable=False, index=True)
    destination = db.Column(db.String(100), nullable=False, index=True)
    date = db.Column(db.String(10), nullable=False)
    cargo_type = db.Column(db.String(50), nullable=False)
    weight = db.Column(db.Float, nullable=False)
    notes = db.Column(db.Text)
    shipper_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
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
    sender_membership = db.Column(db.String(20), nullable=False, index=True)
    recipient_membership = db.Column(db.String(20), nullable=False, index=True)
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
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    pages = db.Column(db.Text)  # JSON string containing page access data
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    user = db.relationship('User', backref=db.backref('access_controls', lazy=True))

# Helper Functions
def generate_membership_number():
    """Generates a unique membership number in the format MF000001."""
    try:
        # Use database sequence for thread-safe membership number generation
        result = db.session.execute(text("SELECT nextval('membership_number_seq')"))
        next_id = result.scalar()
        return f"MF{str(next_id).zfill(6)}"
    except Exception as e:
        logger.warning(f"Sequence not found, creating sequence: {e}")
        try:
            db.session.execute(text("CREATE SEQUENCE IF NOT EXISTS membership_number_seq START 100001"))
            db.session.commit()
            result = db.session.execute(text("SELECT nextval('membership_number_seq')"))
            next_id = result.scalar()
            return f"MF{str(next_id).zfill(6)}"
        except Exception as seq_error:
            logger.error(f"Error creating sequence: {seq_error}")
            # Fallback: use timestamp-based approach
            return f"MF{str(int(datetime.now(timezone.utc).timestamp())).zfill(6)}"

def check_auth(request):
    """Check authentication token with error handling"""
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return None
    token = token.split(' ')[1]
    
    try:
        return User.query.filter_by(token=token).first()
    except Exception as e:
        logger.error(f"Auth error: {e}")
        return None

def admin_required(f):
    """Decorator for admin-only endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        return f(*args, **kwargs)
    return decorated_function

def auth_required(f):
    """Decorator for authenticated endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = check_auth(request)
        if not user:
            return jsonify({
                "success": False,
                "message": "Authentication required",
                "error": "Please login to continue"
            }), 401
        return f(*args, **kwargs)
    return decorated_function

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
    """Get access control data with proper error handling"""
    try:
        ac = AccessControl.query.first()
        if not ac:
            default_data = get_default_access_control_data()
            ac = AccessControl(data=json.dumps(default_data))
            db.session.add(ac)
            db.session.commit()
            return default_data
        
        try:
            data = json.loads(ac.data)
        except json.JSONDecodeError:
            logger.warning("Invalid JSON in access control, resetting to default")
            default_data = get_default_access_control_data()
            ac.data = json.dumps(default_data)
            db.session.commit()
            return default_data
            
        # Ensure all required keys exist
        default_data = get_default_access_control_data()
        updated = False
        
        for key in ['pages', 'banners', 'post_loads_enabled', 'user_access']:
            if key not in data:
                data[key] = default_data[key]
                updated = True
        
        if updated:
            ac.data = json.dumps(data)
            db.session.commit()
        return data
    except Exception as e:
        logger.error(f"Error in get_access_control: {e}")
        return get_default_access_control_data()

def update_access_control(data):
    """Update access control with error handling"""
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
        raise

def initialize_data():
    """Initialize database with proper error handling"""
    with app.app_context():
        try:
            logger.info("Initializing database...")
            
            # Create all tables
            db.create_all()
            logger.info("✅ Database tables created")
            
            # Create sequence for membership numbers
            try:
                db.session.execute(text("CREATE SEQUENCE IF NOT EXISTS membership_number_seq START 100001"))
                db.session.commit()
            except Exception as e:
                logger.warning(f"Sequence creation warning: {e}")
            
            # Test database connection
            db.session.execute(text("SELECT 1"))
            db_type = "PostgreSQL" if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI'] else "SQLite"
            logger.info(f"✅ Connected to {db_type} database")
            
            # Create admin user
            admin_email = os.environ.get('ADMIN_EMAIL', 'cyprianmak@gmail.com')
            admin_password = os.environ.get('ADMIN_PASSWORD', 'Muchandida@1')
            admin = User.query.filter_by(email=admin_email).first()
            
            if not admin:
                logger.info("Creating admin user...")
                admin = User(
                    name="Admin User",
                    email=admin_email,
                    role="admin",
                    membership_number="MF152285",
                    company="MakiwaFreight Admin",
                    phone="0739874446"
                )
                admin.set_password(admin_password)
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

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "message": "Resource not found",
        "error": str(error)
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "success": False,
        "message": "Internal server error",
        "error": "An unexpected error occurred"
    }), 500

@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        "success": False,
        "message": "Bad request",
        "error": str(error)
    }), 400

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
        db.session.execute(text("SELECT 1"))
        db_info = "PostgreSQL" if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI'] else "SQLite"
        return jsonify({
            "success": True,
            "message": "Service is healthy",
            "data": {
                "status": "healthy",
                "database": "connected",
                "database_type": db_info,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
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
            
        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '').strip()
        role = data.get('role', 'shipper')
        
        # Validation
        if not name or not email or not password:
            return jsonify({
                "success": False,
                "message": "Registration failed",
                "error": "Name, email, and password are required"
            }), 400
        
        if len(password) < 8:
            return jsonify({
                "success": False,
                "message": "Registration failed",
                "error": "Password must be at least 8 characters long"
            }), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({
                "success": False,
                "message": "Registration failed",
                "error": "Email already registered"
            }), 400
        
        membership_number = generate_membership_number()
        
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
        
        # Generate token for immediate login
        token = str(uuid.uuid4())
        new_user.token = token
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Registration successful",
            "data": {
                "token": token,
                "user": {
                    "id": new_user.id,
                    "name": new_user.name,
                    "email": new_user.email,
                    "role": new_user.role,
                    "membership_number": new_user.membership_number
                }
            }
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
            
        email = data.get('email', '').strip().lower()
        password = data.get('password', '').strip()
        
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

# User endpoints
@app.route('/api/users/me', methods=['GET'])
@auth_required
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
                    "created_at": user.created_at.isoformat()
                }
            }
        })
    except Exception as e:
        logger.error(f"Error getting current user: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to retrieve user data",
            "error": str(e)
        }), 500

@app.route('/api/users/me', methods=['PUT'])
@auth_required
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
        
        # Update allowed fields
        allowed_fields = ['name', 'company', 'phone', 'address', 'vehicle_info']
        for field in allowed_fields:
            if field in data:
                setattr(user, field, data[field])
        
        if 'password' in data and data['password']:
            if len(data['password']) >= 8:
                user.set_password(data['password'])
            else:
                return jsonify({
                    "success": False,
                    "message": "Update failed",
                    "error": "Password must be at least 8 characters long"
                }), 400
        
        user.updated_at = datetime.now(timezone.utc)
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
                    "membership_number": user.membership_number
                }
            }
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Profile update error: {e}")
        return jsonify({
            "success": False,
            "message": "Profile update failed",
            "error": str(e)
        }), 500

# Load endpoints
@app.route('/api/loads', methods=['GET'])
def get_loads():
    try:
        # Get all non-expired loads with shipper information
        loads = Load.query.filter(
            Load.expires_at >= datetime.now(timezone.utc)
        ).join(User).add_entity(User).all()
        
        result = []
        for load, shipper in loads:
            result.append({
                "id": load.id,
                "ref": load.ref,
                "origin": load.origin,
                "destination": load.destination,
                "date": load.date,
                "cargo_type": load.cargo_type,
                "weight": load.weight,
                "notes": load.notes,
                "shipper_name": shipper.name,
                "shipper_membership": shipper.membership_number,
                "shipper_company": shipper.company,
                "expires_at": load.expires_at.isoformat(),
                "created_at": load.created_at.isoformat()
            })
        return jsonify({
            "success": True,
            "message": "Loads retrieved",
            "data": {"loads": result}
        })
    except Exception as e:
        logger.error(f"Error getting loads: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to retrieve loads",
            "error": str(e)
        }), 500

@app.route('/api/loads', methods=['POST'])
@auth_required
def create_load():
    try:
        user = check_auth(request)
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
        
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        ref = 'LD' + str(int(datetime.now(timezone.utc).timestamp()))[-6:]
        
        new_load = Load(
            ref=ref,
            origin=data['origin'],
            destination=data['destination'],
            date=data['date'],
            cargo_type=data['cargo_type'],
            weight=float(data['weight']),
            notes=data.get('notes', ''),
            shipper_id=user.id,
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
                    "date": new_load.date,
                    "cargo_type": new_load.cargo_type,
                    "weight": new_load.weight,
                    "notes": new_load.notes,
                    "expires_at": new_load.expires_at.isoformat(),
                    "created_at": new_load.created_at.isoformat()
                }
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Load creation error: {e}")
        return jsonify({
            "success": False,
            "message": "Load creation failed",
            "error": str(e)
        }), 500

@app.route('/api/my-loads', methods=['GET'])
@auth_required
def get_my_loads():
    try:
        user = check_auth(request)
        loads = Load.query.filter_by(shipper_id=user.id).order_by(Load.created_at.desc()).all()
        result = []
        for load in loads:
            result.append({
                "id": load.id,
                "ref": load.ref,
                "origin": load.origin,
                "destination": load.destination,
                "date": load.date,
                "cargo_type": load.cargo_type,
                "weight": load.weight,
                "notes": load.notes,
                "expires_at": load.expires_at.isoformat(),
                "created_at": load.created_at.isoformat(),
                "is_expired": load.expires_at < datetime.now(timezone.utc)
            })
        
        return jsonify({
            "success": True,
            "message": "Your loads retrieved",
            "data": {"loads": result}
        })
    except Exception as e:
        logger.error(f"Error getting user loads: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to retrieve your loads",
            "error": str(e)
        }), 500

@app.route('/api/loads/<load_id>', methods=['DELETE'])
@auth_required
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
        
        if load.shipper_id != user.id and user.role != 'admin':
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
        logger.error(f"Error deleting load: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to delete load",
            "error": str(e)
        }), 500

# Message endpoints
@app.route('/api/messages', methods=['GET'])
@auth_required
def get_messages():
    try:
        user = check_auth(request)
        if user.role == 'admin':
            messages = Message.query.order_by(Message.created_at.desc()).all()
        else:
            user_membership = user.membership_number
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
                "is_sent_by_me": msg.sender_membership == (user.membership_number or 'Admin')
            })
        return jsonify({
            "success": True,
            "message": "Messages retrieved",
            "data": {"messages": result}
        })
    except Exception as e:
        logger.error(f"Error getting messages: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to retrieve messages",
            "error": str(e)
        }), 500

@app.route('/api/messages', methods=['POST'])
@auth_required
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
                
        recipient_membership = data.get('recipient_membership', '').strip()
        body = data.get('body', '').strip()
        
        if not recipient_membership or not body:
            return jsonify({
                "success": False,
                "message": "Message not sent",
                "error": "Recipient membership number and message body required"
            }), 400
        
        # Check if recipient exists or is admin
        if recipient_membership != 'Admin':
            recipient = User.query.filter_by(membership_number=recipient_membership).first()
            if not recipient:
                return jsonify({
                    "success": False,
                    "message": "Message not sent",
                    "error": "Recipient not found"
                }), 404
        
        sender_membership = user.membership_number if user.membership_number else 'Admin'
        
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
        logger.error(f"Error sending message: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to send message",
            "error": str(e)
        }), 500

# Admin endpoints
@app.route('/api/admin/loads', methods=['GET'])
@admin_required
def get_all_loads_admin():
    try:
        loads = Load.query.join(User).add_entity(User).all()
        
        result = []
        for load, shipper in loads:
            result.append({
                "id": load.id,
                "ref": load.ref,
                "origin": load.origin,
                "destination": load.destination,
                "date": load.date,
                "cargo_type": load.cargo_type,
                "weight": load.weight,
                "notes": load.notes,
                "shipper_name": shipper.name,
                "shipper_email": shipper.email,
                "shipper_membership": shipper.membership_number,
                "shipper_company": shipper.company,
                "expires_at": load.expires_at.isoformat(),
                "created_at": load.created_at.isoformat(),
                "is_expired": load.expires_at < datetime.now(timezone.utc)
            })
        
        return jsonify({
            "success": True,
            "message": "All loads retrieved",
            "data": {"loads": result}
        })
    except Exception as e:
        logger.error(f"Admin loads error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to retrieve loads",
            "error": str(e)
        }), 500

@app.route('/api/admin/banners', methods=['GET'])
@admin_required
def get_admin_banners():
    try:
        return jsonify({
            "success": True,
            "message": "Banners retrieved",
            "data": get_access_control().get('banners', {})
        })
    except Exception as e:
        logger.error(f"Error getting banners: {e}")
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
        
        ac_data = get_access_control()
        ac_data['banners'] = data
        update_access_control(ac_data)
        
        return jsonify({
            "success": True,
            "message": "Banners updated successfully",
            "data": data
        })
    except Exception as e:
        logger.error(f"Error updating banners: {e}")
        return jsonify({
            "success": False,
            "message": "Banner update failed",
            "error": str(e)
        }), 500

@app.route('/api/admin/access-control', methods=['GET'])
@admin_required
def get_admin_access_control():
    try:
        return jsonify({
            "success": True,
            "message": "Access control data retrieved",
            "data": get_access_control()
        })
    except Exception as e:
        logger.error(f"Error getting access control: {e}")
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
        updated_data = update_access_control(data)
        
        return jsonify({
            "success": True,
            "message": "Access control updated successfully",
            "data": updated_data
        })
    except Exception as e:
        logger.error(f"Error updating access control: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to update access control",
            "error": str(e)
        }), 500

@app.route('/api/admin/users/<string:user_id>/access', methods=['GET'])
@admin_required
def get_user_access(user_id):
    try:
        target_user = User.query.filter_by(id=user_id).first()
        if not target_user:
            return jsonify({
                "success": False,
                "message": "User not found",
                "error": "User does not exist"
            }), 404
        
        user_access = UserAccessControl.query.filter_by(user_id=user_id).first()
        
        if not user_access:
            return jsonify({
                "success": True,
                "message": "User access retrieved",
                "data": {
                    "user_id": user_id,
                    "pages": {
                        'market': {'enabled': False},
                        'shipper-post': {'enabled': False}
                    }
                }
            })
        
        return jsonify({
            "success": True,
            "message": "User access retrieved",
            "data": {
                "user_id": user_id,
                "pages": json.loads(user_access.pages) if user_access.pages else {}
            }
        })
    except Exception as e:
        logger.error(f"Error getting user access: {e}")
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
        
        target_user = User.query.filter_by(id=user_id).first()
        if not target_user:
            return jsonify({
                "success": False,
                "message": "User not found",
                "error": "User does not exist"
            }), 404
        
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
                "pages": data['pages']
            }
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating user access: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to update user access",
            "error": str(e)
        }), 500

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
                "created_at": u.created_at.isoformat()
            })
        
        return jsonify({
            "success": True,
            "message": "Users retrieved",
            "data": {"users": result}
        })
    except Exception as e:
        logger.error(f"Error getting users: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to retrieve users",
            "error": str(e)
        }), 500

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
        
        # Delete user's loads
        Load.query.filter_by(shipper_id=user_to_delete.id).delete()
        
        # Delete user's messages
        user_membership = user_to_delete.membership_number or 'Admin'
        Message.query.filter(
            (Message.sender_membership == user_membership) | 
            (Message.recipient_membership == user_membership)
        ).delete()
        
        # Delete user's access controls
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
        logger.error(f"Error deleting user: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to delete user",
            "error": str(e)
        }), 500

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
        
        if len(new_password) < 8:
            return jsonify({
                "success": False,
                "message": "Password reset failed",
                "error": "Password must be at least 8 characters long"
            }), 400
        
        user_to_update = User.query.filter_by(email=email).first()
        if not user_to_update:
            return jsonify({
                "success": False,
                "message": "Password reset failed",
                "error": "User not found"
            }), 404
        
        user_to_update.set_password(new_password)
        user_to_update.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Password reset successfully",
            "data": {"email": email}
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error resetting password: {e}")
        return jsonify({
            "success": False,
            "message": "Password reset failed",
            "error": str(e)
        }), 500

# Debug endpoints
@app.route("/api/debug/db")
def debug_db():
    try:
        db.session.execute(text("SELECT 1"))
        connection_status = "OK"
    except Exception as e:
        connection_status = f"ERROR: {str(e)}"

    try:
        user_count = User.query.count()
        load_count = Load.query.count()
        message_count = Message.query.count()
        access_control_count = AccessControl.query.count()
        user_access_control_count = UserAccessControl.query.count()
        
        database_type = "PostgreSQL" if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI'] else "SQLite"
        
        response = {
            "database_type": database_type,
            "connection_status": connection_status,
            "user_count": user_count,
            "load_count": load_count,
            "message_count": message_count,
            "access_control_count": access_control_count,
            "user_access_control_count": user_access_control_count,
            "environment": os.environ.get('RENDER', 'local'),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({
            "database_type": db.engine.name if hasattr(db, 'engine') else "Unknown",
            "connection_status": "ERROR",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 500

# Initialize the application
with app.app_context():
    initialize_data()

# Application entry point
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"🚀 Starting MakiwaFreight server on port {port}")
    
    db_type = "PostgreSQL" if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI'] else "SQLite"
    logger.info(f"📊 Database type: {db_type}")
    
    if os.environ.get('RENDER'):
        app.run(host='0.0.0.0', port=port)
    else:
        app.run(debug=True, host='0.0.0.0', port=port)
