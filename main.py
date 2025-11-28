# main.py - COMPLETE PRODUCTION-READY VERSION
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

# Configure database - FIXED VERSION
def get_database_url():
    """REQUIRE PostgreSQL - no SQLite fallback"""
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
    'pool_pre_ping': True
}

# Initialize db
db = SQLAlchemy(app)

# Database Models
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

# Helper Functions
def generate_membership_number():
    """Generates a unique membership number in the format MF000001."""
    try:
        last_membership = db.session.query(User.membership_number).filter(
            User.membership_number.like('MF%')
        ).order_by(User.membership_number.desc()).first()
        
        if not last_membership:
            next_id = 1
        else:
            try:
                last_num = int(last_membership[0][2:])
                next_id = last_num + 1
            except (ValueError, IndexError):
                next_id = 1
        
        return f"MF{str(next_id).zfill(6)}"
    except Exception as e:
        logger.error(f"Error generating membership number: {e}")
        return f"MF000001"

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
            default_data = get_default_access_control_data()
            ac = AccessControl(data=json.dumps(default_data))
            db.session.add(ac)
            db.session.commit()
            return default_data
        
        try:
            data = json.loads(ac.data)
        except:
            default_data = get_default_access_control_data()
            ac.data = json.dumps(default_data)
            db.session.commit()
            return default_data
            
        default_data = get_default_access_control_data()
        updated = False
        
        if 'pages' not in data or not isinstance(data['pages'], dict):
            data['pages'] = default_data['pages']
            updated = True
        else:
            if 'post_load' not in data['pages'] or not isinstance(data['pages'].get('post_load'), dict):
                data['pages']['post_load'] = default_data['pages']['post_load']
                updated = True
            if 'market' not in data['pages'] or not isinstance(data['pages'].get('market'), dict):
                data['pages']['market'] = default_data['pages']['market']
                updated = True
        
        if 'banners' not in data or not isinstance(data['banners'], dict):
            data['banners'] = default_data['banners']
            updated = True
        else:
            for key in ['index', 'dashboard']:
                if key not in data['banners']:
                    data['banners'][key] = default_data['banners'][key]
                    updated = True
        
        if 'post_loads_enabled' not in data:
            data['post_loads_enabled'] = default_data['post_loads_enabled']
            updated = True
        
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

def initialize_data():
    with app.app_context():
        try:
            logger.info("Initializing database...")
            
            # Drop all existing tables to ensure clean schema
            db.drop_all()
            logger.info("✅ Dropped existing tables")
            
            # Create all tables with correct schema
            db.create_all()
            logger.info("✅ Database tables created with correct schema")
            
            # Test database connection
            db.session.execute(text("SELECT 1"))
            db_type = "PostgreSQL" if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI'] else "SQLite"
            logger.info(f"✅ Connected to {db_type} database")
            
            # Create admin user - FIXED VERSION
            admin_email = 'cyprianmak@gmail.com'
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
                admin.set_password("Muchandida@1")
                db.session.add(admin)
                db.session.commit()
                logger.info("✅ Admin user created")
            else:
                # Ensure existing admin has correct role
                if admin.role != 'admin':
                    admin.role = 'admin'
                    db.session.commit()
                    logger.info("✅ Updated existing user to admin role")
                else:
                    logger.info("✅ Admin user already exists with correct role")
                    
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
        db.session.execute(text("SELECT 1"))
        db_info = "PostgreSQL" if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI'] else "SQLite"
        return jsonify({
            "success": True,
            "message": "Service is healthy",
            "data": {
                "status": "healthy",
                "database": "connected",
                "database_type": db_info
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
        role = data.get('role', 'shipper')
        
        if not name or not email or not password:
            return jsonify({
                "success": False,
                "message": "Registration failed",
                "error": "name, email, and password are required"
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

# User endpoints
@app.route('/api/users/me', methods=['GET'])
def get_current_user():
    try:
        user = check_auth(request)
        if not user:
            return jsonify({
                "success": False,
                "message": "Authentication required",
                "error": "Please login to continue"
            }), 401
        
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
        return jsonify({
            "success": False,
            "message": "Failed to retrieve user data",
            "error": str(e)
        }), 500

@app.route('/api/users/me', methods=['PUT'])
def update_current_user():
    try:
        user = check_auth(request)
        if not user:
            return jsonify({
                "success": False,
                "message": "Authentication required",
                "error": "Please login to continue"
            }), 401
        
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "message": "Update failed",
                "error": "No JSON data provided"
            }), 400
        
        if 'name' in data:
            user.name = data['name']
        if 'company' in data:
            user.company = data['company']
        if 'phone' in data:
            user.phone = data['phone']
        if 'address' in data:
            user.address = data['address']
        if 'vehicle_info' in data:
            user.vehicle_info = data['vehicle_info']
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
                    "membership_number": user.membership_number
                }
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "success": False,
            "message": "Profile update failed",
            "error": str(e)
        }), 500

# Load endpoints
@app.route('/api/loads', methods=['GET', 'POST'])
def handle_loads():
    try:
        if request.method == 'GET':
            loads = Load.query.filter(Load.expires_at >= datetime.now(timezone.utc)).all()
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
                    "shipper_name": load.shipper.name if load.shipper else "Unknown",
                    "shipper_membership": load.shipper.membership_number if load.shipper else "Unknown",
                    "expires_at": load.expires_at.isoformat(),
                    "created_at": load.created_at.isoformat()
                })
            return jsonify({
                "success": True,
                "message": "Loads retrieved",
                "data": {"loads": result}
            })
        
        if request.method == 'POST':
            user = check_auth(request)
            if not user:
                return jsonify({
                    "success": False,
                    "message": "Authentication required",
                    "error": "Please login to post loads"
                }), 401
            
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
                        "expires_at": new_load.expires_at.isoformat()
                    }
                }
            }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "success": False,
            "message": "Operation failed",
            "error": str(e)
        }), 500

@app.route('/api/loads/<load_id>', methods=['PUT'])
def update_load_endpoint(load_id):
    try:
        user = check_auth(request)
        if not user:
            return jsonify({
                "success": False,
                "message": "Authentication required",
                "error": "Please login to continue"
            }), 401
        
        load = db.session.get(Load, load_id)
        if not load:
            return jsonify({
                "success": False,
                "message": "Load not found",
                "error": "Load does not exist"
            }), 404
        
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
        return jsonify({
            "success": False,
            "message": "Failed to update load",
            "error": str(e)
        }), 500

@app.route('/api/loads/<load_id>', methods=['DELETE'])
def delete_load_endpoint(load_id):
    try:
        user = check_auth(request)
        if not user:
            return jsonify({
                "success": False,
                "message": "Authentication required",
                "error": "Please login to continue"
            }), 401
        
        load = db.session.get(Load, load_id)
        if not load:
            return jsonify({
                "success": False,
                "message": "Load not found",
                "error": "Load does not exist"
            }), 404
        
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
        return jsonify({
            "success": False,
            "message": "Failed to delete load",
            "error": str(e)
        }), 500

# Message endpoints
@app.route('/api/messages', methods=['GET', 'POST'])
def handle_messages():
    try:
        user = check_auth(request)
        if not user:
            return jsonify({
                "success": False,
                "message": "Authentication required",
                "error": "Please login to access messages"
            }), 401
        
        if request.method == 'GET':
            user_membership = user.membership_number or 'Admin'
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
                    "created_at": msg.created_at.isoformat()
                })
            return jsonify({
                "success": True,
                "message": "Messages retrieved",
                "data": {"messages": result}
            })
        
        if request.method == 'POST':
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
            
            recipient = User.query.filter_by(membership_number=recipient_membership).first()
            if not recipient and recipient_membership != 'Admin':
                return jsonify({
                    "success": False,
                    "message": "Message not sent",
                    "error": "Recipient not found"
                }), 404
            
            sender_membership = user.membership_number or 'Admin'
            
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
        return jsonify({
            "success": False,
            "message": "Message operation failed",
            "error": str(e)
        }), 500

# Admin endpoints
@app.route('/api/admin/banners', methods=['GET'])
def get_admin_banners():
    try:
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        
        return jsonify({
            "success": True,
            "message": "Banners retrieved",
            "data": get_banners()
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Failed to retrieve banners",
            "error": str(e)
        }), 500

@app.route('/api/admin/banners', methods=['POST'])
def update_admin_banners():
    try:
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        
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
        return jsonify({
            "success": False,
            "message": "Banner update failed",
            "error": str(e)
        }), 500

@app.route('/api/admin/access-control', methods=['GET'])
def get_admin_access_control():
    try:
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        
        return jsonify({
            "success": True,
            "message": "Access control data retrieved",
            "data": get_access_control()
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Failed to retrieve access control data",
            "error": str(e)
        }), 500

@app.route('/api/admin/access-control', methods=['PUT'])
def update_admin_access_control():
    try:
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        
        data = request.get_json()
        updated_data = update_access_control(data)
        
        return jsonify({
            "success": True,
            "message": "Access control updated successfully",
            "data": updated_data
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Failed to update access control",
            "error": str(e)
        }), 500

@app.route('/api/admin/users/<string:user_id>/access', methods=['GET'])
def get_user_access(user_id):
    try:
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        
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
        return jsonify({
            "success": False,
            "message": "Failed to retrieve user access",
            "error": str(e)
        }), 500

@app.route('/api/admin/users/<string:user_id>/access', methods=['PUT'])
def update_user_access(user_id):
    try:
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        
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
        return jsonify({
            "success": False,
            "message": "Failed to update user access",
            "error": str(e)
        }), 500

@app.route('/api/users', methods=['GET'])
def get_users():
    try:
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        
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
        return jsonify({
            "success": False,
            "message": "Failed to retrieve users",
            "error": str(e)
        }), 500

@app.route('/api/admin/users/<email>', methods=['DELETE'])
def delete_user_endpoint(email):
    try:
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        
        user_to_delete = User.query.filter_by(email=email).first()
        if not user_to_delete:
            return jsonify({
                "success": False,
                "message": "User not found",
                "error": "User does not exist"
            }), 404
        
        Load.query.filter_by(shipper_id=user_to_delete.id).delete()
        
        user_membership = user_to_delete.membership_number or 'Admin'
        Message.query.filter(
            (Message.sender_membership == user_membership) | 
            (Message.recipient_membership == user_membership)
        ).delete()
        
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
        return jsonify({
            "success": False,
            "message": "Failed to delete user",
            "error": str(e)
        }), 500

@app.route('/api/admin/reset-password', methods=['POST'])
def reset_password():
    try:
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        
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
        return jsonify({
            "success": False,
            "message": "Password reset failed",
            "error": str(e)
        }), 500

@app.route("/api/debug/db")
def debug_db():
    try:
        db.session.execute(text("SELECT 1"))
        db.session.commit()
        connection_status = "OK"
    except Exception as e:
        db.session.rollback()
        connection_status = "ERROR"
        connection_error = str(e)

    try:
        user_count = User.query.count()
        load_count = Load.query.count()
        message_count = Message.query.count()
        access_control_count = AccessControl.query.count()
        user_access_control_count = UserAccessControl.query.count()
        banner_count = Banner.query.count()
        
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
        
        database_type = "PostgreSQL" if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI'] else "SQLite"
        
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
        
        if connection_status == "ERROR":
            response["connection_error"] = connection_error
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({
            "database_type": db.engine.name if hasattr(db, 'engine') else "Unknown",
            "connection_status": "ERROR",
            "error": str(e)
        }), 500

@app.route('/api/debug/db-config')
def debug_db_config():
    return jsonify({
        "db_user": os.environ.get('DB_USER'),
        "db_host": os.environ.get('DB_HOST'), 
        "db_database": os.environ.get('DB_DATABASE'),
        "db_port": os.environ.get('DB_PORT'),
        "database_url": os.environ.get('DATABASE_URL'),
        "has_db_url": bool(os.environ.get('DATABASE_URL'))
    })

@app.route('/api/debug/check-admin')
def debug_check_admin():
    user = User.query.filter_by(email='cyprianmak@gmail.com').first()
    if user:
        return jsonify({
            "email": user.email,
            "role": user.role,
            "is_admin": user.role == 'admin',
            "id": user.id
        })
    return jsonify({"error": "User not found"}), 404


@app.route('/api/debug/db-info')
def debug_db_info():
    return jsonify({
        'database_url': os.environ.get('DATABASE_URL'),
        'db_user': os.environ.get('DB_USER'),
        'using_postgresql': 'postgresql' in os.environ.get('DATABASE_URL', ''),
        'tables_created': True
    })

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
