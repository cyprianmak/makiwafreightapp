from flask import Flask, render_template, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import uuid
import json
import os
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)
# Configure the database with persistent storage
# Check if we're running on Render
if os.environ.get('RENDER'):
    # Use Render's persistent storage
    persistent_dir = '/opt/render/project/.render/data'
    if not os.path.exists(persistent_dir):
        os.makedirs(persistent_dir)
    db_path = os.path.join(persistent_dir, 'makiwafreight.db')
    print(f"Using persistent database at: {db_path}")
else:
    # Local development - use data directory
    basedir = os.path.abspath(os.path.dirname(__file__))
    db_dir = os.path.join(basedir, 'data')
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)
    db_path = os.path.join(db_dir, 'makiwafreight.db')
    print(f"Using local database at: {db_path}")
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# Define database models
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    company = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    vehicle_info = db.Column(db.String(200))
    token = db.Column(db.String(36))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
class Load(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ref = db.Column(db.String(10), nullable=False)
    origin = db.Column(db.String(100), nullable=False)
    destination = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    cargo_type = db.Column(db.String(50), nullable=False)
    weight = db.Column(db.Float, nullable=False)
    notes = db.Column(db.Text)
    shipper_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    shipper = db.relationship('User', backref=db.backref('loads', lazy=True))
class Message(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_email = db.Column(db.String(100), nullable=False)
    recipient_email = db.Column(db.String(100), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
class AccessControl(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Text)  # JSON string containing access control data
class Banner(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    index = db.Column(db.String(200))
    dashboard = db.Column(db.String(200))
# Helper functions
def check_auth(request):
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return None
    token = token.split(' ')[1]
    return User.query.filter_by(token=token).first()
def get_default_access_control_data():
    return {
        'pages': {
            'post_load': {
                'allowed_roles': ['admin', 'shipper', 'transporter']  # All roles can post loads
            },
            'market': {
                'allowed_roles': ['admin', 'shipper', 'transporter']  # All roles can access market
            }
        },
        'banners': {
            'index': '',
            'dashboard': ''
        },
        'post_loads_enabled': True,  # Global setting to control post loads access
        'user_access': {}  # User-specific access control
    }
def get_access_control():
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
    
    # Ensure pages exists and has the required structure
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
    
    # Ensure banners exists and has the required structure
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
def update_access_control(data):
    ac = AccessControl.query.first()
    if not ac:
        ac = AccessControl()
        db.session.add(ac)
    
    ac.data = json.dumps(data)
    db.session.commit()
    return data
def get_banners():
    ac_data = get_access_control()
    return {
        'index': ac_data.get('banners', {}).get('index', ''),
        'dashboard': ac_data.get('banners', {}).get('dashboard', '')
    }
def update_banners(banners):
    ac_data = get_access_control()
    if 'banners' not in ac_data:
        ac_data['banners'] = {}
    
    ac_data['banners']['index'] = banners.get('index', '')
    ac_data['banners']['dashboard'] = banners.get('dashboard', '')
    
    return update_access_control(ac_data)
# Initialize admin user and database
def initialize_data():
    with app.app_context():
        # Check if the database file exists
        db_exists = os.path.exists(db_path)
        print(f"Database file exists: {db_exists}")
        
        # Check if tables exist by trying to query them
        tables_exist = False
        if db_exists:
            try:
                # Try to query the User table
                user_count = User.query.count()
                print(f"User table exists with {user_count} users")
                tables_exist = True
            except Exception as e:
                print(f"Error querying User table: {e}")
                tables_exist = False
        
        # Only create tables if they don't exist
        if not tables_exist:
            print("Creating database tables...")
            db.create_all()
            print("Database tables created")
        else:
            print("Database tables already exist, skipping table creation")
        
        # Check if admin user exists
        admin_email = 'cyprianmak@gmail.com'
        admin = User.query.filter_by(email=admin_email).first()
        
        if not admin:
            print("Creating admin user...")
            admin = User(
                name="Admin",
                email=admin_email,
                role="admin"
            )
            admin.set_password("Muchandida@1")
            db.session.add(admin)
            db.session.commit()
            print("Admin user created")
        else:
            print("Admin user already exists")
        
        # Check if access control data exists
        ac = AccessControl.query.first()
        if not ac:
            print("Creating access control data...")
            default_data = get_default_access_control_data()
            ac = AccessControl(data=json.dumps(default_data))
            db.session.add(ac)
            db.session.commit()
            print("Access control data created")
        else:
            print("Access control data already exists")
# Debug route to check database status
@app.route('/api/debug/db')
def debug_db():
    try:
        # Check if database file exists
        db_exists = os.path.exists(db_path)
        
        # Get file stats
        file_stats = {}
        if db_exists:
            stat = os.stat(db_path)
            file_stats = {
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stat.st_atime).isoformat()
            }
        
        # Count users
        user_count = User.query.count()
        
        # Count loads
        load_count = Load.query.count()
        
        # Count messages
        message_count = Message.query.count()
        
        # List users
        users = []
        for user in User.query.all():
            users.append({
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role,
                "created_at": user.created_at.isoformat()
            })
        
        return jsonify({
            "database_path": db_path,
            "database_exists": db_exists,
            "file_stats": file_stats,
            "user_count": user_count,
            "load_count": load_count,
            "message_count": message_count,
            "users": users,
            "environment": os.environ.get('RENDER', 'local')
        })
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500
# Backup and restore endpoints
@app.route('/api/admin/backup', methods=['POST'])
def backup_data():
    try:
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        
        # Create backup directory if it doesn't exist
        backup_dir = '/opt/render/project/.render/backups'
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        # Generate backup filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(backup_dir, f'makiwafreight_backup_{timestamp}.db')
        
        # Copy the database file
        import shutil
        shutil.copy2(db_path, backup_path)
        
        return jsonify({
            "success": True,
            "message": "Backup created successfully",
            "data": {
                "backup_path": backup_path,
                "timestamp": timestamp
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Backup failed",
            "error": str(e)
        }), 500
@app.route('/api/admin/restore', methods=['POST'])
def restore_data():
    try:
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        
        data = request.get_json()
        backup_file = data.get('backup_file')
        
        if not backup_file:
            return jsonify({
                "success": False,
                "message": "Backup file is required",
                "error": "Please provide a backup file path"
            }), 400
        
        # Check if backup file exists
        if not os.path.exists(backup_file):
            return jsonify({
                "success": False,
                "message": "Backup file not found",
                "error": f"Backup file {backup_file} does not exist"
            }), 404
        
        # Close all database connections
        db.session.remove()
        
        # Restore the database file
        import shutil
        shutil.copy2(backup_file, db_path)
        
        # Reinitialize the database
        initialize_data()
        
        return jsonify({
            "success": True,
            "message": "Data restored successfully",
            "data": {
                "backup_file": backup_file
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Restore failed",
            "error": str(e)
        }), 500
@app.route('/api/admin/list-backups', methods=['GET'])
def list_backups():
    try:
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        
        backup_dir = '/opt/render/project/.render/backups'
        backups = []
        
        if os.path.exists(backup_dir):
            for filename in os.listdir(backup_dir):
                if filename.startswith('makiwafreight_backup_') and filename.endswith('.db'):
                    file_path = os.path.join(backup_dir, filename)
                    stat = os.stat(file_path)
                    backups.append({
                        "filename": filename,
                        "path": file_path,
                        "size": stat.st_size,
                        "created": datetime.fromtimestamp(stat.st_ctime).isoformat()
                    })
        
        # Sort backups by creation time (newest first)
        backups.sort(key=lambda x: x['created'], reverse=True)
        
        return jsonify({
            "success": True,
            "message": "Backups retrieved",
            "data": {
                "backups": backups
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Failed to retrieve backups",
            "error": str(e)
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
                "admin_banners": "/api/admin/banners",
                "admin_access_control": "/api/admin/access-control",
                "debug_db": "/api/debug/db",
                "admin_backup": "/api/admin/backup",
                "admin_restore": "/api/admin/restore",
                "admin_list_backups": "/api/admin/list-backups"
            },
            "status": "running",
            "version": "1.0.0"
        }
    })
@app.route('/api/health')
def health():
    return jsonify({
        "success": True,
        "message": "Service is healthy",
        "data": {"status": "healthy"}
    })
# Auth endpoints
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'user')  # Default role
        
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
        
        # Create new user
        new_user = User(
            name=name,
            email=email,
            role=role
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
                    "role": new_user.role
                }
            }
        }), 201
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Registration failed",
            "error": str(e)
        }), 500
@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
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
                        "role": user.role
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
        return jsonify({
            "success": False,
            "message": "Login failed",
            "error": str(e)
        }), 500
# Get current user endpoint
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
# Update current user endpoint
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
        
        # Update fields if provided
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
                    "vehicle_info": user.vehicle_info
                }
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Profile update failed",
            "error": str(e)
        }), 500
# Admin banners endpoints
@app.route('/api/admin/banners', methods=['GET'])
def get_admin_banners():
    try:
        # Check if user is admin
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
        # Check if user is admin
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        
        data = request.get_json()
        
        if 'index' not in data or 'dashboard' not in data:
            return jsonify({
                "success": False,
                "message": "Update failed",
                "error": "Both index and dashboard banners are required"
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
# Admin access control endpoints
@app.route('/api/admin/access-control', methods=['GET'])
def get_admin_access_control():
    try:
        # Check if user is admin
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
        # Check if user is admin
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
# Load endpoints
@app.route('/api/loads', methods=['GET', 'POST'])
def handle_loads():
    try:
        user = check_auth(request)
        
        # Get all loads (public access)
        if request.method == 'GET':
            loads = Load.query.filter(Load.expires_at >= datetime.utcnow()).all()
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
                    "shipper": load.shipper.name if load.shipper else None,
                    "expires_at": load.expires_at.isoformat(),
                    "created_at": load.created_at.isoformat()
                })
            return jsonify({
                "success": True,
                "message": "Loads retrieved",
                "data": {"loads": result}
            })
        
        # Create new load (requires authentication)
        if request.method == 'POST':
            if not user:
                return jsonify({
                    "success": False,
                    "message": "Authentication required",
                    "error": "Please login to post loads"
                }), 401
            
            data = request.get_json()
            required_fields = ['ref', 'origin', 'destination', 'date', 'cargo_type', 'weight']
            for field in required_fields:
                if field not in data:
                    return jsonify({
                        "success": False,
                        "message": "Load creation failed",
                        "error": f"Missing field: {field}"
                    }), 400
            
            # Set expiration date (7 days from creation)
            expires_at = datetime.utcnow() + timedelta(days=7)
            
            new_load = Load(
                ref=data['ref'],
                origin=data['origin'],
                destination=data['destination'],
                date=data['date'],
                cargo_type=data['cargo_type'],
                weight=data['weight'],
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
        return jsonify({
            "success": False,
            "message": "Operation failed",
            "error": str(e)
        }), 500
# Update load endpoint
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
        
        load = Load.query.get(load_id)
        if not load:
            return jsonify({
                "success": False,
                "message": "Load not found",
                "error": "Load does not exist"
            }), 404
        
        # Only the shipper who posted the load can update it
        if load.shipper_id != user.id:
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "You can only update your own loads"
            }), 403
        
        data = request.get_json()
        
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
            load.weight = data['weight']
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
        return jsonify({
            "success": False,
            "message": "Failed to update load",
            "error": str(e)
        }), 500
# Delete load endpoint
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
        
        load = Load.query.get(load_id)
        if not load:
            return jsonify({
                "success": False,
                "message": "Load not found",
                "error": "Load does not exist"
            }), 404
        
        # Only the shipper who posted the load can delete it
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
        
        # Get user's messages
        if request.method == 'GET':
            messages = Message.query.filter(
                (Message.sender_email == user.email) | 
                (Message.recipient_email == user.email)
            ).order_by(Message.created_at.desc()).all()
            
            result = []
            for msg in messages:
                result.append({
                    "id": msg.id,
                    "sender": msg.sender_email,
                    "recipient": msg.recipient_email,
                    "body": msg.body,
                    "created_at": msg.created_at.isoformat()
                })
            return jsonify({
                "success": True,
                "message": "Messages retrieved",
                "data": {"messages": result}
            })
        
        # Send a new message
        if request.method == 'POST':
            data = request.get_json()
            recipient = data.get('recipient')
            body = data.get('body')
            
            if not recipient or not body:
                return jsonify({
                    "success": False,
                    "message": "Message not sent",
                    "error": "Recipient and message body required"
                }), 400
            
            # Verify recipient exists
            if not User.query.filter_by(email=recipient).first():
                return jsonify({
                    "success": False,
                    "message": "Message not sent",
                    "error": "Recipient not found"
                }), 404
            
            new_message = Message(
                sender_email=user.email,
                recipient_email=recipient,
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
        return jsonify({
            "success": False,
            "message": "Message operation failed",
            "error": str(e)
        }), 500
# User management (admin only)
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
# Delete user endpoint
@app.route('/api/users/<email>', methods=['DELETE'])
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
        
        # Delete user's loads and messages
        Load.query.filter_by(shipper_id=user_to_delete.id).delete()
        Message.query.filter(
            (Message.sender_email == user_to_delete.email) | 
            (Message.recipient_email == user_to_delete.email)
        ).delete()
        
        db.session.delete(user_to_delete)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "User deleted successfully",
            "data": {"email": email}
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Failed to delete user",
            "error": str(e)
        }), 500
# Reset password endpoint
from flask import Flask, render_template, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import uuid
import json
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Configure the database with persistent storage
# Check if we're running on Render
if os.environ.get('RENDER'):
    # Use PostgreSQL on Render
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        print(f"Using PostgreSQL database at: {database_url}")
    else:
        # Fallback to persistent SQLite if DATABASE_URL is not available
        persistent_dir = '/opt/render/project/.render/data'
        if not os.path.exists(persistent_dir):
            os.makedirs(persistent_dir)
        db_path = os.path.join(persistent_dir, 'makiwafreight.db')
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
        print(f"DATABASE_URL not found, using SQLite fallback at: {db_path}")
else:
    # Local development - check for PostgreSQL first, then fallback to SQLite
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        print(f"Using PostgreSQL database at: {database_url}")
    else:
        # Local development - use SQLite in data directory
        basedir = os.path.abspath(os.path.dirname(__file__))
        db_dir = os.path.join(basedir, 'data')
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
        db_path = os.path.join(db_dir, 'makiwafreight.db')
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
        print(f"DATABASE_URL not found, using local SQLite at: {db_path}")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define database models
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    company = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    vehicle_info = db.Column(db.String(200))
    token = db.Column(db.String(36))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Load(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ref = db.Column(db.String(10), nullable=False)
    origin = db.Column(db.String(100), nullable=False)
    destination = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    cargo_type = db.Column(db.String(50), nullable=False)
    weight = db.Column(db.Float, nullable=False)
    notes = db.Column(db.Text)
    shipper_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    shipper = db.relationship('User', backref=db.backref('loads', lazy=True))

class Message(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_email = db.Column(db.String(100), nullable=False)
    recipient_email = db.Column(db.String(100), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AccessControl(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Text)  # JSON string containing access control data

class Banner(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    index = db.Column(db.String(200))
    dashboard = db.Column(db.String(200))

# Helper functions
def check_auth(request):
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return None
    token = token.split(' ')[1]
    return User.query.filter_by(token=token).first()

def get_default_access_control_data():
    return {
        'pages': {
            'post_load': {
                'allowed_roles': ['admin', 'shipper', 'transporter']  # All roles can post loads
            },
            'market': {
                'allowed_roles': ['admin', 'shipper', 'transporter']  # All roles can access market
            }
        },
        'banners': {
            'index': '',
            'dashboard': ''
        },
        'post_loads_enabled': True,  # Global setting to control post loads access
        'user_access': {}  # User-specific access control
    }

def get_access_control():
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
    
    # Ensure pages exists and has the required structure
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
    
    # Ensure banners exists and has the required structure
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

def update_access_control(data):
    ac = AccessControl.query.first()
    if not ac:
        ac = AccessControl()
        db.session.add(ac)
    
    ac.data = json.dumps(data)
    db.session.commit()
    return data

def get_banners():
    ac_data = get_access_control()
    return {
        'index': ac_data.get('banners', {}).get('index', ''),
        'dashboard': ac_data.get('banners', {}).get('dashboard', '')
    }

def update_banners(banners):
    ac_data = get_access_control()
    if 'banners' not in ac_data:
        ac_data['banners'] = {}
    
    ac_data['banners']['index'] = banners.get('index', '')
    ac_data['banners']['dashboard'] = banners.get('dashboard', '')
    
    return update_access_control(ac_data)

# Initialize admin user and database
def initialize_data():
    with app.app_context():
        # Check if tables exist by trying to query them
        tables_exist = False
        try:
            # Try to query the User table
            user_count = User.query.count()
            print(f"Database tables exist with {user_count} users")
            tables_exist = True
        except Exception as e:
            print(f"Error querying User table: {e}")
            tables_exist = False
        
        # Only create tables if they don't exist
        if not tables_exist:
            print("Creating database tables...")
            db.create_all()
            print("Database tables created")
        else:
            print("Database tables already exist, skipping table creation")
        
        # Check if admin user exists
        admin_email = 'cyprianmak@gmail.com'
        admin = User.query.filter_by(email=admin_email).first()
        
        if not admin:
            print("Creating admin user...")
            admin = User(
                name="Admin",
                email=admin_email,
                role="admin"
            )
            admin.set_password("Muchandida@1")
            db.session.add(admin)
            db.session.commit()
            print("Admin user created")
        else:
            print("Admin user already exists")
        
        # Check if access control data exists
        ac = AccessControl.query.first()
        if not ac:
            print("Creating access control data...")
            default_data = get_default_access_control_data()
            ac = AccessControl(data=json.dumps(default_data))
            db.session.add(ac)
            db.session.commit()
            print("Access control data created")
        else:
            print("Access control data already exists")

# Debug route to check database status
@app.route('/api/debug/db')
def debug_db():
    try:
        # Check if database file exists (only for SQLite)
        db_exists = False
        file_stats = {}
        
        if 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI']:
            db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
            db_exists = os.path.exists(db_path)
            
            # Get file stats
            if db_exists:
                stat = os.stat(db_path)
                file_stats = {
                    "size": stat.st_size,
                    "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "accessed": datetime.fromtimestamp(stat.st_atime).isoformat()
                }
        
        # Count users
        user_count = User.query.count()
        
        # Count loads
        load_count = Load.query.count()
        
        # Count messages
        message_count = Message.query.count()
        
        # List users
        users = []
        for user in User.query.all():
            users.append({
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role,
                "created_at": user.created_at.isoformat()
            })
        
        return jsonify({
            "database_type": "PostgreSQL" if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI'] else "SQLite",
            "database_uri": app.config['SQLALCHEMY_DATABASE_URI'],
            "database_exists": db_exists,
            "file_stats": file_stats,
            "user_count": user_count,
            "load_count": load_count,
            "message_count": message_count,
            "users": users,
            "environment": os.environ.get('RENDER', 'local')
        })
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

# Backup and restore endpoints
@app.route('/api/admin/backup', methods=['POST'])
def backup_data():
    try:
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        
        # Create backup directory if it doesn't exist
        backup_dir = '/opt/render/project/.render/backups'
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        # Generate backup filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI']:
            # PostgreSQL backup
            backup_path = os.path.join(backup_dir, f'makiwafreight_backup_{timestamp}.sql')
            # Extract database connection info from DATABASE_URL
            db_url = app.config['SQLALCHEMY_DATABASE_URI']
            # Use pg_dump to create a backup
            import subprocess
            subprocess.run(['pg_dump', db_url, '-f', backup_path], check=True)
        else:
            # SQLite backup
            backup_path = os.path.join(backup_dir, f'makiwafreight_backup_{timestamp}.db')
            # Copy the database file
            import shutil
            db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
            shutil.copy2(db_path, backup_path)
        
        return jsonify({
            "success": True,
            "message": "Backup created successfully",
            "data": {
                "backup_path": backup_path,
                "timestamp": timestamp
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Backup failed",
            "error": str(e)
        }), 500

@app.route('/api/admin/restore', methods=['POST'])
def restore_data():
    try:
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        
        data = request.get_json()
        backup_file = data.get('backup_file')
        
        if not backup_file:
            return jsonify({
                "success": False,
                "message": "Backup file is required",
                "error": "Please provide a backup file path"
            }), 400
        
        # Check if backup file exists
        if not os.path.exists(backup_file):
            return jsonify({
                "success": False,
                "message": "Backup file not found",
                "error": f"Backup file {backup_file} does not exist"
            }), 404
        
        # Close all database connections
        db.session.remove()
        
        if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI']:
            # PostgreSQL restore
            db_url = app.config['SQLALCHEMY_DATABASE_URI']
            # Use psql to restore the database
            import subprocess
            subprocess.run(['psql', db_url, '-f', backup_file], check=True)
        else:
            # SQLite restore
            import shutil
            db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
            shutil.copy2(backup_file, db_path)
        
        # Reinitialize the database
        initialize_data()
        
        return jsonify({
            "success": True,
            "message": "Data restored successfully",
            "data": {
                "backup_file": backup_file
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Restore failed",
            "error": str(e)
        }), 500

@app.route('/api/admin/list-backups', methods=['GET'])
def list_backups():
    try:
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        
        backup_dir = '/opt/render/project/.render/backups'
        backups = []
        
        if os.path.exists(backup_dir):
            for filename in os.listdir(backup_dir):
                if filename.startswith('makiwafreight_backup_'):
                    file_path = os.path.join(backup_dir, filename)
                    stat = os.stat(file_path)
                    backups.append({
                        "filename": filename,
                        "path": file_path,
                        "size": stat.st_size,
                        "created": datetime.fromtimestamp(stat.st_ctime).isoformat()
                    })
        
        # Sort backups by creation time (newest first)
        backups.sort(key=lambda x: x['created'], reverse=True)
        
        return jsonify({
            "success": True,
            "message": "Backups retrieved",
            "data": {
                "backups": backups
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Failed to retrieve backups",
            "error": str(e)
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
                "admin_banners": "/api/admin/banners",
                "admin_access_control": "/api/admin/access-control",
                "debug_db": "/api/debug/db",
                "admin_backup": "/api/admin/backup",
                "admin_restore": "/api/admin/restore",
                "admin_list_backups": "/api/admin/list-backups"
            },
            "status": "running",
            "version": "1.0.0"
        }
    })

@app.route('/api/health')
def health():
    return jsonify({
        "success": True,
        "message": "Service is healthy",
        "data": {"status": "healthy"}
    })

# Auth endpoints
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'user')  # Default role
        
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
        
        # Create new user
        new_user = User(
            name=name,
            email=email,
            role=role
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
                    "role": new_user.role
                }
            }
        }), 201
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Registration failed",
            "error": str(e)
        }), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
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
                        "role": user.role
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
        return jsonify({
            "success": False,
            "message": "Login failed",
            "error": str(e)
        }), 500

# Get current user endpoint
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

# Update current user endpoint
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
        
        # Update fields if provided
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
                    "vehicle_info": user.vehicle_info
                }
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Profile update failed",
            "error": str(e)
        }), 500

# Admin banners endpoints
@app.route('/api/admin/banners', methods=['GET'])
def get_admin_banners():
    try:
        # Check if user is admin
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
        # Check if user is admin
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "Admin access required"
            }), 403
        
        data = request.get_json()
        
        if 'index' not in data or 'dashboard' not in data:
            return jsonify({
                "success": False,
                "message": "Update failed",
                "error": "Both index and dashboard banners are required"
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

# Admin access control endpoints
@app.route('/api/admin/access-control', methods=['GET'])
def get_admin_access_control():
    try:
        # Check if user is admin
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
        # Check if user is admin
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

# Load endpoints
@app.route('/api/loads', methods=['GET', 'POST'])
def handle_loads():
    try:
        user = check_auth(request)
        
        # Get all loads (public access)
        if request.method == 'GET':
            loads = Load.query.filter(Load.expires_at >= datetime.utcnow()).all()
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
                    "shipper": load.shipper.name if load.shipper else None,
                    "expires_at": load.expires_at.isoformat(),
                    "created_at": load.created_at.isoformat()
                })
            return jsonify({
                "success": True,
                "message": "Loads retrieved",
                "data": {"loads": result}
            })
        
        # Create new load (requires authentication)
        if request.method == 'POST':
            if not user:
                return jsonify({
                    "success": False,
                    "message": "Authentication required",
                    "error": "Please login to post loads"
                }), 401
            
            data = request.get_json()
            required_fields = ['ref', 'origin', 'destination', 'date', 'cargo_type', 'weight']
            for field in required_fields:
                if field not in data:
                    return jsonify({
                        "success": False,
                        "message": "Load creation failed",
                        "error": f"Missing field: {field}"
                    }), 400
            
            # Set expiration date (7 days from creation)
            expires_at = datetime.utcnow() + timedelta(days=7)
            
            new_load = Load(
                ref=data['ref'],
                origin=data['origin'],
                destination=data['destination'],
                date=data['date'],
                cargo_type=data['cargo_type'],
                weight=data['weight'],
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
        return jsonify({
            "success": False,
            "message": "Operation failed",
            "error": str(e)
        }), 500

# Update load endpoint
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
        
        load = Load.query.get(load_id)
        if not load:
            return jsonify({
                "success": False,
                "message": "Load not found",
                "error": "Load does not exist"
            }), 404
        
        # Only the shipper who posted the load can update it
        if load.shipper_id != user.id:
            return jsonify({
                "success": False,
                "message": "Access denied",
                "error": "You can only update your own loads"
            }), 403
        
        data = request.get_json()
        
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
            load.weight = data['weight']
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
        return jsonify({
            "success": False,
            "message": "Failed to update load",
            "error": str(e)
        }), 500

# Delete load endpoint
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
        
        load = Load.query.get(load_id)
        if not load:
            return jsonify({
                "success": False,
                "message": "Load not found",
                "error": "Load does not exist"
            }), 404
        
        # Only the shipper who posted the load can delete it
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
        
        # Get user's messages
        if request.method == 'GET':
            messages = Message.query.filter(
                (Message.sender_email == user.email) | 
                (Message.recipient_email == user.email)
            ).order_by(Message.created_at.desc()).all()
            
            result = []
            for msg in messages:
                result.append({
                    "id": msg.id,
                    "sender": msg.sender_email,
                    "recipient": msg.recipient_email,
                    "body": msg.body,
                    "created_at": msg.created_at.isoformat()
                })
            return jsonify({
                "success": True,
                "message": "Messages retrieved",
                "data": {"messages": result}
            })
        
        # Send a new message
        if request.method == 'POST':
            data = request.get_json()
            recipient = data.get('recipient')
            body = data.get('body')
            
            if not recipient or not body:
                return jsonify({
                    "success": False,
                    "message": "Message not sent",
                    "error": "Recipient and message body required"
                }), 400
            
            # Verify recipient exists
            if not User.query.filter_by(email=recipient).first():
                return jsonify({
                    "success": False,
                    "message": "Message not sent",
                    "error": "Recipient not found"
                }), 404
            
            new_message = Message(
                sender_email=user.email,
                recipient_email=recipient,
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
        return jsonify({
            "success": False,
            "message": "Message operation failed",
            "error": str(e)
        }), 500

# User management (admin only)
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

# Delete user endpoint
@app.route('/api/users/<email>', methods=['DELETE'])
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
        
        # Delete user's loads and messages
        Load.query.filter_by(shipper_id=user_to_delete.id).delete()
        Message.query.filter(
            (Message.sender_email == user_to_delete.email) | 
            (Message.recipient_email == user_to_delete.email)
        ).delete()
        
        db.session.delete(user_to_delete)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "User deleted successfully",
            "data": {"email": email}
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Failed to delete user",
            "error": str(e)
        }), 500

# Reset password endpoint
@app.route('/api/admin/reset-password', methods=['POST'])
def reset_password_endpoint():
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
        new_password = data.get('password')
        
        if not email or not new_password:
            return jsonify({
                "success": False,
                "message": "Reset failed",
                "error": "Email and password are required"
            }), 400
        
        user_to_update = User.query.filter_by(email=email).first()
        if not user_to_update:
            return jsonify({
                "success": False,
                "message": "User not found",
                "error": "User does not exist"
            }), 404
        
        user_to_update.set_password(new_password)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Password reset successfully",
            "data": {"email": email}
        })
except Exception as e:
        return jsonify({
            "success": False,
            "message": "Failed to reset password",
            "error": str(e)
        }), 500

# Initialize data and run app
print("Initializing application...")
initialize_data()
print("Application initialized")

# Run the app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
