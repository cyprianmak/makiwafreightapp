from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid
import json
import os
from sqlalchemy import text

app = Flask(__name__)

# Configure database properly for Render PostgreSQL
if os.environ.get('RENDER'):
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        # Fix old postgres:// URLs
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        print(f"✅ Using PostgreSQL database at: {database_url}")
    else:
        # Fallback to persistent SQLite if DATABASE_URL not found
        persistent_dir = '/opt/render/project/.render/data'
        os.makedirs(persistent_dir, exist_ok=True)
        db_path = os.path.join(persistent_dir, 'makiwafreight.db')
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
        print(f"⚠️ DATABASE_URL not found, using SQLite fallback at: {db_path}")
else:
    # Local development: check for DATABASE_URL first, else fallback to SQLite
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        print(f"✅ Using local PostgreSQL database at: {database_url}")
    else:
        basedir = os.path.abspath(os.path.dirname(__file__))
        db_dir = os.path.join(basedir, 'data')
        os.makedirs(db_dir, exist_ok=True)
        db_path = os.path.join(db_dir, 'makiwafreight.db')
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
        print(f"⚙️ Using local SQLite at: {db_path}")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Add this function to check if a column exists in a table
def column_exists(table_name, column_name):
    try:
        if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI']:
            # For PostgreSQL
            result = db.session.execute(text(f"""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = '{table_name}' AND column_name = '{column_name}'
            """))
        else:
            # For SQLite
            result = db.session.execute(text(f"PRAGMA table_info({table_name})"))
            columns = [row[1] for row in result]
            return column_name in columns
        
        return result.rowcount > 0
    except Exception as e:
        print(f"Error checking if column exists: {e}")
        return False

# Add this function to add the membership_number column if it doesn't exist
def add_membership_number_column():
    try:
        # Close any existing transactions
        db.session.rollback()
        
        if not column_exists('user', 'membership_number'):
            print("Adding membership_number column to user table...")
            if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI']:
                # For PostgreSQL - add column without unique constraint first
                db.session.execute(text("""
                    ALTER TABLE "user" 
                    ADD COLUMN membership_number VARCHAR(20)
                """))
                db.session.commit()
                print("membership_number column added successfully (without unique constraint)")
                
                # Now update all existing users with unique membership numbers
                users = db.session.execute(text("SELECT id FROM \"user\"")).fetchall()
                for i, user in enumerate(users):
                    membership_num = f"MF{str(i+1).zfill(6)}"
                    db.session.execute(text(f"""
                        UPDATE "user" 
                        SET membership_number = '{membership_num}' 
                        WHERE id = '{user[0]}'
                    """))
                db.session.commit()
                print("Updated existing users with membership numbers")
                
                # Now add the unique constraint
                db.session.execute(text("""
                    ALTER TABLE "user" 
                    ADD CONSTRAINT user_membership_number_key UNIQUE (membership_number)
                """))
                db.session.commit()
                print("Added unique constraint to membership_number column")
                
                # Finally, make the column NOT NULL
                db.session.execute(text("""
                    ALTER TABLE "user" 
                    ALTER COLUMN membership_number SET NOT NULL
                """))
                db.session.commit()
                print("Made membership_number column NOT NULL")
            else:
                # For SQLite
                db.session.execute(text("""
                    ALTER TABLE "user" 
                    ADD COLUMN membership_number VARCHAR(20)
                """))
                db.session.commit()
                print("membership_number column added successfully")
                
                # Update all existing users with unique membership numbers
                users = db.session.execute(text("SELECT id FROM user")).fetchall()
                for i, user in enumerate(users):
                    membership_num = f"MF{str(i+1).zfill(6)}"
                    db.session.execute(text(f"""
                        UPDATE user 
                        SET membership_number = '{membership_num}' 
                        WHERE id = '{user[0]}'
                    """))
                db.session.commit()
                print("Updated existing users with membership numbers")
        else:
            print("membership_number column already exists")
    except Exception as e:
        print(f"Error adding membership_number column: {e}")
        db.session.rollback()

# Add debug route after initializing database
@app.route("/api/debug/db")
def debug_db():
    try:
        # First, test basic database connection
        db.session.execute(text("SELECT 1"))
        db.session.commit()
        connection_status = "OK"
    except Exception as e:
        db.session.rollback()
        connection_status = "ERROR"
        connection_error = str(e)

    # Now gather detailed database information
    try:
        # Check if database file exists (only for SQLite)
        db_exists = False
        file_stats = {}
        db_path = None
        
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
        
        # Count records in each table
        user_count = User.query.count()
        load_count = Load.query.count()
        message_count = Message.query.count()
        access_control_count = AccessControl.query.count()
        banner_count = Banner.query.count()
        user_access_control_count = UserAccessControl.query.count()
        
        # List users
        users = []
        for user in User.query.all():
            users.append({
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role,
                "membership_number": getattr(user, 'membership_number', None),
                "created_at": user.created_at.isoformat()
            })
        
        # Get database type
        database_type = "PostgreSQL" if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI'] else "SQLite"
        
        # Prepare response
        response = {
            "database_type": database_type,
            "database_uri": app.config['SQLALCHEMY_DATABASE_URI'],
            "database_path": db_path,
            "database_exists": db_exists,
            "file_stats": file_stats,
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
        return jsonify({
            "database_type": db.engine.name if hasattr(db, 'engine') else "Unknown",
            "connection_status": "ERROR",
            "error": str(e)
        }), 500

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
    membership_number = db.Column(db.String(20), unique=True, nullable=False)  # Added for membership numbers
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
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_email = db.Column(db.String(100), nullable=False)
    recipient_email = db.Column(db.String(100), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            "id": self.id,
            "sender_email": self.sender_email,
            "recipient_email": self.recipient_email,
            "body": self.body,
            "created_at": self.created_at.isoformat()
        }

class AccessControl(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Text)  # JSON string containing access control data

class UserAccessControl(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    pages = db.Column(db.Text)  # JSON string containing page access data
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('access_controls', lazy=True))

class Banner(db.Model):
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
    except Exception:
        # If anything goes wrong (e.g., table doesn't exist yet), start from 1
        return f"MF000001"

# Helper function to ensure all users have a membership number
def ensure_membership_numbers():
    """
    Checks for users without a membership number and assigns them one.
    This is a one-time migration helper.
    """
    try:
        print("Checking for users without membership numbers...")
        # This query works even if the column doesn't exist yet, it will just fail gracefully
        users_without_membership = User.query.filter(
            (User.membership_number.is_(None)) | (User.membership_number == '')
        ).all()
        
        if users_without_membership:
            print(f"Found {len(users_without_membership)} users without membership numbers. Assigning...")
            for user in users_without_membership:
                user.membership_number = generate_membership_number()
            db.session.commit()
            print("Membership numbers assigned successfully.")
        else:
            print("All users have membership numbers.")
    except Exception as e:
        print(f"Could not update membership numbers (this is ok on first run): {e}")
        db.session.rollback()

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

# Add this function to create tables if they don't exist
def create_tables():
    with app.app_context():
        # Close any existing transactions
        db.session.rollback()
        
        # Check if tables exist by trying to query them
        tables_exist = False
        try:
            # Try to query User table
            user_count = db.session.execute(text("SELECT COUNT(*) FROM \"user\"")).scalar()
            print(f"Database tables exist with {user_count} users")
            tables_exist = True
        except Exception as e:
            print(f"Error querying User table (this is ok on first run): {e}")
            tables_exist = False
        
        # Only create tables if they don't exist
        if not tables_exist:
            print("Creating database tables...")
            db.create_all()
            db.session.commit()
            print("Database tables created")
        else:
            print("Database tables already exist, skipping table creation")
        
        # Check if user_access_control table exists
        try:
            user_access_count = UserAccessControl.query.count()
            print(f"User access control table exists with {user_access_count} records")
        except Exception as e:
            print(f"Error checking user_access_control table: {e}")
            # Create table using raw SQL as fallback
            try:
                db.session.execute(text("""
                    CREATE TABLE IF NOT EXISTS user_access_control (
                        id SERIAL PRIMARY KEY,
                        user_id VARCHAR(36) NOT NULL,
                        pages TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """))
                db.session.commit()
                print("User access control table created successfully")
            except Exception as sql_error:
                print(f"Error creating user_access_control table with SQL: {sql_error}")
                # Final fallback - create all tables
                db.create_all()

# Initialize admin user and database
def initialize_data():
    with app.app_context():
        # Close any existing transactions
        db.session.rollback()
        
        # Create tables if they don't exist
        create_tables()
        
        # Add membership_number column if it doesn't exist
        add_membership_number_column()
        
        # Ensure all users have membership numbers
        ensure_membership_numbers()
        
        # Check if admin user exists
        admin_email = 'cyprianmak@gmail.com'
        try:
            admin = User.query.filter_by(email=admin_email).first()
            
            if not admin:
                print("Creating admin user...")
                admin = User(
                    name="Admin",
                    email=admin_email,
                    role="admin",
                    membership_number=generate_membership_number()  # Generate membership number for admin
                )
                admin.set_password("Muchandida@1")
                db.session.add(admin)
                db.session.commit()
                print("Admin user created")
            else:
                print("Admin user already exists")
        except Exception as e:
            print(f"Error checking/creating admin user: {e}")
            db.session.rollback()
        
        # Check if access control data exists
        try:
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
        except Exception as e:
            print(f"Error checking/creating access control data: {e}")
            db.session.rollback()

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
            # For PostgreSQL, use pg_dump
            import subprocess
            backup_path = os.path.join(backup_dir, f'makiwafreight_backup_{timestamp}.sql')
            
            # Extract database connection details from URI
            db_uri = app.config['SQLALCHEMY_DATABASE_URI']
            # Parse URI to get connection details
            # Format: postgresql://username:password@host:port/database
            uri_parts = db_uri.replace('postgresql://', '').split('@')
            user_pass = uri_parts[0].split(':')
            host_db_port = uri_parts[1].split('/')
            host_port = host_db_port[0].split(':')
            
            username = user_pass[0]
            password = user_pass[1] if len(user_pass) > 1 else ''
            host = host_port[0]
            port = host_port[1] if len(host_port) > 1 else '5432'
            database = host_db_port[1]
            
            # Set password environment variable for pg_dump
            env = os.environ.copy()
            env['PGPASSWORD'] = password
            
            # Run pg_dump command
            subprocess.run([
                'pg_dump',
                '-h', host,
                '-p', port,
                '-U', username,
                '-d', database,
                '-f', backup_path
            ], env=env, check=True)
        else:
            # For SQLite, copy database file
            backup_path = os.path.join(backup_dir, f'makiwafreight_backup_{timestamp}.db')
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
        
        if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI']:
            # For PostgreSQL, use psql to restore
            import subprocess
            
            # Extract database connection details from URI
            db_uri = app.config['SQLALCHEMY_DATABASE_URI']
            # Parse URI to get connection details
            # Format: postgresql://username:password@host:port/database
            uri_parts = db_uri.replace('postgresql://', '').split('@')
            user_pass = uri_parts[0].split(':')
            host_db_port = uri_parts[1].split('/')
            host_port = host_db_port[0].split(':')
            
            username = user_pass[0]
            password = user_pass[1] if len(user_pass) > 1 else ''
            host = host_port[0]
            port = host_port[1] if len(host_port) > 1 else '5432'
            database = host_db_port[1]
            
            # Set password environment variable for psql
            env = os.environ.copy()
            env['PGPASSWORD'] = password
            
            # Run psql command to restore
            subprocess.run([
                'psql',
                '-h', host,
                '-p', port,
                '-U', username,
                '-d', database,
                '-f', backup_file
            ], env=env, check=True)
        else:
            # For SQLite, restore database file
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
                if filename.startswith('makiwafreight_backup_') and (filename.endswith('.db') or filename.endswith('.sql')):
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
                "admin_user_access": "/api/admin/users/<user_id>/access",
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
        
        # Generate unique membership number
        membership_number = generate_membership_number()
        
        # Create new user
        new_user = User(
            name=name,
            email=email,
            role=role,
            membership_number=membership_number  # Add membership number
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
                    "membership_number": new_user.membership_number  # Include in response
                }
            },
            "membership_number": membership_number  # Also include at top level for frontend
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
                        "role": user.role,
                        "membership_number": user.membership_number  # Include in response
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
                    "membership_number": user.membership_number,  # Include in response
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
                    "membership_number": user.membership_number  # Include in response
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

# User-specific access control endpoints
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
        
        # Get user access control settings
        user_access = UserAccessControl.query.filter_by(user_id=user_id).first()
        
        if not user_access:
            # Create default access control for this user if it doesn't exist
            user_access = UserAccessControl(
                user_id=user_id,
                pages=json.dumps({
                    'market': {'enabled': False},
                    'shipper-post': {'enabled': False}
                })
            )
            db.session.add(user_access)
            db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "User access retrieved",
            "data": {
                "user_id": user_id,
                "pages": json.loads(user_access.pages) if user_access else {}
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
                "pages": data['pages']
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Failed to update user access",
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
                    "shipper_name": load.shipper.name if load.shipper else None,
                    "shipper_membership": load.shipper.membership_number if load.shipper else None,
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
            
            # Check if post loads is enabled
            ac_data = get_access_control()
            if not ac_data.get('post_loads_enabled', True):
                return jsonify({
                    "success": False,
                    "message": "Load posting is currently disabled",
                    "error": "Please contact administrator"
                }), 403
            
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
        
        # Only shipper who posted load can update it
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
                "membership_number": u.membership_number,  # Include in response
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
        return jsonify({
            "success": False,
            "message": "Password reset failed",
            "error": str(e)
        }), 500

# Initialize application
if __name__ == '__main__':
    initialize_data()
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
