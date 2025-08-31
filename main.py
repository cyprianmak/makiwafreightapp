from flask import Flask, render_template, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import uuid
import json
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///makiwafreight.db'
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

def get_access_control():
    ac = AccessControl.query.first()
    if not ac:
        # Initialize with empty structure (removed post and market)
        ac = AccessControl(data=json.dumps({
            'pages': {},
            'banners': {
                'index': '',
                'dashboard': ''
            }
        }))
        db.session.add(ac)
        db.session.commit()
    
    return json.loads(ac.data)

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
        db.create_all()
        
        admin_email = 'cyprianmak@gmail.com'
        admin_password = 'Muchandida@1'
        admin = User.query.filter_by(email=admin_email).first()
        
        if not admin:
            admin = User(
                name="Admin",
                email=admin_email,
                role="admin"
            )
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()

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
                "admin_access_control": "/api/admin/access-control"
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
        
        # Create new load (requires authentication and shipper role)
        if request.method == 'POST':
            if not user:
                return jsonify({
                    "success": False,
                    "message": "Authentication required",
                    "error": "Please login to post loads"
                }), 401
            if user.role != 'shipper':
                return jsonify({
                    "success": False,
                    "message": "Access denied",
                    "error": "Only shippers can post loads"
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
initialize_data()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
