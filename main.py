from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import jwt
import datetime
import secrets
import hashlib
import uuid
import os
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')

# In-memory database (for demo purposes)
# In production, you'd use a real database
users_db = {}
loads_db = {}
messages_db = {}
access_control_db = {
    "post": {},
    "market": {},
    "pages": {},
    "banners": {"index": "", "dashboard": ""}
}

# Admin credentials
ADMIN_EMAIL = "cyprianmak@gmail.com"
ADMIN_PASS = "Muchandida@1"

# Create admin user if not exists
if ADMIN_EMAIL not in users_db:
    users_db[ADMIN_EMAIL] = {
        "id": str(uuid.uuid4()),
        "name": "Admin",
        "email": ADMIN_EMAIL,
        "password": hashlib.sha256(ADMIN_PASS.encode()).hexdigest(),
        "role": "admin",
        "company": "MakiwaFreight",
        "phone": "",
        "address": "",
        "vehicle_info": "",
        "created_at": datetime.datetime.now().isoformat(),
        "updated_at": datetime.datetime.now().isoformat()
    }
    access_control_db["post"][ADMIN_EMAIL] = True
    access_control_db["market"][ADMIN_EMAIL] = True
    access_control_db["pages"][ADMIN_EMAIL] = {}

# Helper functions
def generate_load_ref():
    return ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(6))

def calculate_expiry_date():
    expiry_date = datetime.datetime.now() + datetime.timedelta(days=7)
    return expiry_date.isoformat()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Bearer token malformed'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users_db.get(data['email'])
            if not current_user:
                return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        current_user = kwargs.get('current_user')
        if not current_user or current_user.get('role') != 'admin':
            return jsonify({'message': 'Admin access required!'}), 403
        return f(*args, **kwargs)
    return decorated

# Root endpoint
@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'message': 'Welcome to MakiwaFreight API',
        'version': '1.0.0',
        'status': 'running',
        'endpoints': {
            'auth': '/api/auth/login',
            'users': '/api/users',
            'loads': '/api/loads',
            'messages': '/api/messages',
            'health': '/api/health'
        }
    })

# Auth endpoints
@app.route('/api/auth/login', methods=['POST'])
def login():
    auth = request.json
    if not auth or not auth.get('email') or not auth.get('password'):
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm="Login required!"'}
        )
    
    email = auth['email'].lower()
    user = users_db.get(email)
    
    if not user or user['password'] != hashlib.sha256(auth['password'].encode()).hexdigest():
        return jsonify({'message': 'Invalid credentials'}), 401
    
    # Generate token
    token = jwt.encode({
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'])
    
    # Store token with user
    user['token'] = token
    
    # Return user without password
    user_response = user.copy()
    user_response.pop('password', None)
    
    return jsonify({
        'access_token': token,
        'token_type': 'bearer',
        'user': user_response
    })

@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.json
    
    if not data or not data.get('name') or not data.get('email') or not data.get('password') or not data.get('phone') or not data.get('role'):
        return jsonify({'message': 'Missing required fields'}), 400
    
    email = data['email'].lower()
    
    if email in users_db:
        return jsonify({'message': 'Email already registered'}), 400
    
    user_id = str(uuid.uuid4())
    now = datetime.datetime.now().isoformat()
    
    user = {
        "id": user_id,
        "name": data['name'],
        "email": email,
        "password": hashlib.sha256(data['password'].encode()).hexdigest(),
        "role": data['role'],
        "company": data.get('company'),
        "phone": data['phone'],
        "address": data.get('address'),
        "vehicle_info": data.get('vehicle_info'),
        "created_at": now,
        "updated_at": now
    }
    
    users_db[email] = user
    
    # Set default access
    if data['role'] == "shipper":
        access_control_db["post"][email] = True
    if data['role'] == "transporter":
        access_control_db["market"][email] = True
    
    # Initialize page access
    access_control_db["pages"][email] = {}
    
    # Return user without password
    user_response = user.copy()
    user_response.pop('password', None)
    
    return jsonify(user_response), 201

@app.route('/api/users/me', methods=['GET'])
@token_required
def get_current_user_info(current_user):
    user_response = current_user.copy()
    user_response.pop('password', None)
    return jsonify(user_response)

@app.route('/api/users/<user_id>', methods=['PUT'])
@token_required
def update_user(user_id, current_user):
    data = request.json
    
    # Find user by email (since we use email as key)
    user_email = None
    for email, user in users_db.items():
        if user["id"] == user_id:
            user_email = email
            break
    
    if not user_email:
        return jsonify({'message': 'User not found'}), 404
    
    # Only allow updating specific fields
    allowed_fields = ["name", "phone", "address", "password"]
    for field in data:
        if field in allowed_fields:
            if field == "password":
                users_db[user_email][field] = hashlib.sha256(data[field].encode()).hexdigest()
            else:
                users_db[user_email][field] = data[field]
    
    users_db[user_email]["updated_at"] = datetime.datetime.now().isoformat()
    
    # Return user without password
    user_response = users_db[user_email].copy()
    user_response.pop('password', None)
    
    return jsonify(user_response)

# Load endpoints
@app.route('/api/loads', methods=['POST'])
@token_required
def create_load(current_user):
    data = request.json
    
    # Check if user has permission to post
    if not access_control_db["post"].get(current_user["email"]):
        return jsonify({'message': "You don't have permission to post loads"}), 403
    
    if not data or not data.get('origin') or not data.get('destination') or not data.get('date') or not data.get('cargo_type') or not data.get('weight'):
        return jsonify({'message': 'Missing required fields'}), 400
    
    load_id = str(uuid.uuid4())
    now = datetime.datetime.now().isoformat()
    
    load = {
        "id": load_id,
        "ref": generate_load_ref(),
        "origin": data['origin'],
        "destination": data['destination'],
        "date": data['date'],
        "cargo_type": data['cargo_type'],
        "weight": data['weight'],
        "notes": data.get('notes'),
        "shipper_id": current_user["id"],
        "shipper_email": current_user["email"],
        "created_at": now,
        "updated_at": now,
        "expires_at": calculate_expiry_date(),
        "status": "active"
    }
    
    loads_db[load_id] = load
    return jsonify(load), 201

@app.route('/api/loads', methods=['GET'])
@token_required
def get_loads(current_user):
    origin = request.args.get('origin')
    destination = request.args.get('destination')
    shipper_id = request.args.get('shipper_id')
    
    loads = []
    
    for load_id, load in loads_db.items():
        # Apply filters
        if origin and origin.lower() not in load["origin"].lower():
            continue
        if destination and destination.lower() not in load["destination"].lower():
            continue
        if shipper_id and load["shipper_id"] != shipper_id:
            continue
        
        # Check if load is expired
        if datetime.datetime.fromisoformat(load["expires_at"]) < datetime.datetime.now():
            continue
        
        loads.append(load)
    
    return jsonify(loads)

@app.route('/api/loads/<load_id>', methods=['PUT'])
@token_required
def update_load(load_id, current_user):
    data = request.json
    
    if load_id not in loads_db:
        return jsonify({'message': 'Load not found'}), 404
    
    # Only allow updating specific fields
    allowed_fields = ["origin", "destination", "date", "cargo_type", "weight", "notes"]
    for field in data:
        if field in allowed_fields:
            loads_db[load_id][field] = data[field]
    
    loads_db[load_id]["updated_at"] = datetime.datetime.now().isoformat()
    return jsonify(loads_db[load_id])

@app.route('/api/loads/<load_id>', methods=['DELETE'])
@token_required
def delete_load(load_id, current_user):
    if load_id not in loads_db:
        return jsonify({'message': 'Load not found'}), 404
    
    del loads_db[load_id]
    return jsonify({'message': 'Load deleted successfully'})

# Message endpoints
@app.route('/api/messages', methods=['POST'])
@token_required
def create_message(current_user):
    data = request.json
    
    if not data or not data.get('to') or not data.get('body'):
        return jsonify({'message': 'Missing required fields'}), 400
    
    receiver_email = data['to'].lower()
    
    if receiver_email not in users_db:
        return jsonify({'message': 'Receiver not found'}), 404
    
    message_id = str(uuid.uuid4())
    now = datetime.datetime.now().isoformat()
    
    message = {
        "id": message_id,
        "sender_id": current_user["id"],
        "sender_email": current_user["email"],
        "receiver_id": users_db[receiver_email]["id"],
        "receiver_email": receiver_email,
        "body": data['body'],
        "created_at": now
    }
    
    messages_db[message_id] = message
    return jsonify(message), 201

@app.route('/api/messages', methods=['GET'])
@token_required
def get_messages(current_user):
    messages = []
    
    for message_id, message in messages_db.items():
        if message["receiver_id"] == current_user["id"]:
            messages.append(message)
    
    return jsonify(messages)

@app.route('/api/messages/<message_id>', methods=['DELETE'])
@token_required
def delete_message(message_id, current_user):
    if message_id not in messages_db:
        return jsonify({'message': 'Message not found'}), 404
    
    if messages_db[message_id]["receiver_id"] != current_user["id"]:
        return jsonify({'message': 'You can only delete your own messages'}), 403
    
    del messages_db[message_id]
    return jsonify({'message': 'Message deleted successfully'})

# Admin endpoints
@app.route('/api/admin/users', methods=['GET'])
@token_required
def get_all_users(current_user):
    if current_user["role"] != "admin":
        return jsonify({'message': 'Admin access required'}), 403
    
    users = []
    for email, user in users_db.items():
        user_response = user.copy()
        user_response.pop('password', None)
        users.append(user_response)
    
    return jsonify(users)

@app.route('/api/admin/users/<email>', methods=['DELETE'])
@token_required
def delete_user(email, current_user):
    if current_user["role"] != "admin":
        return jsonify({'message': 'Admin access required'}), 403
    
    if email not in users_db:
        return jsonify({'message': 'User not found'}), 404
    
    # Delete user
    del users_db[email]
    
    # Delete user's loads
    loads_to_delete = [load_id for load_id, load in loads_db.items() if load["shipper_email"] == email]
    for load_id in loads_to_delete:
        del loads_db[load_id]
    
    # Delete user's messages
    messages_to_delete = [
        msg_id for msg_id, msg in messages_db.items() 
        if msg["sender_email"] == email or msg["receiver_email"] == email
    ]
    for msg_id in messages_to_delete:
        del messages_db[msg_id]
    
    # Remove from access control
    if email in access_control_db["post"]:
        del access_control_db["post"][email]
    if email in access_control_db["market"]:
        del access_control_db["market"][email]
    if email in access_control_db["pages"]:
        del access_control_db["pages"][email]
    
    return jsonify({'message': 'User deleted successfully'})

@app.route('/api/admin/reset-password', methods=['POST'])
@token_required
def reset_password(current_user):
    data = request.json
    
    if current_user["role"] != "admin":
        return jsonify({'message': 'Admin access required'}), 403
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields'}), 400
    
    email = data['email']
    
    if email not in users_db:
        return jsonify({'message': 'User not found'}), 404
    
    users_db[email]["password"] = hashlib.sha256(data['password'].encode()).hexdigest()
    users_db[email]["updated_at"] = datetime.datetime.now().isoformat()
    
    return jsonify({'message': 'Password reset successfully'})

@app.route('/api/admin/banners', methods=['GET'])
@token_required
def get_banners(current_user):
    if current_user["role"] != "admin":
        return jsonify({'message': 'Admin access required'}), 403
    
    return jsonify(access_control_db["banners"])

@app.route('/api/admin/banners', methods=['PUT'])
@token_required
def update_banners(current_user):
    if current_user["role"] != "admin":
        return jsonify({'message': 'Admin access required'}), 403
    
    data = request.json
    
    if not data or 'index' not in data or 'dashboard' not in data:
        return jsonify({'message': 'Missing required fields'}), 400
    
    access_control_db["banners"] = {
        "index": data['index'],
        "dashboard": data['dashboard']
    }
    
    return jsonify(access_control_db["banners"])

@app.route('/api/admin/access-control', methods=['GET'])
@token_required
def get_access_control(current_user):
    if current_user["role"] != "admin":
        return jsonify({'message': 'Admin access required'}), 403
    
    return jsonify(access_control_db)

@app.route('/api/admin/access-control', methods=['PUT'])
@token_required
def update_access_control(current_user):
    if current_user["role"] != "admin":
        return jsonify({'message': 'Admin access required'}), 403
    
    data = request.json
    
    if not data or 'post' not in data or 'market' not in data or 'pages' not in data:
        return jsonify({'message': 'Missing required fields'}), 400
    
    access_control_db["post"] = data['post']
    access_control_db["market"] = data['market']
    access_control_db["pages"] = data['pages']
    
    return jsonify(access_control_db)

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
