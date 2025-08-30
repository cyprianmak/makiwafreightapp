from flask import Flask, render_template, jsonify, request
import os
from datetime import datetime, timedelta
import uuid

app = Flask(__name__)

# In-memory data storage (for demo purposes)
users = {}
loads = {}
messages = {}
access_control = {
    'post': {},
    'market': {},
    'pages': {}
}
banners = {
    'index': '',
    'dashboard': ''
}

# Helper functions
def generate_token():
    return str(uuid.uuid4())

def check_auth(request):
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return None
    token = token.split(' ')[1]
    for user_id, user in users.items():
        if user.get('token') == token:
            return user
    return None

# Initialize admin user
def initialize_data():
    admin_email = 'cyprianmak@gmail.com'
    admin_password = 'Muchandida@1'
    admin_exists = False
    for u in users.values():
        if u['email'] == admin_email:
            admin_exists = True
            break
    
    if not admin_exists:
        admin_id = str(uuid.uuid4())
        users[admin_id] = {
            "id": admin_id,
            "name": "Admin",
            "email": admin_email,
            "password": admin_password,
            "role": "admin",
            "company": "",
            "phone": "",
            "address": "",
            "vehicle_info": "",
            "created_at": datetime.now().isoformat()
        }

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api')
def api_info():
    return jsonify({
        "endpoints": {
            "auth": "/api/auth/login",
            "health": "/api/health",
            "loads": "/api/loads",
            "messages": "/api/messages",
            "users": "/api/users"
        },
        "message": "Welcome to MakiwaFreight API",
        "status": "running",
        "version": "1.0.0"
    })

@app.route('/api/health')
def health():
    return jsonify({"status": "healthy"})

# Auth endpoints
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = None
    for u in users.values():
        if u['email'] == email and u['password'] == password:
            user = u
            break

    if user:
        token = generate_token()
        user['token'] = token
        return jsonify({
            "token": token,
            "user": {
                "id": user['id'],
                "name": user['name'],
                "email": user['email'],
                "role": user['role']
            }
        })
    else:
        return jsonify({"message": "Invalid credentials"}), 401

# User endpoints
@app.route('/api/users', methods=['GET'])
def get_users():
    user = check_auth(request)
    if not user or user['role'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 401

    user_list = []
    for u in users.values():
        user_list.append({
            "id": u['id'],
            "name": u['name'],
            "email": u['email'],
            "role": u['role']
        })
    return jsonify(user_list)

@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.get_json()
    required_fields = ['name', 'email', 'password', 'role']
    for field in required_fields:
        if field not in data:
            return jsonify({"message": f"Missing field: {field}"}), 400

    for u in users.values():
        if u['email'] == data['email']:
            return jsonify({"message": "Email already exists"}), 400

    user_id = str(uuid.uuid4())
    users[user_id] = {
        "id": user_id,
        "name": data['name'],
        "email": data['email'],
        "password": data['password'],
        "role": data['role'],
        "company": data.get('company', ''),
        "phone": data.get('phone', ''),
        "address": data.get('address', ''),
        "vehicle_info": data.get('vehicle_info', ''),
        "created_at": datetime.now().isoformat()
    }
    return jsonify({"id": user_id}), 201

@app.route('/api/users/me', methods=['GET'])
def get_current_user():
    user = check_auth(request)
    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    return jsonify({
        "id": user['id'],
        "name": user['name'],
        "email": user['email'],
        "role": user['role'],
        "company": user.get('company', ''),
        "phone": user.get('phone', ''),
        "address": user.get('address', ''),
        "vehicle_info": user.get('vehicle_info', ''),
        "created_at": user['created_at']
    })

@app.route('/api/users/<user_id>', methods=['PUT'])
def update_user(user_id):
    user = check_auth(request)
    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    if user['id'] != user_id and user['role'] != 'admin':
        return jsonify({"message": "Forbidden"}), 403

    target_user = users.get(user_id)
    if not target_user:
        return jsonify({"message": "User not found"}), 404

    data = request.get_json()
    allowed_fields = ['name', 'phone', 'address', 'password']
    for field in allowed_fields:
        if field in data:
            target_user[field] = data[field]

    return jsonify({"message": "User updated"})

# Load endpoints
@app.route('/api/loads', methods=['GET'])
def get_loads():
    user = check_auth(request)
    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    origin = request.args.get('origin')
    destination = request.args.get('destination')
    shipper_id = request.args.get('shipper_id')

    load_list = []
    for load in loads.values():
        if shipper_id and load['shipper_id'] != shipper_id:
            continue
        if origin and origin.lower() not in load['origin'].lower():
            continue
        if destination and destination.lower() not in load['destination'].lower():
            continue
        load_list.append(load)

    return jsonify(load_list)

@app.route('/api/loads', methods=['POST'])
def create_load():
    user = check_auth(request)
    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    data = request.get_json()
    required_fields = ['origin', 'destination', 'date', 'cargo_type', 'weight']
    for field in required_fields:
        if field not in data:
            return jsonify({"message": f"Missing field: {field}"}), 400

    load_id = str(uuid.uuid4())
    expiry_date = datetime.now() + timedelta(days=7)
    loads[load_id] = {
        "id": load_id,
        "ref": f"LD{len(loads)+1:04d}",
        "origin": data['origin'],
        "destination": data['destination'],
        "date": data['date'],
        "cargo_type": data['cargo_type'],
        "weight": data['weight'],
        "notes": data.get('notes', ''),
        "shipper_id": user['id'],
        "shipper_email": user['email'],
        "expires_at": expiry_date.isoformat(),
        "created_at": datetime.now().isoformat()
    }
    return jsonify({"id": load_id}), 201

@app.route('/api/loads/<load_id>', methods=['PUT'])
def update_load(load_id):
    user = check_auth(request)
    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    load = loads.get(load_id)
    if not load:
        return jsonify({"message": "Load not found"}), 404

    if load['shipper_id'] != user['id'] and user['role'] != 'admin':
        return jsonify({"message": "Forbidden"}), 403

    data = request.get_json()
    allowed_fields = ['origin', 'destination', 'date', 'cargo_type', 'weight', 'notes']
    for field in allowed_fields:
        if field in data:
            load[field] = data[field]

    return jsonify({"message": "Load updated"})

@app.route('/api/loads/<load_id>', methods=['DELETE'])
def delete_load(load_id):
    user = check_auth(request)
    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    load = loads.get(load_id)
    if not load:
        return jsonify({"message": "Load not found"}), 404

    if load['shipper_id'] != user['id'] and user['role'] != 'admin':
        return jsonify({"message": "Forbidden"}), 403

    del loads[load_id]
    return jsonify({"message": "Load deleted"})

# Message endpoints
@app.route('/api/messages', methods=['GET'])
def get_messages():
    user = check_auth(request)
    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    message_list = []
    for msg in messages.values():
        if msg['sender_email'] == user['email'] or msg['recipient_email'] == user['email']:
            message_list.append(msg)

    return jsonify(message_list)

@app.route('/api/messages', methods=['POST'])
def send_message():
    user = check_auth(request)
    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    data = request.get_json()
    required_fields = ['to', 'body']
    for field in required_fields:
        if field not in data:
            return jsonify({"message": f"Missing field: {field}"}), 400

    message_id = str(uuid.uuid4())
    messages[message_id] = {
        "id": message_id,
        "sender_email": user['email'],
        "recipient_email": data['to'],
        "body": data['body'],
        "created_at": datetime.now().isoformat()
    }
    return jsonify({"id": message_id}), 201

@app.route('/api/messages/<message_id>', methods=['DELETE'])
def delete_message(message_id):
    user = check_auth(request)
    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    msg = messages.get(message_id)
    if not msg:
        return jsonify({"message": "Message not found"}), 404

    if msg['sender_email'] != user['email'] and msg['recipient_email'] != user['email']:
        return jsonify({"message": "Forbidden"}), 403

    del messages[message_id]
    return jsonify({"message": "Message deleted"})

# Admin endpoints
@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    user = check_auth(request)
    if not user or user['role'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 401

    user_list = []
    for u in users.values():
        user_list.append({
            "id": u['id'],
            "name": u['name'],
            "email": u['email'],
            "role": u['role']
        })
    return jsonify(user_list)

@app.route('/api/admin/users/<email>', methods=['DELETE'])
def admin_delete_user(email):
    user = check_auth(request)
    if not user or user['role'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 401

    target_user = None
    for u in users.values():
        if u['email'] == email:
            target_user = u
            break

    if not target_user:
        return jsonify({"message": "User not found"}), 404

    del users[target_user['id']]
    loads_to_delete = [load_id for load_id, load in loads.items() if load['shipper_id'] == target_user['id']]
    for load_id in loads_to_delete:
        del loads[load_id]
    messages_to_delete = [msg_id for msg_id, msg in messages.items() if msg['sender_email'] == target_user['email'] or msg['recipient_email'] == target_user['email']]
    for msg_id in messages_to_delete:
        del messages[msg_id]

    return jsonify({"message": "User deleted"})

@app.route('/api/admin/reset-password', methods=['POST'])
def admin_reset_password():
    user = check_auth(request)
    if not user or user['role'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 401

    data = request.get_json()
    email = data.get('email')
    new_password = data.get('password')

    if not email or not new_password:
        return jsonify({"message": "Email and password are required"}), 400

    target_user = None
    for u in users.values():
        if u['email'] == email:
            target_user = u
            break

    if not target_user:
        return jsonify({"message": "User not found"}), 404

    target_user['password'] = new_password
    return jsonify({"message": "Password reset"})

@app.route('/api/admin/banners', methods=['GET'])
def admin_get_banners():
    user = check_auth(request)
    if not user or user['role'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 401

    return jsonify(banners)

@app.route('/api/admin/banners', methods=['PUT'])
def admin_update_banners():
    user = check_auth(request)
    if not user or user['role'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 401

    data = request.get_json()
    if 'index' in data:
        banners['index'] = data['index']
    if 'dashboard' in data:
        banners['dashboard'] = data['dashboard']

    return jsonify(banners)

@app.route('/api/admin/access-control', methods=['GET'])
def admin_get_access_control():
    user = check_auth(request)
    if not user or user['role'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 401

    return jsonify(access_control)

@app.route('/api/admin/access-control', methods=['PUT'])
def admin_update_access_control():
    user = check_auth(request)
    if not user or user['role'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 401

    data = request.get_json()
    if 'post' in data:
        access_control['post'] = data['post']
    if 'market' in data:
        access_control['market'] = data['market']
    if 'pages' in data:
        access_control['pages'] = data['pages']

    return jsonify(access_control)

# Initialize data and run app
initialize_data()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
