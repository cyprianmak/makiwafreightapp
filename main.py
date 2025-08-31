from flask import Flask, render_template, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import uuid
import bcrypt
import json

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
    password_hash = db.Column(db.String(100), nullable=False)  # Changed to store hash
    role = db.Column(db.String(20), nullable=False)
    company = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    vehicle_info = db.Column(db.String(200))
    token = db.Column(db.String(36))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

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
    post = db.Column(db.Text)  # JSON string
    market = db.Column(db.Text)  # JSON string
    pages = db.Column(db.Text)  # JSON string

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
        ac = AccessControl(post='{}', market='{}', pages='{}')
        db.session.add(ac)
        db.session.commit()
    
    return {
        'post': json.loads(ac.post),
        'market': json.loads(ac.market),
        'pages': json.loads(ac.pages)
    }

def update_access_control(acl):
    ac = AccessControl.query.first()
    if not ac:
        ac = AccessControl()
        db.session.add(ac)
    
    ac.post = json.dumps(acl.post)
    ac.market = json.dumps(acl.market)
    ac.pages = json.dumps(acl.pages)
    db.session.commit()
    return acl

def get_banners():
    b = Banner.query.first()
    if not b:
        b = Banner(index='', dashboard='')
        db.session.add(b)
        db.session.commit()
    
    return {
        'index': b.index,
        'dashboard': b.dashboard
    }

def update_banners(banners):
    b = Banner.query.first()
    if not b:
        b = Banner()
        db.session.add(b)
    
    b.index = banners.index
    b.dashboard = banners.dashboard
    db.session.commit()
    return banners

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
        "endpoints": {
            "auth": "/api/auth/login",
            "register": "/api/auth/register",
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
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'user')  # Default role
    
    # Validate required fields
    if not name or not email or not password:
        return jsonify({"message": "Missing required fields"}), 400
    
    # Check if user already exists
    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already registered"}), 400
    
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
        "message": "User registered successfully",
        "user": {
            "id": new_user.id,
            "name": new_user.name,
            "email": new_user.email,
            "role": new_user.role
        }
    }), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Email and password required"}), 400

    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        token = str(uuid.uuid4())
        user.token = token
        db.session.commit()
        return jsonify({
            "token": token,
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role
            }
        })
    else:
        return jsonify({"message": "Invalid credentials"}), 401

# Load endpoints
@app.route('/api/loads', methods=['GET', 'POST'])
def handle_loads():
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
        return jsonify(result)
    
    # Create new load (requires authentication and shipper role)
    if request.method == 'POST':
        if not user:
            return jsonify({"message": "Authentication required"}), 401
        if user.role != 'shipper':
            return jsonify({"message": "Only shippers can post loads"}), 403
            
        data = request.get_json()
        required_fields = ['ref', 'origin', 'destination', 'date', 'cargo_type', 'weight']
        for field in required_fields:
            if field not in data:
                return jsonify({"message": f"Missing field: {field}"}), 400
        
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
            "message": "Load created successfully",
            "load": {
                "id": new_load.id,
                "ref": new_load.ref,
                "origin": new_load.origin,
                "destination": new_load.destination,
                "expires_at": new_load.expires_at.isoformat()
            }
        }), 201

# Message endpoints
@app.route('/api/messages', methods=['GET', 'POST'])
def handle_messages():
    user = check_auth(request)
    if not user:
        return jsonify({"message": "Authentication required"}), 401
    
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
        return jsonify(result)
    
    # Send a new message
    if request.method == 'POST':
        data = request.get_json()
        recipient = data.get('recipient')
        body = data.get('body')
        
        if not recipient or not body:
            return jsonify({"message": "Recipient and message body required"}), 400
        
        # Verify recipient exists
        if not User.query.filter_by(email=recipient).first():
            return jsonify({"message": "Recipient not found"}), 404
        
        new_message = Message(
            sender_email=user.email,
            recipient_email=recipient,
            body=body
        )
        
        db.session.add(new_message)
        db.session.commit()
        
        return jsonify({
            "message": "Message sent successfully",
            "message_id": new_message.id
        }), 201

# User management (admin only)
@app.route('/api/users', methods=['GET'])
def get_users():
    user = check_auth(request)
    if not user or user.role != 'admin':
        return jsonify({"message": "Admin access required"}), 403
    
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
    
    return jsonify(result)

# Initialize data and run app
initialize_data()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
