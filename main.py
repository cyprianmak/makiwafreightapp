from flask import Flask, render_template, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import uuid

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
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    company = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    vehicle_info = db.Column(db.String(200))
    token = db.Column(db.String(36))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
                password=admin_password,
                role="admin"
            )
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

    user = User.query.filter_by(email=email, password=password).first()

    if user:
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

# Update other endpoints to use the database models instead of dictionaries...

# Initialize data and run app
initialize_data()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
