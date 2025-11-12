from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer as Serializer, BadSignature, SignatureExpired
import os
import json
import logging

# -----------------------------------------------------------
# App Setup
# -----------------------------------------------------------
app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)

# Database Configuration
db_path = os.path.join(os.path.dirname(__file__), 'users.db')
db_url = os.environ.get('DATABASE_URL', f"sqlite:///{db_path}?check_same_thread=False")

# Render sometimes uses postgres:// instead of postgresql://
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'supersecretkey')

db = SQLAlchemy(app)
s = Serializer(app.config['SECRET_KEY'])

# -----------------------------------------------------------
# Models
# -----------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# -----------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------
def initialize_data():
    """Ensure the database and admin user exist."""
    logging.info("Initializing database...")
    db.create_all()

    admin = User.query.filter_by(username='admin').first()
    if not admin:
        logging.info("Creating default admin user...")
        admin = User(username='admin', email='admin@vast.com', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
    logging.info("Database initialization complete.")


def check_auth(request):
    token = request.headers.get('Authorization')
    if not token:
        return None
    try:
        data = s.loads(token, max_age=86400)
        return User.query.get(data['id'])
    except (BadSignature, SignatureExpired):
        return None


# -----------------------------------------------------------
# Routes
# -----------------------------------------------------------
@app.route('/')
def index():
    return jsonify({'message': 'Welcome to Vast Holdings API', 'status': 'running'})


# -------------------- Register --------------------
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        if not all(k in data for k in ('username', 'email', 'password')):
            return jsonify({'message': 'Missing fields'}), 400

        if User.query.filter((User.username == data['username']) | (User.email == data['email'])).first():
            return jsonify({'message': 'User already exists'}), 400

        new_user = User(username=data['username'], email=data['email'])
        new_user.set_password(data['password'])
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'Registration successful'}), 201
    except Exception as e:
        logging.error(f"Registration error: {e}")
        return jsonify({'message': 'Error during registration', 'error': str(e)}), 500


# -------------------- Login --------------------
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        user = User.query.filter_by(email=data['email']).first()
        if not user or not user.check_password(data['password']):
            return jsonify({'message': 'Invalid email or password'}), 401

        token = s.dumps({'id': user.id})
        return jsonify({'message': 'Login successful', 'token': token, 'role': user.role})
    except Exception as e:
        logging.error(f"Login error: {e}")
        return jsonify({'message': 'Login error', 'error': str(e)}), 500


# -------------------- Profile --------------------
@app.route('/api/profile', methods=['GET'])
def profile():
    user = check_auth(request)
    if not user:
        return jsonify({'message': 'Unauthorized'}), 401
    return jsonify({
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'date_created': user.date_created.strftime('%Y-%m-%d %H:%M:%S')
    })


# -------------------- Backup --------------------
@app.route('/api/backup', methods=['GET'])
def backup():
    user = check_auth(request)
    if not user or user.role != 'admin':
        return jsonify({'message': 'Unauthorized'}), 401

    try:
        # Use a persistent Render-safe folder
        backup_dir = '/opt/render/project/.render/data/backups'
        os.makedirs(backup_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = os.path.join(backup_dir, f"backup-{timestamp}.json")

        data = []
        for u in User.query.all():
            data.append({
                'username': u.username,
                'email': u.email,
                'role': u.role,
                'date_created': u.date_created.isoformat()
            })

        with open(backup_path, 'w') as f:
            json.dump(data, f, indent=2)

        return jsonify({'message': 'Backup successful', 'backup_path': backup_path})
    except Exception as e:
        logging.error(f"Backup error: {e}")
        return jsonify({'message': 'Backup failed', 'error': str(e)}), 500


# -------------------- Admin: Get All Users --------------------
@app.route('/api/users', methods=['GET'])
def get_users():
    try:
        user = check_auth(request)
        if not user or user.role != 'admin':
            return jsonify({'message': 'Unauthorized'}), 401

        users = User.query.all()
        users_data = [{
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'role': u.role,
            'date_created': u.date_created.strftime('%Y-%m-%d %H:%M:%S')
        } for u in users]

        return jsonify({'users': users_data})
    except Exception as e:
        logging.error(f"Get users error: {e}")
        return jsonify({'message': 'Error retrieving users', 'error': str(e)}), 500


# -----------------------------------------------------------
# App Startup
# -----------------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        initialize_data()

    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

