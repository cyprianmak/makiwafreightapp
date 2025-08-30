from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional
import datetime
import secrets
import hashlib
import uuid

# Initialize FastAPI app
app = FastAPI(title="MakiwaFreight API", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

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

# Pydantic models
class User(BaseModel):
    id: str
    name: str
    email: str
    role: str
    company: Optional[str] = None
    phone: str
    address: Optional[str] = None
    vehicle_info: Optional[str] = None
    created_at: str
    updated_at: str

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone: str
    role: str
    company: Optional[str] = None
    address: Optional[str] = None
    vehicle_info: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user: User

class Load(BaseModel):
    id: str
    ref: str
    origin: str
    destination: str
    date: str
    cargo_type: str
    weight: float
    notes: Optional[str] = None
    shipper_id: str
    shipper_email: str
    created_at: str
    updated_at: str
    expires_at: str
    status: str = "active"

class LoadCreate(BaseModel):
    origin: str
    destination: str
    date: str
    cargo_type: str
    weight: float
    notes: Optional[str] = None

class Message(BaseModel):
    id: str
    sender_id: str
    sender_email: str
    receiver_id: str
    receiver_email: str
    body: str
    created_at: str

class MessageCreate(BaseModel):
    to: EmailStr
    body: str

class Banners(BaseModel):
    index: str
    dashboard: str

class AccessControl(BaseModel):
    post: dict
    market: dict
    pages: dict

# Helper functions
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    for email, user in users_db.items():
        if user.get("token") == token:
            return user
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

def generate_load_ref():
    return ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(6))

def calculate_expiry_date():
    expiry_date = datetime.datetime.now() + datetime.timedelta(days=7)
    return expiry_date.isoformat()

# Auth endpoints
@app.post("/auth/login", response_model=Token)
async def login(user_data: UserLogin):
    email = user_data.email.lower()
    user = users_db.get(email)
    
    if not user or user["password"] != hashlib.sha256(user_data.password.encode()).hexdigest():
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Generate token
    token = secrets.token_urlsafe(32)
    user["token"] = token
    
    # Return user without password
    user_response = user.copy()
    user_response.pop("password", None)
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user_response
    }

@app.post("/users", response_model=User)
async def create_user(user_data: UserCreate):
    email = user_data.email.lower()
    
    if email in users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = str(uuid.uuid4())
    now = datetime.datetime.now().isoformat()
    
    user = {
        "id": user_id,
        "name": user_data.name,
        "email": email,
        "password": hashlib.sha256(user_data.password.encode()).hexdigest(),
        "role": user_data.role,
        "company": user_data.company,
        "phone": user_data.phone,
        "address": user_data.address,
        "vehicle_info": user_data.vehicle_info,
        "created_at": now,
        "updated_at": now
    }
    
    users_db[email] = user
    
    # Set default access
    if user_data.role == "shipper":
        access_control_db["post"][email] = True
    if user_data.role == "transporter":
        access_control_db["market"][email] = True
    
    # Initialize page access
    access_control_db["pages"][email] = {}
    
    # Return user without password
    user_response = user.copy()
    user_response.pop("password", None)
    
    return user_response

@app.get("/users/me", response_model=User)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    user_response = current_user.copy()
    user_response.pop("password", None)
    return user_response

@app.put("/users/{user_id}", response_model=User)
async def update_user(user_id: str, user_data: dict, current_user: dict = Depends(get_current_user)):
    # Find user by email (since we use email as key)
    user_email = None
    for email, user in users_db.items():
        if user["id"] == user_id:
            user_email = email
            break
    
    if not user_email:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Only allow updating specific fields
    allowed_fields = ["name", "phone", "address", "password"]
    for field in user_data:
        if field in allowed_fields:
            if field == "password":
                users_db[user_email][field] = hashlib.sha256(user_data[field].encode()).hexdigest()
            else:
                users_db[user_email][field] = user_data[field]
    
    users_db[user_email]["updated_at"] = datetime.datetime.now().isoformat()
    
    # Return user without password
    user_response = users_db[user_email].copy()
    user_response.pop("password", None)
    
    return user_response

# Load endpoints
@app.post("/loads", response_model=Load)
async def create_load(load_data: LoadCreate, current_user: dict = Depends(get_current_user)):
    # Check if user has permission to post
    if not access_control_db["post"].get(current_user["email"]):
        raise HTTPException(status_code=403, detail="You don't have permission to post loads")
    
    load_id = str(uuid.uuid4())
    now = datetime.datetime.now().isoformat()
    
    load = {
        "id": load_id,
        "ref": generate_load_ref(),
        "origin": load_data.origin,
        "destination": load_data.destination,
        "date": load_data.date,
        "cargo_type": load_data.cargo_type,
        "weight": load_data.weight,
        "notes": load_data.notes,
        "shipper_id": current_user["id"],
        "shipper_email": current_user["email"],
        "created_at": now,
        "updated_at": now,
        "expires_at": calculate_expiry_date(),
        "status": "active"
    }
    
    loads_db[load_id] = load
    return load

@app.get("/loads", response_model=List[Load])
async def get_loads(
    origin: Optional[str] = None,
    destination: Optional[str] = None,
    shipper_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
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
    
    return loads

@app.put("/loads/{load_id}", response_model=Load)
async def update_load(load_id: str, load_data: dict, current_user: dict = Depends(get_current_user)):
    if load_id not in loads_db:
        raise HTTPException(status_code=404, detail="Load not found")
    
    # Only allow updating specific fields
    allowed_fields = ["origin", "destination", "date", "cargo_type", "weight", "notes"]
    for field in load_data:
        if field in allowed_fields:
            loads_db[load_id][field] = load_data[field]
    
    loads_db[load_id]["updated_at"] = datetime.datetime.now().isoformat()
    return loads_db[load_id]

@app.delete("/loads/{load_id}")
async def delete_load(load_id: str, current_user: dict = Depends(get_current_user)):
    if load_id not in loads_db:
        raise HTTPException(status_code=404, detail="Load not found")
    
    del loads_db[load_id]
    return {"message": "Load deleted successfully"}

# Message endpoints
@app.post("/messages", response_model=Message)
async def create_message(message_data: MessageCreate, current_user: dict = Depends(get_current_user)):
    receiver_email = message_data.to.lower()
    
    if receiver_email not in users_db:
        raise HTTPException(status_code=404, detail="Receiver not found")
    
    message_id = str(uuid.uuid4())
    now = datetime.datetime.now().isoformat()
    
    message = {
        "id": message_id,
        "sender_id": current_user["id"],
        "sender_email": current_user["email"],
        "receiver_id": users_db[receiver_email]["id"],
        "receiver_email": receiver_email,
        "body": message_data.body,
        "created_at": now
    }
    
    messages_db[message_id] = message
    return message

@app.get("/messages", response_model=List[Message])
async def get_messages(current_user: dict = Depends(get_current_user)):
    messages = []
    
    for message_id, message in messages_db.items():
        if message["receiver_id"] == current_user["id"]:
            messages.append(message)
    
    return messages

@app.delete("/messages/{message_id}")
async def delete_message(message_id: str, current_user: dict = Depends(get_current_user)):
    if message_id not in messages_db:
        raise HTTPException(status_code=404, detail="Message not found")
    
    if messages_db[message_id]["receiver_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="You can only delete your own messages")
    
    del messages_db[message_id]
    return {"message": "Message deleted successfully"}

# Admin endpoints
@app.get("/admin/users", response_model=List[User])
async def get_all_users(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    users = []
    for email, user in users_db.items():
        user_response = user.copy()
        user_response.pop("password", None)
        users.append(user_response)
    
    return users

@app.delete("/admin/users/{email}")
async def delete_user(email: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if email not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    
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
    
    return {"message": "User deleted successfully"}

@app.post("/admin/reset-password")
async def reset_password(email: str, password: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if email not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    
    users_db[email]["password"] = hashlib.sha256(password.encode()).hexdigest()
    users_db[email]["updated_at"] = datetime.datetime.now().isoformat()
    
    return {"message": "Password reset successfully"}

@app.get("/admin/banners", response_model=Banners)
async def get_banners(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return access_control_db["banners"]

@app.put("/admin/banners", response_model=Banners)
async def update_banners(banners: Banners, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    access_control_db["banners"] = {
        "index": banners.index,
        "dashboard": banners.dashboard
    }
    
    return access_control_db["banners"]

@app.get("/admin/access-control", response_model=AccessControl)
async def get_access_control(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return access_control_db

@app.put("/admin/access-control", response_model=AccessControl)
async def update_access_control(acl: AccessControl, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    access_control_db["post"] = acl.post
    access_control_db["market"] = acl.market
    access_control_db["pages"] = acl.pages
    
    return access_control_db

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
