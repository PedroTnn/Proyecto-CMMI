# app/auth.py

from datetime import datetime, timedelta
from fastapi import HTTPException
from passlib.context import CryptContext
import jwt
import os
from typing import Dict, Optional, Tuple

# Configuración de JWT
SECRET_KEY = os.getenv("SECRET_KEY", "tK$7-mXy#9@qW!-zP5%2-fBv^3&")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configuración de encriptación con bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Simulación de almacenamiento en memoria
login_attempts = {}
users_db = {}  # Simulación de base de datos de usuarios
user_profiles = {}  # Almacena perfiles de usuario adicionales
MAX_ATTEMPTS = 5
BLOCK_DURATION = timedelta(minutes=15)

def get_password_hash(password: str) -> str:
    """
    Genera un hash seguro para la contraseña utilizando bcrypt.
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica que la contraseña coincida con el hash almacenado.
    """
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: Dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Crea un token JWT con los datos del usuario.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> Dict:
    """
    Verifica y decodifica un token JWT.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

def get_user_profile(username: str) -> Dict:
    """
    Obtiene el perfil completo del usuario.
    """
    # Obtener el hash de la contraseña para mostrarlo (solo para propósitos educativos)
    password_hash = users_db.get(username, "")
    
    base_profile = {
        "username": username,
        "email": f"{username}@example.com",  # Email simulado
        "full_name": user_profiles.get(username, {}).get("full_name", username.title()),
        "role": user_profiles.get(username, {}).get("role", "user"),
        "created_at": user_profiles.get(username, {}).get("created_at", datetime.now().isoformat()),
        "password_hash": password_hash  # Incluir hash bcrypt para demostración
    }
    return base_profile

def register_user(username: str, password: str) -> Dict:
    """
    Registra un nuevo usuario con contraseña encriptada.
    """
    if username in users_db:
        raise HTTPException(status_code=400, detail="El usuario ya existe.")
    
    hashed_password = get_password_hash(password)
    users_db[username] = hashed_password
      # Crear perfil de usuario
    user_profiles[username] = {
        "username": username,
        "role": "user",
        "created_at": datetime.now().isoformat()
    }
    
    return {"msg": "Usuario registrado exitosamente"}

def initialize_demo_users():
    """
    Inicializa algunos usuarios de demostración.
    """
    if not users_db:
        # Crear usuarios de prueba con perfiles básicos
        register_user("testuser", "secret")
        register_user("admin", "admin123")
        # Actualizar rol del admin
        user_profiles["admin"]["role"] = "admin"

# Inicializar usuarios de demostración
initialize_demo_users()

def is_user_blocked(username: str) -> bool:
    user_data = login_attempts.get(username, {"attempts": 0, "blocked_until": None})
    if user_data["blocked_until"] and datetime.now() < user_data["blocked_until"]:
        return True
    return False

def register_login_attempt(username: str, success: bool):
    user_data = login_attempts.get(username, {"attempts": 0, "blocked_until": None})
    if success:
        user_data["attempts"] = 0
        user_data["blocked_until"] = None
    else:
        user_data["attempts"] += 1
        if user_data["attempts"] >= MAX_ATTEMPTS:
            user_data["blocked_until"] = datetime.now() + BLOCK_DURATION
    login_attempts[username] = user_data

def login(username: str, password: str):
    """
    Realiza un login seguro con bloqueo tras múltiples intentos.
    Verifica la contraseña utilizando bcrypt y genera un JWT.
    """
    # Primero verificar si el usuario existe
    if username not in users_db:
        # No registrar intento fallido para usuarios inexistentes
        raise HTTPException(status_code=401, detail="La cuenta no existe.")
    
    # Solo verificar bloqueo si el usuario existe
    if is_user_blocked(username):
        raise HTTPException(status_code=403, detail="Cuenta bloqueada temporalmente por múltiples intentos fallidos. Intente nuevamente en 15 minutos.")    # Verificación de contraseña con bcrypt
    hashed_password = users_db.get(username)
    success = verify_password(password, hashed_password)
    
    # Registrar intento (solo para usuarios existentes)
    register_login_attempt(username, success)
    
    if not success:
        # Verificar si después de este intento fallido el usuario queda bloqueado
        user_data = login_attempts.get(username, {"attempts": 0, "blocked_until": None})
        remaining_attempts = MAX_ATTEMPTS - user_data["attempts"]
        
        if user_data["attempts"] >= MAX_ATTEMPTS:
            raise HTTPException(status_code=403, detail="Cuenta bloqueada temporalmente por múltiples intentos fallidos. Intente nuevamente en 15 minutos.")
        else:
            detail_msg = f"Credenciales inválidas. Te quedan {remaining_attempts} intentos antes de que tu cuenta sea bloqueada."
            raise HTTPException(status_code=401, detail=detail_msg)

    # Crear JWT con perfil del usuario
    user_profile = get_user_profile(username)
    access_token = create_access_token(
        data={"sub": username, "profile": user_profile}
    )
    
    return {
        "msg": "Login exitoso",
        "access_token": access_token,
        "token_type": "bearer",
        "user_profile": user_profile
    }