# app/utils.py

import re
import logging

logger = logging.getLogger(__name__)

def validate_username(username: str) -> bool:
    """Valida que el nombre de usuario sea alfanumérico (3-30 caracteres)."""
    pattern = r"^[a-zA-Z0-9_]{3,30}$"
    return bool(re.match(pattern, username))

def log_login_attempt(ip: str, username: str, status: str):
    """Registra intentos de inicio de sesión."""
    logger.info(f"Login attempt - IP: {ip} | User: {username} | Status: {status}")
