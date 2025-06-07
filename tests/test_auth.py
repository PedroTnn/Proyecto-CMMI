# tests/test_auth.py

import pytest
from app.auth import login, is_user_blocked, register_login_attempt, register_user, users_db, login_attempts
from datetime import datetime, timedelta

def test_login_fails_and_blocks():
    username = "testuser"

    for _ in range(4):
        with pytest.raises(Exception) as e:
            login(username, "wrong")
        assert "Credenciales inválidas" in str(e.value.detail)

    # Quinto intento, debe bloquearse
    with pytest.raises(Exception) as e:
        login(username, "wrong")
    assert "Credenciales inválidas" in str(e.value.detail)

    # Sexto intento, debe estar bloqueado
    with pytest.raises(Exception) as e:
        login(username, "wrong")
    assert "Usuario bloqueado" in str(e.value.detail)

def test_user_unblocks_after_timeout():
    username = "testuser2"

    # Bloquear al usuario
    for _ in range(5):
        with pytest.raises(Exception):
            login(username, "wrong")

    # Simular paso del tiempo
    login_attempts[username]["blocked_until"] = datetime.now() - timedelta(seconds=1)

    # Ahora debería poder intentar de nuevo
    with pytest.raises(Exception) as e:
        login(username, "wrong")
    assert "Credenciales inválidas" in str(e.value.detail)

def test_register_user():
    username = "newuser"
    password = "testpassword"
    
    # Asegurarse de que el usuario no exista
    if username in users_db:
        del users_db[username]
    
    # Registrar el usuario
    result = register_user(username, password)
    assert "exitosamente" in result["msg"]
    
    # Verificar que el usuario está en la base de datos
    assert username in users_db
    
    # Verificar que la contraseña está hasheada (no es texto plano)
    assert users_db[username] != password
    
    # Intentar registrar el mismo usuario debe fallar
    with pytest.raises(Exception) as e:
        register_user(username, password)
    assert "ya existe" in str(e.value.detail)

def test_login_with_registered_user():
    username = "loginuser"
    password = "correctpassword"
    
    # Registrar usuario
    register_user(username, password)
    
    # Login exitoso
    result = login(username, password)
    assert "exitoso" in result["msg"]
    
    # Login fallido
    with pytest.raises(Exception) as e:
        login(username, "wrongpassword")
    assert "Credenciales inválidas" in str(e.value.detail)

def test_password_encryption():
    """Prueba que la contraseña se almacena encriptada."""
    username = "encryptiontest"
    password = "mypassword123"
    
    # Asegurarse de que el usuario no exista
    if username in users_db:
        del users_db[username]
    
    # Registrar usuario
    register_user(username, password)
    
    # Verificar que la contraseña está encriptada
    assert username in users_db
    assert users_db[username] != password  # No debe ser texto plano
    assert len(users_db[username]) > 20    # Hashes bcrypt son largos
    
def test_is_user_blocked_function():
    """Prueba que la función is_user_blocked funciona correctamente."""
    username = "blocktest"
    
    # Inicialmente no está bloqueado
    if username in login_attempts:
        del login_attempts[username]
    assert is_user_blocked(username) is False
    
    # Simular usuario bloqueado
    login_attempts[username] = {
        "attempts": 5,
        "blocked_until": datetime.now() + timedelta(minutes=1)
    }
    assert is_user_blocked(username) is True
    
    # Simular que ha pasado el tiempo
    login_attempts[username]["blocked_until"] = datetime.now() - timedelta(minutes=1)
    assert is_user_blocked(username) is False


def test_block_duration():
    """Prueba que el bloqueo dura el tiempo especificado."""
    username = "durationtest"
      # Bloquear usuario
    for _ in range(5):
        with pytest.raises(Exception):
            login(username, "wrong")
    
    # Verificar que está bloqueado
    assert is_user_blocked(username) is True
      # Verificar que el tiempo de bloqueo es aproximadamente 15 minutos
    block_time = login_attempts[username]["blocked_until"] - datetime.now()
    assert 14 <= block_time.seconds/60 <= 15