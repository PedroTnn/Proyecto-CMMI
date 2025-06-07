# Aplicación de Autenticación

Servicio de autenticación con funcionalidades de seguridad como bloqueo de cuentas después de múltiples intentos fallidos.

## Características

- Registro de usuarios con contraseñas encriptadas usando bcrypt
- Login seguro con manejo de sesiones
- Bloqueo de cuentas después de 5 intentos fallidos
- Desbloqueo automático después de un período de tiempo

## Requerimientos

- Python 3.8+
- FastAPI
- Dependencias en `requirements.txt`

## Instalación

```bash
# Clonar repositorio
git clone <url-del-repositorio>
cd auth-service

# Instalar dependencias
pip install -r requirements.txt
```

## Uso

```bash
# Iniciar el servidor
python run.py
```

El servidor estará disponible en http://127.0.0.1:8000

## Tests

```bash
# Ejecutar todos los tests
pytest

# Ejecutar tests específicos
pytest tests/test_auth.py
```

## QA – Process Quality Assurance

Este proyecto sigue las buenas prácticas de OWASP y PEP8. El código es verificado con Bandit para seguridad y Flake8 para estilo.

### Ejecutar verificaciones

```bash
# Windows
.\run_qa.bat

# Linux/Mac
./run_qa.sh
```

### Ejemplos de código verificado

El módulo `app/utils.py` implementa validaciones de seguridad y logging:

```python
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
```

### Herramientas de análisis

- **Bandit**: Análisis de seguridad para detectar vulnerabilidades comunes
- **Flake8**: Verificación de estilo según PEP8 y detección de errores potenciales

## Licencia

[MIT](LICENSE)
