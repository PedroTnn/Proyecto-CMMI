# app/main.py

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from app.auth import login as auth_login, register_user
from app.utils import validate_username, log_login_attempt
from pydantic import BaseModel
from typing import Optional

class UserCredentials(BaseModel):
    username: str
    password: str

class UserRegistration(BaseModel):
    username: str
    password: str

app = FastAPI(
    title="Servicio de Autenticación Segura",
    description="Microservicio que gestiona autenticación segura con bloqueo por intentos fallidos.",
    version="1.0.0"
)

# Configurar CORS para permitir solicitudes desde el frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En producción, cambiar a orígenes específicos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Montar archivos estáticos
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def root():
    """
    Endpoint raíz que proporciona la interfaz de usuario.
    """
    return RedirectResponse(url="/static/index.html")

@app.get("/debug/users")
async def debug_users():
    """
    Endpoint de debug para ver los usuarios disponibles
    """
    from app.auth import users_db, user_profiles
    
    users_info = []
    for username in users_db.keys():
        profile = user_profiles.get(username, {})
        users_info.append({
            "username": username,
            "profile": profile
        })
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Debug - Usuarios Disponibles</title>
        <style>
            body {{ font-family: Arial, sans-serif; padding: 20px; }}
            .user {{ background: #f0f0f0; padding: 10px; margin: 10px 0; border-radius: 5px; }}
            .credentials {{ background: #e8f5e8; padding: 10px; margin: 10px 0; border-radius: 5px; }}
        </style>
    </head>
    <body>
        <h1>Usuarios Disponibles para Pruebas</h1>
        
        <div class="credentials">
            <h3>Credenciales de Prueba:</h3>
            <p><strong>Usuario 1:</strong> testuser / secret</p>
            <p><strong>Usuario 2:</strong> admin / admin123</p>
        </div>
        
        <h2>Usuarios en el Sistema:</h2>
        {"".join([f'<div class="user"><strong>{user["username"]}</strong><br>Perfil: {user["profile"]}</div>' for user in users_info])}
        
        <p><a href="/static/index.html">Ir al Login</a></p>
        <p><a href="/test-welcome">Ir a Test Welcome</a></p>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)

@app.get("/test-welcome")
async def test_welcome():
    """
    Página de prueba para verificar la funcionalidad de bienvenida
    """
    html_content = """
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Test - Página de Bienvenida</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; background: #f0f0f0; }
            .container { background: white; padding: 20px; border-radius: 10px; max-width: 600px; margin: 0 auto; }
            .success { color: #4CAF50; font-weight: bold; }
            .error { color: #f44336; font-weight: bold; }
            .info { background: #e3f2fd; padding: 10px; border-radius: 5px; margin: 10px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎉 Test - Página de Bienvenida</h1>
            <div id="status" class="info">Verificando datos del usuario...</div>
            <div id="user-info" style="display:none;">
                <h2>Información del Usuario:</h2>
                <p><strong>Hola:</strong> <span id="user-name">-</span></p>
                <p class="success">✅ JWT Creado</p>
                <div id="user-details"></div>
                <div id="token-info" style="margin-top: 20px; font-family: monospace; background: #f5f5f5; padding: 10px; border-radius: 5px; word-break: break-all;"></div>
            </div>
            <div id="error-info" style="display:none;">
                <p class="error">❌ No se encontraron datos de usuario</p>
                <p>Posibles causas:</p>
                <ul>
                    <li>No has iniciado sesión</li>
                    <li>Los datos del localStorage se perdieron</li>
                    <li>Hay un problema con el JWT</li>
                </ul>
                <a href="/static/index.html" style="display: inline-block; background: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Volver al Login</a>
            </div>
            
            <div style="margin-top: 30px;">
                <button onclick="checkLocalStorage()" style="background: #2196F3; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">Revisar localStorage</button>
                <button onclick="clearData()" style="background: #ff9800; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin-left: 10px;">Limpiar Datos</button>
                <button onclick="goToLogin()" style="background: #4CAF50; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin-left: 10px;">Ir al Login</button>
            </div>
        </div>

        <script>
            function checkUserData() {
                const userData = localStorage.getItem('userData');
                const token = localStorage.getItem('access_token');
                
                console.log('userData:', userData);
                console.log('token:', token);
                
                if (userData && token) {
                    try {
                        const profile = JSON.parse(userData);
                        displayUserInfo(profile, token);
                        return true;
                    } catch (error) {
                        console.error('Error parsing userData:', error);
                        showError();
                        return false;
                    }
                } else {
                    showError();
                    return false;
                }
            }
            
            function displayUserInfo(profile, token) {
                document.getElementById('status').style.display = 'none';
                document.getElementById('user-info').style.display = 'block';
                
                document.getElementById('user-name').textContent = profile.full_name || profile.username;
                
                let detailsHtml = '<h3>Detalles del Perfil:</h3>';
                detailsHtml += `<p><strong>Usuario:</strong> ${profile.username}</p>`;
                detailsHtml += `<p><strong>Nombre completo:</strong> ${profile.full_name || 'No especificado'}</p>`;
                detailsHtml += `<p><strong>Email:</strong> ${profile.email}</p>`;
                detailsHtml += `<p><strong>Rol:</strong> ${profile.role}</p>`;
                detailsHtml += `<p><strong>Creado:</strong> ${new Date(profile.created_at).toLocaleString('es-ES')}</p>`;
                
                document.getElementById('user-details').innerHTML = detailsHtml;
                
                const tokenDisplay = token.length > 100 ? token.substring(0, 100) + '...' : token;
                document.getElementById('token-info').innerHTML = `<strong>JWT Token:</strong><br>${tokenDisplay}`;
            }
            
            function showError() {
                document.getElementById('status').style.display = 'none';
                document.getElementById('error-info').style.display = 'block';
            }
            
            function checkLocalStorage() {
                const userData = localStorage.getItem('userData');
                const token = localStorage.getItem('access_token');
                alert(`userData: ${userData ? 'SÍ' : 'NO'}\\ntoken: ${token ? 'SÍ' : 'NO'}`);
            }
            
            function clearData() {
                localStorage.removeItem('userData');
                localStorage.removeItem('access_token');
                alert('Datos limpiados. Recargando página...');
                location.reload();
            }
            
            function goToLogin() {
                window.location.href = '/static/index.html';
            }
            
            // Verificar datos al cargar
            document.addEventListener('DOMContentLoaded', function() {
                setTimeout(checkUserData, 500);
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.get("/welcome")
async def welcome_page():
    """
    Página de bienvenida tras login exitoso.
    """
    html_content = """
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Bienvenido - Sistema de Autenticación</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .welcome-container {
                background: white;
                padding: 2rem;
                border-radius: 10px;
                box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
                text-align: center;
                max-width: 500px;
                width: 90%;
            }

            .welcome-header {
                color: #333;
                margin-bottom: 1rem;
                font-size: 2rem;
            }

            .user-greeting {
                color: #667eea;
                font-size: 1.5rem;
                margin-bottom: 1rem;
                font-weight: 600;
            }

            .jwt-status {
                background: #4CAF50;
                color: white;
                padding: 0.8rem;
                border-radius: 5px;
                margin: 1rem 0;
                font-weight: bold;
                font-size: 1.1rem;
            }

            .user-info {
                background: #f8f9fa;
                padding: 1rem;
                border-radius: 5px;
                margin: 1rem 0;
                text-align: left;
            }

            .user-info h3 {
                color: #333;
                margin-bottom: 0.5rem;
            }

            .user-info p {
                margin: 0.3rem 0;
                color: #666;
            }

            .jwt-token {
                background: #e9ecef;
                padding: 1rem;
                border-radius: 5px;
                margin: 1rem 0;
                word-break: break-all;
                font-family: 'Courier New', monospace;
                font-size: 0.8rem;
                color: #495057;
                max-height: 100px;
                overflow-y: auto;
            }

            .actions {
                margin-top: 1.5rem;
            }

            .btn {
                background: #667eea;
                color: white;
                padding: 0.7rem 1.5rem;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
                margin: 0.3rem;
                transition: background 0.3s ease;
            }

            .btn:hover {
                background: #5a6fd8;
            }

            .btn-secondary {
                background: #6c757d;
            }

            .btn-secondary:hover {
                background: #545b62;
            }

            .loading {
                display: none;
                color: #666;
                font-style: italic;
            }

            .error {
                background: #f8d7da;
                color: #721c24;
                padding: 1rem;
                border-radius: 5px;
                margin: 1rem 0;
                display: none;
            }
        </style>
    </head>
    <body>
        <div class="welcome-container">
            <div class="loading" id="loading">Cargando información del usuario...</div>
            
            <div id="welcome-content" style="display: none;">
                <h1 class="welcome-header">¡Bienvenido!</h1>
                <div class="user-greeting" id="user-greeting">Hola: <span id="user-name">Usuario</span></div>
                
                <div class="jwt-status">
                    🔐 JWT Creado
                </div>
                  <div class="user-info" id="user-info">
                    <h3>Información del Usuario</h3>
                    <p><strong>Usuario:</strong> <span id="info-username">-</span></p>
                    <p><strong>Rol:</strong> <span id="info-role">-</span></p>
                    <p><strong>Fecha de registro:</strong> <span id="info-created">-</span></p>
                </div>
                
                <div class="jwt-token" id="jwt-token">
                    <strong>Token JWT:</strong><br>
                    <span id="token-value">Cargando...</span>
                </div>
                
                <div class="actions">
                    <button class="btn" onclick="copyToken()">Copiar Token</button>
                    <button class="btn btn-secondary" onclick="logout()">Cerrar Sesión</button>
                </div>
            </div>
            
            <div class="error" id="error-message">
                Error al cargar la información del usuario. 
                <a href="/static/index.html" class="btn" style="margin-top: 1rem;">Volver al Login</a>
            </div>
        </div>

        <script>
            // Obtener datos del usuario desde localStorage
            function getUserData() {
                console.log('Obteniendo datos de usuario desde localStorage'); // Debug
                
                const userData = localStorage.getItem('userData');
                const token = localStorage.getItem('access_token');
                
                console.log('userData from localStorage:', userData); // Debug
                console.log('token from localStorage:', token); // Debug
                
                if (userData && token) {
                    try {
                        const parsedUserData = JSON.parse(userData);
                        console.log('Datos parseados correctamente:', parsedUserData); // Debug
                        return {
                            user_profile: parsedUserData,
                            access_token: token
                        };
                    } catch (error) {
                        console.error('Error parsing userData:', error); // Debug
                        return null;
                    }
                }
                
                console.log('No se encontraron datos válidos en localStorage'); // Debug
                return null;
            }
              function displayUserInfo(data) {
                const profile = data.user_profile;
                
                // Actualizar información del usuario
                document.getElementById('user-name').textContent = profile.username;
                document.getElementById('info-username').textContent = profile.username;
                document.getElementById('info-role').textContent = profile.role;
                
                // Formatear fecha
                const createdDate = new Date(profile.created_at).toLocaleDateString('es-ES', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit'
                });
                document.getElementById('info-created').textContent = createdDate;
                
                // Mostrar token (truncado para seguridad visual)
                const tokenDisplay = data.access_token.length > 100 
                    ? data.access_token.substring(0, 100) + '...' 
                    : data.access_token;
                document.getElementById('token-value').textContent = tokenDisplay;
                
                // Mostrar contenido
                document.getElementById('loading').style.display = 'none';
                document.getElementById('welcome-content').style.display = 'block';
            }
            
            function showError() {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('error-message').style.display = 'block';
            }
            
            function copyToken() {
                const token = localStorage.getItem('access_token');
                if (token) {
                    navigator.clipboard.writeText(token).then(() => {
                        alert('Token copiado al portapapeles');
                    }).catch(() => {
                        // Fallback para navegadores más antiguos
                        const textArea = document.createElement('textarea');
                        textArea.value = token;
                        document.body.appendChild(textArea);
                        textArea.select();
                        document.execCommand('copy');
                        document.body.removeChild(textArea);
                        alert('Token copiado al portapapeles');
                    });
                }
            }
            
            function logout() {
                // Limpiar localStorage
                localStorage.removeItem('userData');
                localStorage.removeItem('access_token');
                
                // Redireccionar al login
                window.location.href = '/static/index.html';
            }
            
            // Inicializar página
            document.addEventListener('DOMContentLoaded', function() {
                console.log('Página de bienvenida cargada'); // Debug
                
                const userData = getUserData();
                console.log('Datos de usuario obtenidos:', userData); // Debug
                
                if (userData) {
                    console.log('Mostrando información del usuario'); // Debug
                    displayUserInfo(userData);
                } else {
                    console.log('No se encontraron datos de usuario, mostrando error'); // Debug
                    showError();
                }
            });
            
            // Verificar periódicamente que el usuario sigue autenticado
            setInterval(() => {
                const token = localStorage.getItem('access_token');
                if (!token) {
                    logout();
                }
            }, 30000); // Verificar cada 30 segundos
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.get("/register")
async def register_form():
    """
    Proporciona información sobre cómo registrar un usuario.
    Redirecciona a la documentación de la API.
    """
    from fastapi.responses import HTMLResponse, RedirectResponse
    
    # Opción 1: Redireccionar a la documentación
    return RedirectResponse(url="/docs#/default/register_route_register_post")
    
    # Opción 2: Un formulario HTML simple (descomentar para usar)
    # html_content = """
    # <!DOCTYPE html>
    # <html>
    # <head>
    #     <title>Registro de Usuario</title>
    #     <style>
    #         body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
    #         .container { max-width: 500px; margin: 0 auto; }
    #         input, button { padding: 8px; margin: 5px 0; width: 100%; }
    #         button { background-color: #4CAF50; color: white; border: none; cursor: pointer; }
    #     </style>
    # </head>
    # <body>
    #     <div class="container">
    #         <h1>Registro de Usuario</h1>
    #         <form id="registerForm">
    #             <input type="text" id="username" placeholder="Nombre de usuario" required>
    #             <input type="password" id="password" placeholder="Contraseña" required>
    #             <button type="submit">Registrar</button>
    #         </form>
    #         <p>Para probar la API, utilice la <a href="/docs">documentación interactiva</a>.</p>
    #         <div id="result"></div>
    #     </div>
    #     <script>
    #         document.getElementById('registerForm').addEventListener('submit', async (e) => {
    #             e.preventDefault();
    #             const username = document.getElementById('username').value;
    #             const password = document.getElementById('password').value;
    #             
    #             try {
    #                 const response = await fetch('/register', {
    #                     method: 'POST',
    #                     headers: { 'Content-Type': 'application/json' },
    #                     body: JSON.stringify({ username, password })
    #                 });
    #                 

    #                 const data = await response.json();
    #                 document.getElementById('result').innerHTML = 
    #                     `<p style="color: ${response.ok ? 'green' : 'red'}">
    #                         ${response.ok ? data.msg : data.detail}
    #                     </p>`;
    #             } catch (error) {
    #                 document.getElementById('result').innerHTML = 
    #                     `<p style="color: red">Error: ${error.message}</p>`;
    #             }
    #         });
    #     </script>
    # </body>
    # </html>
    # """
    # return HTMLResponse(content=html_content)

@app.get("/test-client")
async def test_client():
    """
    Proporciona una interfaz HTML para probar la API de autenticación.
    """
    with open("test_client.html", "r") as file:
        html_content = file.read()
    return HTMLResponse(content=html_content)

@app.post("/login")
async def login_route(request: Request, user: UserCredentials):
    ip = request.client.host
    username = user.username
    password = user.password
    
    print(f"[DEBUG] Login attempt for user: {username}") # Debug

    if not validate_username(username):
        log_login_attempt(ip, username, "invalid format")
        raise HTTPException(status_code=400, detail="Nombre de usuario inválido")

    try:
        result = auth_login(username, password)
        print(f"[DEBUG] Login successful for user: {username}") # Debug
        print(f"[DEBUG] Login result: {result}") # Debug
        log_login_attempt(ip, username, "success")
        return result
    except HTTPException as e:
        print(f"[DEBUG] Login failed for user: {username}, error: {e.detail}") # Debug
        log_login_attempt(ip, username, "failed")
        raise e

@app.post("/register")
async def register_route(request: Request, user: UserRegistration):
    """
    Registra un nuevo usuario con contraseña cifrada.
    """
    ip = request.client.host
    username = user.username
    password = user.password

    if not validate_username(username):
        log_login_attempt(ip, username, "register_invalid_format")
        raise HTTPException(status_code=400, detail="Nombre de usuario inválido")

    try:
        result = register_user(username, password)
        log_login_attempt(ip, username, "register_success")
        return result
    except HTTPException as e:
        log_login_attempt(ip, username, "register_failed")
        raise e