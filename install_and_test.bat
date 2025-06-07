@echo off
REM Este script instala el paquete en modo de desarrollo y ejecuta las pruebas

REM Instalar el paquete en modo desarrollo
pip install -e .

echo === Ejecutando pruebas básicas de autenticación ===
pytest -v tests/test_auth.py

echo === Pruebas completadas ===
pause
