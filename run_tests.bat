@echo off
REM Este script ejecuta las pruebas de autenticación

REM Establecer el PYTHONPATH para incluir el directorio raíz
set PYTHONPATH=%cd%

echo === Ejecutando pruebas básicas de autenticación ===
pytest -v tests/test_auth.py

echo === Pruebas completadas ===
pause
