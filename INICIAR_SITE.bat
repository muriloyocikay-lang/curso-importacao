@echo off
title Curso de Importação
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo Node.js nao encontrado.
  echo Instale o Node.js em https://nodejs.org/ e execute este arquivo novamente.
  echo.
  pause
  exit /b 1
)
set ADMIN_PASSWORD=admin123
echo.
echo ==========================================
echo       CURSO DE IMPORTACAO - SERVIDOR
echo ==========================================
echo.
echo Senha do painel: admin123
echo Abra: http://localhost:3000
echo.
start "" http://localhost:3000
node server.js
pause
