@echo off
setlocal

:: Sanitize PATH to remove any mismatched double quotes (e.g. from eSpeak or similar)
set PATH=%PATH:"=%

echo ============================================================================
echo   SecureShield v1.0 - Compilador para MSVC (Visual Studio)
echo ============================================================================

:: Find Visual Studio installation using vswhere
set "VSWHERE_PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE_PATH%" (
    set "VSWHERE_PATH=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
)

if not exist "%VSWHERE_PATH%" (
    echo [ERROR] No se pudo encontrar vswhere.exe. Asegurate de tener Visual Studio instalado.
    pause
    exit /b 1
)

:: Get installation path of latest VS instance
for /f "usebackq tokens=*" %%i in (`"%VSWHERE_PATH%" -latest -property installationPath`) do (
    set "VS_PATH=%%i"
)

if "%VS_PATH%"=="" (
    echo [ERROR] No se encontro ninguna instalacion de Visual Studio.
    pause
    exit /b 1
)

set "VCVARS_PATH=%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS_PATH%" (
    set "VCVARS_PATH=%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat"
)

if not exist "%VCVARS_PATH%" (
    echo [ERROR] No se pudo encontrar vcvars64.bat o vcvarsall.bat.
    pause
    exit /b 1
)

echo [*] Configurando entorno del compilador x64 de Visual Studio...
call "%VCVARS_PATH%" x64 >nul

echo [*] Compilando SecureShield.exe...
cl.exe /EHsc /std:c++17 main.cpp /FeSecureShield.exe ws2_32.lib iphlpapi.lib

if %errorlevel% neq 0 (
    echo [ERROR] Fallo la compilacion de SecureShield.exe
    pause
    exit /b 1
)
echo [OK] SecureShield.exe compilado con exito.

echo [*] Compilando Attacker.exe...
cl.exe /EHsc /std:c++17 attacker.cpp /FeAttacker.exe ws2_32.lib

if %errorlevel% neq 0 (
    echo [ERROR] Fallo la compilacion de Attacker.exe
    pause
    exit /b 1
)
echo [OK] Attacker.exe compilado con exito.

echo ============================================================================
echo   Compilacion finalizada correctamente.
echo   Ejecute SecureShield.exe para iniciar el programa.
echo   Ejecute Attacker.exe en otra consola para la demostracion de ataques.
echo ============================================================================
pause
