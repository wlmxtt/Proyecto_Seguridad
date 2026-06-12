/*
 * ============================================================================
 *  SECURE SHIELD v1.0 - Sistema de Seguridad Integral
 * ============================================================================
 *  Aplicacion de seguridad para proteger sistemas, recursos y datos.
 *  Materia: Seguridad de Tecnologia de Informacion
 * 
 *  Modulos:
 *    1. Cifrado de Archivos (Encriptacion)
 *    2. Sistema de Autenticacion (Autenticacion + Protocolos)
 *    3. Control de Acceso ACL (Listas de Control de Acceso)
 *    4. Monitor de Integridad + Firewall (Antivirus/Firewall)
 * ============================================================================
 */

// IMPORTANTE: winsock2.h debe incluirse ANTES que windows.h
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <iostream>
#include <string>
#include <conio.h>
#include <ctime>
#include <thread>
#include <chrono>
#include <atomic>

// Incluir modulos de SecureShield
#include "include/ui.h"
#include "include/sha256.h"
#include "include/security_logger.h"
#include "include/crypto_engine.h"
#include "include/auth_system.h"
#include "include/acl_manager.h"
#include "include/integrity_monitor.h"
#include "include/firewall_monitor.h"

// Linker: bibliotecas necesarias
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

using namespace std;

// ============================================================================
//  PANEL DE SEGURIDAD (DASHBOARD)
// ============================================================================
void showDashboard() {
    UI::clearScreen();
    UI::printHeader("PANEL DE SEGURIDAD - ESTADO DEL SISTEMA");
    
    auto& auth = AuthSystem::getInstance();
    auto& logger = SecurityLogger::getInstance();
    auto& integrity = IntegrityMonitor::getInstance();
    auto& firewall = FirewallMonitor::getInstance();
    
    // Estado general
    cout << endl;
    UI::setColor(UI::CYAN);
    cout << "  ===============================================" << endl;
    cout << "       ESTADO GENERAL DEL SISTEMA" << endl;
    cout << "  ===============================================" << endl;
    UI::resetColor();
    cout << endl;
    
    // Usuario actual
    UI::setColor(UI::WHITE);
    cout << "  Usuario actual: ";
    if (auth.isLoggedIn()) {
        UI::setColor(UI::GREEN);
        cout << auth.getCurrentUser() << " [" << auth.getCurrentRole() << "]" << endl;
    } else {
        UI::setColor(UI::YELLOW);
        cout << "No autenticado" << endl;
    }
    UI::resetColor();
    
    // Archivos monitoreados
    cout << "  Archivos monitoreados: ";
    UI::setColor(UI::CYAN);
    cout << integrity.getMonitoredCount() << endl;
    UI::resetColor();
    
    // Archivos comprometidos
    cout << "  Archivos comprometidos: ";
    int compromised = integrity.getCompromisedCount();
    if (compromised > 0) {
        UI::setColor(UI::RED);
        cout << compromised << " [!!! ALERTA !!!]" << endl;
    } else {
        UI::setColor(UI::GREEN);
        cout << "0 (Todo OK)" << endl;
    }
    UI::resetColor();
    
    // Conexiones activas
    cout << "  Conexiones TCP activas: ";
    UI::setColor(UI::CYAN);
    cout << firewall.getConnectionCount() << endl;
    UI::resetColor();
    
    // Alertas de seguridad
    cout << "  Alertas registradas: ";
    int alerts = logger.getAlertCount();
    if (alerts > 0) {
        UI::setColor(UI::YELLOW);
        cout << alerts << " alertas";
    } else {
        UI::setColor(UI::GREEN);
        cout << "0";
    }
    UI::resetColor();
    
    int criticals = logger.getCriticalCount();
    cout << " | Criticas: ";
    if (criticals > 0) {
        UI::setColor(UI::RED);
        cout << criticals << " [!!! PELIGRO !!!]";
    } else {
        UI::setColor(UI::GREEN);
        cout << "0";
    }
    UI::resetColor();
    cout << endl;
    
    cout << endl;
    UI::setColor(UI::CYAN);
    cout << "  ===============================================" << endl;
    cout << "       NIVEL DE SEGURIDAD: ";
    
    int riskScore = compromised * 30 + criticals * 20 + alerts * 5;
    if (riskScore == 0) {
        UI::setColor(UI::GREEN);
        cout << "SEGURO";
    } else if (riskScore < 30) {
        UI::setColor(UI::YELLOW);
        cout << "PRECAUCION";
    } else if (riskScore < 60) {
        UI::setColor(UI::RED);
        cout << "EN RIESGO";
    } else {
        UI::setColor(UI::RED);
        cout << "!!! CRITICO !!!";
    }
    UI::resetColor();
    cout << endl;
    UI::setColor(UI::CYAN);
    cout << "  ===============================================" << endl;
    UI::resetColor();
    
    // Mostrar ultimas alertas si existen
    auto alertList = logger.getAlerts();
    if (!alertList.empty()) {
        cout << endl;
        UI::setColor(UI::RED);
        cout << "  --- ULTIMAS ALERTAS ---" << endl;
        UI::resetColor();
        int showCount = min((int)alertList.size(), 5);
        for (int i = (int)alertList.size() - showCount; i < (int)alertList.size(); i++) {
            auto& entry = alertList[i];
            char timeStr[64];
            struct tm timeinfo;
            localtime_s(&timeinfo, &entry.timestamp);
            strftime(timeStr, sizeof(timeStr), "%H:%M:%S", &timeinfo);
            
            if (entry.level == SecurityLogger::CRITICAL) {
                UI::setColor(UI::RED);
                cout << "  [" << timeStr << "] [CRITICO] ";
            } else {
                UI::setColor(UI::YELLOW);
                cout << "  [" << timeStr << "] [ALERTA]  ";
            }
            cout << "[" << entry.module << "] " << entry.message << endl;
        }
        UI::resetColor();
    }
    
    cout << endl;
    UI::pressEnter();
}

// ============================================================================
//  MENU DE CIFRADO CON VERIFICACION ACL
// ============================================================================
void menuCifrado() {
    auto& acl = ACLManager::getInstance();
    auto& auth = AuthSystem::getInstance();
    
    if (!auth.isLoggedIn()) {
        UI::printError("Debe iniciar sesion para acceder al cifrado.");
        UI::pressEnter();
        return;
    }
    
    if (!acl.checkPermission(auth.getCurrentRole(), ACLManager::CIFRADO, ACLManager::EJECUTAR)) {
        UI::printAlert("ACCESO DENEGADO: No tiene permisos para usar el modulo de cifrado.");
        SecurityLogger::getInstance().log(SecurityLogger::ALERT, "ACL", 
            "Acceso denegado a CIFRADO para usuario: " + auth.getCurrentUser());
        UI::pressEnter();
        return;
    }
    
    CryptoEngine::demonstrateCrypto();
}

// ============================================================================
//  MENU PRINCIPAL
// ============================================================================
void showMainMenu() {
    UI::clearScreen();
    UI::printBanner();
    
    auto& auth = AuthSystem::getInstance();
    
    // Mostrar estado de sesion
    cout << endl;
    UI::setColor(UI::WHITE);
    cout << "  Estado: ";
    if (auth.isLoggedIn()) {
        UI::setColor(UI::GREEN);
        cout << "Conectado como '" << auth.getCurrentUser() 
             << "' [" << auth.getCurrentRole() << "]" << endl;
    } else {
        UI::setColor(UI::YELLOW);
        cout << "No autenticado - Inicie sesion para acceder a los modulos" << endl;
    }
    UI::resetColor();
    
    // Verificar alertas
    auto& logger = SecurityLogger::getInstance();
    int criticals = logger.getCriticalCount();
    if (criticals > 0) {
        UI::setColor(UI::RED);
        cout << "  >>> " << criticals << " ALERTA(S) CRITICA(S) DETECTADA(S) <<<" << endl;
        UI::resetColor();
    }
    
    cout << endl;
    UI::setColor(UI::CYAN);
    cout << "  +--------------------------------------------+" << endl;
    cout << "  |          MODULOS DE SEGURIDAD              |" << endl;
    cout << "  +--------------------------------------------+" << endl;
    UI::resetColor();
    cout << endl;
    
    UI::printMenuItem(1, "Autenticacion y Gestion de Usuarios");
    UI::printMenuItem(2, "Cifrado de Archivos");
    UI::printMenuItem(3, "Control de Acceso (ACL)");
    UI::printMenuItem(4, "Monitor de Integridad de Archivos");
    UI::printMenuItem(5, "Firewall / Monitor de Red");
    UI::printMenuItem(6, "Panel de Seguridad (Dashboard)");
    UI::printMenuItem(7, "Ver Registros de Seguridad");
    UI::printMenuItem(0, "Salir de SecureShield");
    
    cout << endl;
    UI::setColor(UI::WHITE);
    cout << "  Seleccione una opcion: ";
    UI::setColor(UI::CYAN);
}

// ============================================================================
//  FUNCION PRINCIPAL
// ============================================================================
int main() {
    // Configurar consola para UTF-8 y colores
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    
    // Inicializar Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    // Inicializar modulos
    auto& auth = AuthSystem::getInstance();
    auto& logger = SecurityLogger::getInstance();
    auto& integrity = IntegrityMonitor::getInstance();
    auto& firewall = FirewallMonitor::getInstance();
    
    // Registrar inicio del sistema
    logger.log(SecurityLogger::INFO, "SISTEMA", "SecureShield v1.0 iniciado correctamente");
    
    // Pantalla de inicio
    UI::clearScreen();
    UI::printBanner();
    
    UI::setColor(UI::GREEN);
    cout << endl;
    cout << "  Inicializando modulos de seguridad..." << endl;
    Sleep(500);
    cout << "  [OK] Motor de cifrado SHA-256 cargado" << endl;
    Sleep(300);
    cout << "  [OK] Sistema de autenticacion iniciado" << endl;
    Sleep(300);
    cout << "  [OK] Control de acceso ACL configurado" << endl;
    Sleep(300);
    cout << "  [OK] Monitor de integridad activo" << endl;
    Sleep(300);
    cout << "  [OK] Firewall y monitor de red activo" << endl;
    Sleep(300);
    cout << "  [OK] Registro de seguridad habilitado" << endl;
    UI::resetColor();
    
    cout << endl;
    UI::setColor(UI::CYAN);
    cout << "  Sistema de seguridad listo. Todos los modulos operativos." << endl;
    UI::resetColor();
    cout << endl;
    
    UI::pressEnter();
    
    // Bucle principal del menu
    bool running = true;
    while (running) {
        showMainMenu();
        
        int option;
        cin >> option;
        cin.ignore(10000, '\n');
        
        UI::resetColor();
        
        switch (option) {
            case 1:
                auth.interactiveMenu();
                break;
                
            case 2:
                menuCifrado();
                break;
                
            case 3: {
                auto& acl = ACLManager::getInstance();
                acl.interactiveMenu();
                break;
            }
                
            case 4: {
                if (!auth.isLoggedIn()) {
                    UI::printError("Debe iniciar sesion primero.");
                    UI::pressEnter();
                    break;
                }
                integrity.interactiveMenu();
                break;
            }
                
            case 5: {
                if (!auth.isLoggedIn()) {
                    UI::printError("Debe iniciar sesion primero.");
                    UI::pressEnter();
                    break;
                }
                auto& acl = ACLManager::getInstance();
                if (!acl.checkPermission(auth.getCurrentRole(), ACLManager::RED, ACLManager::LEER)) {
                    UI::printAlert("ACCESO DENEGADO: No tiene permisos para el monitor de red.");
                    logger.log(SecurityLogger::ALERT, "ACL", 
                        "Acceso denegado a RED para usuario: " + auth.getCurrentUser());
                    UI::pressEnter();
                    break;
                }
                firewall.interactiveMenu();
                break;
            }
                
            case 6:
                showDashboard();
                break;
                
            case 7:
                UI::clearScreen();
                UI::printHeader("REGISTROS DE SEGURIDAD");
                logger.printRecentLogs(30);
                UI::pressEnter();
                break;
                
            case 0:
                UI::clearScreen();
                logger.log(SecurityLogger::INFO, "SISTEMA", "SecureShield cerrado por el usuario");
                UI::setColor(UI::CYAN);
                cout << endl;
                cout << "  ================================================" << endl;
                cout << "   SecureShield v1.0 - Sesion finalizada" << endl;
                cout << "   Sistema protegido. Hasta pronto." << endl;
                cout << "  ================================================" << endl;
                UI::resetColor();
                cout << endl;
                running = false;
                break;
                
            default:
                UI::printError("Opcion no valida. Intente de nuevo.");
                Sleep(1000);
                break;
        }
    }
    
    // Limpiar Winsock
    WSACleanup();
    
    return 0;
}
