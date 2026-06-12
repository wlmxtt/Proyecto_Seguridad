#pragma once
// ============================================================================
// acl_manager.h - Gestor de Listas de Control de Acceso para SecureShield
// Define recursos, acciones y una matriz de permisos por rol.
// ============================================================================

#include <string>
#include <vector>
#include <map>
#include <set>
#include <iostream>
#include <iomanip>

#include "ui.h"
#include "security_logger.h"
#include "auth_system.h"

// ============================================================================
// Clase ACLManager - Singleton
// ============================================================================
class ACLManager {
public:
    // Recursos protegidos del sistema
    enum Resource {
        ARCHIVOS,       // Gestion de archivos
        CIFRADO,        // Operaciones de cifrado
        RED,            // Monitoreo de red
        USUARIOS,       // Administracion de usuarios
        LOGS,           // Registros de seguridad
        CONFIGURACION   // Configuracion del sistema
    };

    // Acciones posibles sobre los recursos
    enum Action {
        LEER,           // Lectura / consulta
        ESCRIBIR,       // Escritura / modificacion
        EJECUTAR,       // Ejecucion de operaciones
        ADMINISTRAR     // Administracion completa
    };

    static ACLManager& getInstance() {
        static ACLManager instance;
        return instance;
    }

    // ------------------------------------------------------------------
    // Verificar si un rol tiene permiso para una accion sobre un recurso
    // ------------------------------------------------------------------
    bool checkPermission(const std::string& role, Resource resource, Action action) {
        std::string key = role + ":" + std::to_string(resource) + ":" + std::to_string(action);

        if (permissions_.find(key) != permissions_.end() && permissions_[key]) {
            return true;
        }

        // Registrar acceso denegado
        SecurityLogger::getInstance().log(SecurityLogger::ALERT, "ACL",
            "Acceso DENEGADO - Rol: " + role +
            " | Recurso: " + resourceToString(resource) +
            " | Accion: " + actionToString(action));
        return false;
    }

    // ------------------------------------------------------------------
    // Mostrar la matriz completa de permisos con colores
    // ------------------------------------------------------------------
    void showPermissionMatrix() {
        UI::clearScreen();
        UI::printHeader("MATRIZ DE CONTROL DE ACCESO (ACL)");

        std::vector<std::string> roles = {"admin", "usuario", "invitado"};
        std::vector<Resource> resources = {ARCHIVOS, CIFRADO, RED, USUARIOS, LOGS, CONFIGURACION};
        std::vector<Action> actions = {LEER, ESCRIBIR, EJECUTAR, ADMINISTRAR};

        for (const auto& role : roles) {
            UI::setColor(UI::CYAN);
            std::cout << std::endl << "  === Rol: ";
            UI::setColor(UI::YELLOW);
            std::cout << role << std::endl;
            UI::setColor(UI::CYAN);
            std::cout << "  " << std::string(65, '-') << std::endl;

            // Encabezado
            UI::setColor(UI::WHITE);
            std::cout << "  " << padRight("Recurso", 18);
            for (const auto& action : actions) {
                std::cout << padRight(actionToString(action), 12);
            }
            std::cout << std::endl;
            UI::setColor(UI::CYAN);
            std::cout << "  " << std::string(65, '-') << std::endl;

            for (const auto& resource : resources) {
                UI::setColor(UI::WHITE);
                std::cout << "  " << padRight(resourceToString(resource), 18);

                for (const auto& action : actions) {
                    std::string key = role + ":" + std::to_string(resource) + ":" + std::to_string(action);
                    bool hasPermission = (permissions_.find(key) != permissions_.end() && permissions_[key]);

                    if (hasPermission) {
                        UI::setColor(UI::GREEN);
                        std::cout << padRight("[SI]", 12);
                    } else {
                        UI::setColor(UI::RED);
                        std::cout << padRight("[NO]", 12);
                    }
                }
                std::cout << std::endl;
            }
            UI::resetColor();
        }
        std::cout << std::endl;
    }

    // ------------------------------------------------------------------
    // Probar y mostrar todos los accesos para un rol dado
    // ------------------------------------------------------------------
    void testAccess(const std::string& role) {
        UI::printHeader("PRUEBA DE ACCESO PARA ROL: " + role);

        std::vector<Resource> resources = {ARCHIVOS, CIFRADO, RED, USUARIOS, LOGS, CONFIGURACION};
        std::vector<Action> actions = {LEER, ESCRIBIR, EJECUTAR, ADMINISTRAR};

        int permitidos = 0;
        int denegados = 0;

        for (const auto& resource : resources) {
            for (const auto& action : actions) {
                std::string key = role + ":" + std::to_string(resource) + ":" + std::to_string(action);
                bool hasPermission = (permissions_.find(key) != permissions_.end() && permissions_[key]);

                if (hasPermission) {
                    UI::setColor(UI::GREEN);
                    std::cout << "  [PERMITIDO] ";
                    permitidos++;
                } else {
                    UI::setColor(UI::RED);
                    std::cout << "  [DENEGADO]  ";
                    denegados++;
                }
                UI::resetColor();
                std::cout << resourceToString(resource) << " -> " << actionToString(action) << std::endl;
            }
        }

        std::cout << std::endl;
        UI::setColor(UI::CYAN);
        std::cout << "  Resumen: " << permitidos << " permitidos, " << denegados << " denegados." << std::endl;
        UI::resetColor();
    }

    // ------------------------------------------------------------------
    // Convertir recurso a texto en espanol
    // ------------------------------------------------------------------
    std::string resourceToString(Resource r) {
        switch (r) {
            case ARCHIVOS:      return "Archivos";
            case CIFRADO:       return "Cifrado";
            case RED:           return "Red";
            case USUARIOS:      return "Usuarios";
            case LOGS:          return "Registros";
            case CONFIGURACION: return "Configuracion";
            default:            return "Desconocido";
        }
    }

    // ------------------------------------------------------------------
    // Convertir accion a texto en espanol
    // ------------------------------------------------------------------
    std::string actionToString(Action a) {
        switch (a) {
            case LEER:        return "Leer";
            case ESCRIBIR:    return "Escribir";
            case EJECUTAR:    return "Ejecutar";
            case ADMINISTRAR: return "Administrar";
            default:          return "Desconocido";
        }
    }

    // ------------------------------------------------------------------
    // Menu interactivo del modulo ACL
    // ------------------------------------------------------------------
    void interactiveMenu() {
        auto& auth = AuthSystem::getInstance();
        bool salir = false;

        while (!salir) {
            UI::clearScreen();
            UI::printHeader("CONTROL DE ACCESO (ACL)");

            if (auth.isLoggedIn()) {
                UI::printSuccess("Sesion activa: " + auth.getCurrentUser() +
                    " [" + auth.getCurrentRole() + "]");
            } else {
                UI::printWarning("No hay sesion activa.");
            }

            std::cout << std::endl;
            UI::printMenuItem(1, "Ver Matriz de Permisos");
            UI::printMenuItem(2, "Probar Acceso del Usuario Actual");
            UI::printMenuItem(3, "Intentar Acceder a un Recurso");
            UI::printMenuItem(0, "Volver al menu principal");
            std::cout << std::endl;

            UI::setColor(UI::WHITE);
            std::cout << "  Seleccione una opcion: ";
            UI::setColor(UI::CYAN);

            int opcion;
            std::cin >> opcion;
            std::cin.ignore(10000, '\n');
            UI::resetColor();

            switch (opcion) {
                case 1:
                    showPermissionMatrix();
                    UI::pressEnter();
                    break;

                case 2: {
                    if (!auth.isLoggedIn()) {
                        UI::printError("Debe iniciar sesion primero.");
                        UI::pressEnter();
                        break;
                    }
                    testAccess(auth.getCurrentRole());
                    UI::pressEnter();
                    break;
                }

                case 3: {
                    if (!auth.isLoggedIn()) {
                        UI::printError("Debe iniciar sesion primero.");
                        UI::pressEnter();
                        break;
                    }

                    std::cout << std::endl;
                    UI::setColor(UI::WHITE);
                    std::cout << "  Recursos: 0=Archivos, 1=Cifrado, 2=Red, 3=Usuarios, 4=Registros, 5=Config" << std::endl;
                    std::cout << "  Seleccione recurso: ";
                    UI::setColor(UI::CYAN);
                    int r;
                    std::cin >> r;
                    std::cin.ignore(10000, '\n');

                    UI::setColor(UI::WHITE);
                    std::cout << "  Acciones: 0=Leer, 1=Escribir, 2=Ejecutar, 3=Administrar" << std::endl;
                    std::cout << "  Seleccione accion: ";
                    UI::setColor(UI::CYAN);
                    int a;
                    std::cin >> a;
                    std::cin.ignore(10000, '\n');
                    UI::resetColor();

                    if (r >= 0 && r <= 5 && a >= 0 && a <= 3) {
                        Resource recurso = static_cast<Resource>(r);
                        Action accion = static_cast<Action>(a);

                        std::cout << std::endl;
                        std::cout << "  Intentando acceder a: " << resourceToString(recurso)
                                  << " -> " << actionToString(accion) << std::endl;
                        std::cout << std::endl;

                        if (checkPermission(auth.getCurrentRole(), recurso, accion)) {
                            UI::printSuccess("ACCESO CONCEDIDO a " + resourceToString(recurso) +
                                " (" + actionToString(accion) + ")");
                            SecurityLogger::getInstance().log(SecurityLogger::INFO, "ACL",
                                "Acceso concedido - Usuario: " + auth.getCurrentUser() +
                                " | Recurso: " + resourceToString(recurso) +
                                " | Accion: " + actionToString(accion));
                        } else {
                            UI::printAlert("ACCESO DENEGADO a " + resourceToString(recurso) +
                                " (" + actionToString(accion) + ")");
                        }
                    } else {
                        UI::printError("Valor invalido.");
                    }
                    UI::pressEnter();
                    break;
                }

                case 0:
                    salir = true;
                    break;

                default:
                    UI::printError("Opcion invalida.");
                    Sleep(1000);
                    break;
            }
        }
    }

private:
    std::map<std::string, bool> permissions_;

    ACLManager() {
        initializePermissions();
    }

    ACLManager(const ACLManager&) = delete;
    ACLManager& operator=(const ACLManager&) = delete;

    // Inicializar la matriz de permisos
    void initializePermissions() {
        std::vector<Resource> allResources = {ARCHIVOS, CIFRADO, RED, USUARIOS, LOGS, CONFIGURACION};
        std::vector<Action> allActions = {LEER, ESCRIBIR, EJECUTAR, ADMINISTRAR};

        // ADMIN: todos los permisos sobre todos los recursos
        for (const auto& r : allResources) {
            for (const auto& a : allActions) {
                setPermission("admin", r, a, true);
            }
        }

        // USUARIO: permisos limitados
        setPermission("usuario", ARCHIVOS, LEER, true);
        setPermission("usuario", ARCHIVOS, ESCRIBIR, true);
        setPermission("usuario", CIFRADO, LEER, true);
        setPermission("usuario", CIFRADO, EJECUTAR, true);
        setPermission("usuario", RED, LEER, true);
        setPermission("usuario", LOGS, LEER, true);

        // INVITADO: permisos minimos (solo lectura de archivos y logs)
        setPermission("invitado", ARCHIVOS, LEER, true);
        setPermission("invitado", LOGS, LEER, true);
    }

    void setPermission(const std::string& role, Resource resource, Action action, bool allowed) {
        std::string key = role + ":" + std::to_string(resource) + ":" + std::to_string(action);
        permissions_[key] = allowed;
    }

    static std::string padRight(const std::string& texto, size_t ancho) {
        if (texto.length() >= ancho) return texto;
        return texto + std::string(ancho - texto.length(), ' ');
    }
};
