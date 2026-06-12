#pragma once
// ============================================================================
// auth_system.h - Sistema de Autenticacion para SecureShield
// Gestion de usuarios, inicio de sesion, deteccion de fuerza bruta,
// bloqueo de cuentas y roles de acceso.
// ============================================================================

#include <string>
#include <unordered_map>
#include <ctime>
#include <fstream>
#include <sstream>
#include <random>
#include <algorithm>
#include <iostream>

#include "sha256.h"
#include "ui.h"
#include "security_logger.h"

// ============================================================================
// Estructura de usuario
// ============================================================================
struct User {
    std::string username;
    std::string passwordHash;
    std::string salt;
    std::string role;
    int failedAttempts;
    bool locked;
    time_t lastAttempt;

    User() : failedAttempts(0), locked(false), lastAttempt(0) {}

    User(const std::string& usr, const std::string& hash,
         const std::string& s, const std::string& r)
        : username(usr), passwordHash(hash), salt(s), role(r),
          failedAttempts(0), locked(false), lastAttempt(0) {}
};

// ============================================================================
// Clase AuthSystem - Singleton
// ============================================================================
class AuthSystem {
public:
    static AuthSystem& getInstance() {
        static AuthSystem instance;
        return instance;
    }

    // --- Registro de usuarios ---
    bool registerUser(const std::string& username,
                      const std::string& password,
                      const std::string& role) {
        if (username.empty() || password.empty()) {
            UI::printError("El nombre de usuario y la contrasena no pueden estar vacios.");
            return false;
        }

        if (users_.find(username) != users_.end()) {
            UI::printError("El usuario '" + username + "' ya existe.");
            SecurityLogger::getInstance().log(SecurityLogger::WARNING,
                "AUTH", "Intento de registro duplicado: " + username);
            return false;
        }

        if (role != "admin" && role != "usuario" && role != "invitado") {
            UI::printError("Rol invalido. Use: admin, usuario, invitado.");
            return false;
        }

        std::string salt = generateSalt();
        std::string hash = SHA256::hash(password + salt);

        User newUser(username, hash, salt, role);
        users_[username] = newUser;
        saveUsers();

        UI::printSuccess("Usuario '" + username + "' registrado con rol '" + role + "'.");
        SecurityLogger::getInstance().log(SecurityLogger::INFO,
            "AUTH", "Nuevo usuario registrado: " + username + " [Rol: " + role + "]");

        return true;
    }

    // --- Inicio de sesion con deteccion de fuerza bruta ---
    bool login(const std::string& username, const std::string& password) {
        auto it = users_.find(username);
        if (it == users_.end()) {
            UI::printError("Usuario no encontrado: " + username);
            SecurityLogger::getInstance().log(SecurityLogger::WARNING,
                "AUTH", "Intento de login con usuario inexistente: " + username);
            return false;
        }

        User& user = it->second;

        if (user.locked) {
            UI::printAlert("La cuenta '" + username + "' esta BLOQUEADA. Contacte al administrador.");
            SecurityLogger::getInstance().log(SecurityLogger::ALERT,
                "AUTH", "Intento de acceso a cuenta bloqueada: " + username);
            return false;
        }

        std::string hash = SHA256::hash(password + user.salt);
        time_t ahora = std::time(nullptr);

        if (hash == user.passwordHash) {
            // Login exitoso
            user.failedAttempts = 0;
            user.lastAttempt = ahora;
            currentUser_ = username;
            loggedIn_ = true;
            saveUsers();

            UI::printSuccess("Bienvenido, " + username + "! Rol: " + user.role);
            SecurityLogger::getInstance().log(SecurityLogger::INFO,
                "AUTH", "Login exitoso: " + username + " [Rol: " + user.role + "]");
            return true;
        } else {
            // Contrasena incorrecta
            double diferencia = std::difftime(ahora, user.lastAttempt);
            if (diferencia > 60.0) {
                user.failedAttempts = 0;
            }

            user.failedAttempts++;
            user.lastAttempt = ahora;

            SecurityLogger::getInstance().log(SecurityLogger::WARNING,
                "AUTH", "Intento fallido #" + std::to_string(user.failedAttempts) +
                " para usuario: " + username);

            // Deteccion de fuerza bruta: 3+ intentos en 60 segundos
            if (user.failedAttempts >= 3) {
                user.locked = true;
                UI::printAlert("CUENTA '" + username + "' BLOQUEADA por multiples intentos fallidos.");
                SecurityLogger::getInstance().log(SecurityLogger::CRITICAL,
                    "AUTH", "FUERZA BRUTA DETECTADA - Cuenta bloqueada: " + username +
                    " (" + std::to_string(user.failedAttempts) + " intentos fallidos)");
            } else {
                int restantes = 3 - user.failedAttempts;
                UI::printError("Contrasena incorrecta. Intentos restantes: " +
                    std::to_string(restantes));
            }

            saveUsers();
            return false;
        }
    }

    // --- Estado de sesion ---
    bool isLoggedIn() const { return loggedIn_; }
    std::string getCurrentUser() const { return loggedIn_ ? currentUser_ : ""; }

    std::string getCurrentRole() const {
        if (!loggedIn_) return "";
        auto it = users_.find(currentUser_);
        if (it != users_.end()) return it->second.role;
        return "";
    }

    void logout() {
        if (loggedIn_) {
            SecurityLogger::getInstance().log(SecurityLogger::INFO,
                "AUTH", "Cierre de sesion: " + currentUser_);
            UI::printInfo("Sesion cerrada para '" + currentUser_ + "'.");
            currentUser_.clear();
            loggedIn_ = false;
        } else {
            UI::printWarning("No hay ninguna sesion activa.");
        }
    }

    // --- Administracion de usuarios ---
    void listUsers() {
        if (!loggedIn_) {
            UI::printError("Debe iniciar sesion primero.");
            return;
        }

        if (getCurrentRole() != "admin") {
            UI::printError("Acceso denegado. Solo los administradores pueden listar usuarios.");
            SecurityLogger::getInstance().log(SecurityLogger::ALERT,
                "AUTH", "Intento no autorizado de listar usuarios por: " + currentUser_);
            return;
        }

        UI::printHeader("LISTA DE USUARIOS REGISTRADOS");

        // Encabezado de la tabla
        UI::setColor(UI::CYAN);
        std::cout << "  " << padRight("Usuario", 20)
                  << padRight("Rol", 15)
                  << padRight("Estado", 15)
                  << padRight("Intentos", 10) << std::endl;
        std::cout << "  " << std::string(60, '-') << std::endl;
        UI::resetColor();

        for (const auto& par : users_) {
            const User& u = par.second;
            std::string estado = u.locked ? "BLOQUEADO" : "Activo";

            if (u.locked) {
                UI::setColor(UI::RED);
            } else {
                UI::setColor(UI::GREEN);
            }

            std::cout << "  " << padRight(u.username, 20)
                      << padRight(u.role, 15)
                      << padRight(estado, 15)
                      << padRight(std::to_string(u.failedAttempts), 10) << std::endl;
        }
        UI::resetColor();
        std::cout << std::endl;
    }

    bool isLocked(const std::string& username) const {
        auto it = users_.find(username);
        if (it != users_.end()) return it->second.locked;
        return false;
    }

    void unlockUser(const std::string& username) {
        if (!loggedIn_) {
            UI::printError("Debe iniciar sesion primero.");
            return;
        }

        if (getCurrentRole() != "admin") {
            UI::printError("Acceso denegado. Solo administradores pueden desbloquear cuentas.");
            SecurityLogger::getInstance().log(SecurityLogger::ALERT,
                "AUTH", "Intento no autorizado de desbloqueo por: " + currentUser_);
            return;
        }

        auto it = users_.find(username);
        if (it == users_.end()) {
            UI::printError("Usuario '" + username + "' no encontrado.");
            return;
        }

        User& user = it->second;
        if (!user.locked) {
            UI::printInfo("La cuenta '" + username + "' no esta bloqueada.");
            return;
        }

        user.locked = false;
        user.failedAttempts = 0;
        saveUsers();

        UI::printSuccess("Cuenta '" + username + "' desbloqueada exitosamente.");
        SecurityLogger::getInstance().log(SecurityLogger::INFO,
            "AUTH", "Cuenta desbloqueada por admin '" + currentUser_ + "': " + username);
    }

    // --- Persistencia ---
    void saveUsers() {
        std::ofstream archivo("users.dat");
        if (!archivo.is_open()) return;

        for (const auto& par : users_) {
            const User& u = par.second;
            archivo << u.username << "|"
                    << u.passwordHash << "|"
                    << u.salt << "|"
                    << u.role << "|"
                    << u.failedAttempts << "|"
                    << (u.locked ? "1" : "0") << "|"
                    << u.lastAttempt << std::endl;
        }
        archivo.close();
    }

    void loadUsers() {
        std::ifstream archivo("users.dat");
        if (!archivo.is_open()) {
            crearAdminPorDefecto();
            return;
        }

        users_.clear();
        std::string linea;

        while (std::getline(archivo, linea)) {
            if (linea.empty()) continue;

            std::istringstream stream(linea);
            std::string campo;
            User u;

            if (!std::getline(stream, u.username, '|')) continue;
            if (!std::getline(stream, u.passwordHash, '|')) continue;
            if (!std::getline(stream, u.salt, '|')) continue;
            if (!std::getline(stream, u.role, '|')) continue;

            if (std::getline(stream, campo, '|'))
                u.failedAttempts = std::stoi(campo);

            if (std::getline(stream, campo, '|'))
                u.locked = (campo == "1");

            if (std::getline(stream, campo, '|'))
                u.lastAttempt = static_cast<time_t>(std::stoll(campo));

            users_[u.username] = u;
        }

        archivo.close();

        if (users_.empty()) {
            crearAdminPorDefecto();
        }
    }

    // --- Generacion de sal ---
    std::string generateSalt() {
        static const char caracteres[] = "0123456789abcdef";
        std::random_device rd;
        std::mt19937 generador(rd());
        std::uniform_int_distribution<int> distribucion(0, 15);

        std::string sal;
        sal.reserve(16);
        for (int i = 0; i < 16; ++i) {
            sal += caracteres[distribucion(generador)];
        }
        return sal;
    }

    // --- Menu interactivo ---
    void interactiveMenu() {
        bool salir = false;

        while (!salir) {
            UI::clearScreen();
            UI::printHeader("SISTEMA DE AUTENTICACION");

            if (loggedIn_) {
                UI::printSuccess("Sesion activa: " + currentUser_ + " [" + getCurrentRole() + "]");
            } else {
                UI::printWarning("No hay sesion activa.");
            }

            std::cout << std::endl;
            UI::printMenuItem(1, "Iniciar Sesion");
            UI::printMenuItem(2, "Registrar Usuario");
            UI::printMenuItem(3, "Cerrar Sesion");
            UI::printMenuItem(4, "Listar Usuarios");
            UI::printMenuItem(5, "Desbloquear Usuario");
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
                case 1: {
                    if (loggedIn_) {
                        UI::printWarning("Ya hay sesion activa (" + currentUser_ + "). Cierre sesion primero.");
                        UI::pressEnter();
                        break;
                    }
                    std::cout << std::endl;
                    UI::setColor(UI::WHITE);
                    std::cout << "  Usuario: ";
                    UI::setColor(UI::CYAN);
                    std::string usuario;
                    std::getline(std::cin, usuario);

                    UI::setColor(UI::WHITE);
                    std::cout << "  Contrasena: ";
                    std::string clave = UI::getPassword();

                    login(usuario, clave);
                    UI::pressEnter();
                    break;
                }
                case 2: {
                    std::cout << std::endl;
                    UI::setColor(UI::WHITE);
                    std::cout << "  Nuevo usuario: ";
                    UI::setColor(UI::CYAN);
                    std::string usuario;
                    std::getline(std::cin, usuario);

                    UI::setColor(UI::WHITE);
                    std::cout << "  Contrasena: ";
                    std::string clave = UI::getPassword();

                    UI::setColor(UI::WHITE);
                    std::cout << "  Roles disponibles: admin, usuario, invitado" << std::endl;
                    std::cout << "  Rol: ";
                    UI::setColor(UI::CYAN);
                    std::string rol;
                    std::getline(std::cin, rol);

                    registerUser(usuario, clave, rol);
                    UI::pressEnter();
                    break;
                }
                case 3:
                    logout();
                    UI::pressEnter();
                    break;
                case 4:
                    listUsers();
                    UI::pressEnter();
                    break;
                case 5: {
                    std::cout << std::endl;
                    UI::setColor(UI::WHITE);
                    std::cout << "  Usuario a desbloquear: ";
                    UI::setColor(UI::CYAN);
                    std::string usuario;
                    std::getline(std::cin, usuario);
                    unlockUser(usuario);
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
    std::unordered_map<std::string, User> users_;
    std::string currentUser_;
    bool loggedIn_;

    AuthSystem() : loggedIn_(false) {
        loadUsers();
    }

    AuthSystem(const AuthSystem&) = delete;
    AuthSystem& operator=(const AuthSystem&) = delete;

    void crearAdminPorDefecto() {
        std::string salt = generateSalt();
        std::string hash = SHA256::hash(std::string("admin123") + salt);

        User admin("admin", hash, salt, "admin");
        users_["admin"] = admin;
        saveUsers();
    }

    static std::string padRight(const std::string& texto, size_t ancho) {
        if (texto.length() >= ancho) return texto;
        return texto + std::string(ancho - texto.length(), ' ');
    }
};
