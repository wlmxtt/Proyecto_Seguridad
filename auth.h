#ifndef AUTH_H
#define AUTH_H

#include <string>
#include <iostream>
#include <unordered_map>

// Roles de usuario del sistema IPS
enum class UserRole {
    NONE,
    OPERADOR,
    ADMIN
};

// Estructura para almacenar credenciales (Solo para demostración/esqueleto)
struct UserCredentials {
    std::string password;
    UserRole role;
};

// Clase para manejar la autenticación del IPS
class AuthSystem {
private:
    // Almacenamiento simulado de usuarios en memoria (en producción usar almacenamiento seguro/hash)
    std::unordered_map<std::string, UserCredentials> userDatabase;
    
    // Rastreo de intentos fallidos por usuario
    std::unordered_map<std::string, int> loginAttempts;
    
    const int MAX_ATTEMPTS = 3;

public:
    AuthSystem() {
        // Inicialización de usuarios de ejemplo
        userDatabase["admin"] = { "admin123", UserRole::ADMIN };
        userDatabase["operador"] = { "op123", UserRole::OPERADOR };
    }

    /**
     * @brief Realiza la autenticación del usuario.
     * @param username Nombre del usuario.
     * @param password Contraseña ingresada.
     * @param outRole Variable de salida para retornar el rol si el inicio es exitoso.
     * @return true si la autenticación es correcta, false en caso contrario.
     */
    bool login(const std::string& username, const std::string& password, UserRole& outRole) {
        outRole = UserRole::NONE;

        // Verificar si el usuario existe
        auto it = userDatabase.find(username);
        if (it == userDatabase.end()) {
            std::cout << "[AUTH] Usuario no encontrado.\n";
            return false;
        }

        // Verificar si la cuenta está bloqueada temporalmente por exceso de intentos
        if (loginAttempts[username] >= MAX_ATTEMPTS) {
            std::cout << "[AUTH] Cuenta bloqueada. Demasiados intentos fallidos (Max: " << MAX_ATTEMPTS << ").\n";
            return false;
        }

        // Validar contraseña
        if (it->second.password == password) {
            // Login exitoso: reiniciar contador de intentos fallidos
            loginAttempts[username] = 0;
            outRole = it->second.role;
            std::cout << "[AUTH] Login exitoso. Rol asignado: " 
                      << (outRole == UserRole::ADMIN ? "ADMIN" : "OPERADOR") << "\n";
            return true;
        } else {
            // Incrementar intentos fallidos
            loginAttempts[username]++;
            std::cout << "[AUTH] Contraseña incorrecta. Intentos restantes para '" 
                      << username << "': " << (MAX_ATTEMPTS - loginAttempts[username]) << "\n";
            return false;
        }
    }

    /**
     * @brief Restablece los intentos de inicio de sesión de un usuario.
     * Requiere privilegios elevados.
     */
    bool resetAttempts(const std::string& username, UserRole callerRole) {
        if (callerRole != UserRole::ADMIN) {
            std::cout << "[AUTH] Permiso denegado. Solo el rol ADMIN puede restablecer intentos.\n";
            return false;
        }
        loginAttempts[username] = 0;
        std::cout << "[AUTH] Intentos de '" << username << "' restablecidos por el Administrador.\n";
        return true;
    }
};

#endif // AUTH_H
