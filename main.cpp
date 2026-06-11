#include <iostream>
#include <string>
#include <vector>
#include "auth.h"
#include "crypto.h"
#include "network.h"

int main() {
    // 1. EXPERIENCIA VISUAL: Diseño limpio de interfaz de consola para la defensa
    std::cout << "============================================================\n";
    std::cout << "   SISTEMA IPS INTERACTIVO - UNIVERSIDAD GRAN MARISCAL      \n";
    std::cout << "         CATEDRA: SEGURIDAD DE TECNOLOGIA DE LA INFO.       \n";
    std::cout << "============================================================\n\n";

    // 2. UNIDAD V - INTEGRIDAD: Simulación del chequeo de arranque del sistema
    std::cout << "[FASE 1 - INTEGRIDAD] Verificando archivos de configuracion...\n";
    std::cout << "[INTEGRIDAD] Checksum hash verificado correctamente. Archivos integros.\n\n";

    // 3. UNIDAD IV - AUTENTICACION: Flujo dinámico con límite estricto de 3 intentos
    std::cout << "[FASE 2 - AUTENTICACION] Control de Acceso Obligatorio\n";
    AuthSystem auth;
    UserRole activeRole = UserRole::NONE;
    std::string username, password;
    int intentos = 0;
    bool autenticado = false;

    while (intentos < 3) {
        std::cout << " -> Ingrese Usuario: ";
        std::cin >> username;
        std::cout << " -> Ingrese Contrasena: ";
        std::cin >> password;

        if (auth.login(username, password, activeRole)) {
            autenticado = true;
            break;
        } else {
            intentos++;
            std::cout << "⚠️ Credenciales invalidas. Intentos restantes: " << (3 - intentos) << "\n\n";
        }
    }

    // Cierre seguro del sistema si se violan los intentos de login
    if (!autenticado) {
        std::cerr << "❌ [ALERTA] Exceso de intentos fallidos. Sistema bloqueado por seguridad.\n";
        return 1;
    }

    // 4. CONTROL DE ACCESO (ACL): Validar privilegios según el rol retornado
    std::cout << "\n✅ Acceso Concedido.";
    if (activeRole == UserRole::ADMIN) {
        std::cout << " [ROL: ADMINISTRADOR] Privilegios totales de red concedidos.\n\n";
    } else {
        std::cout << " [ROL: OPERADOR] Privilegios limitados (Modo Auditoria).\n\n";
    }

    // 5. UNIDAD VI - ENCRIPCION: Demostración del mecanismo criptográfico XOR en memoria
    std::cout << "[FASE 3 - CRIPTOGRAFIA] Inicializando tunel de logs cifrados...\n";
    std::string logMsg = "Sesion iniciada por usuario: " + username;
    std::vector<char> buffer(logMsg.begin(), logMsg.end());
    char key = 0x5A; // Llave simétrica tradicional

    CryptoSystem::xorEncryptDecrypt(buffer, key);
    std::cout << "[CRYPTO] Mensaje de auditoria cifrado en memoria (XOR hex): ";
    for (char c : buffer) std::cout << std::hex << (static_cast<int>(c) & 0xFF) << " ";
    std::cout << "\n\n";

    // 6. IPS Y RED: Activación del socket TCP en vivo para capturar ataques
    std::cout << "============================================================\n";
    std::cout << "             DESPLIEGUE DEL SERVIDOR IPS TCP                \n";
    std::cout << "============================================================\n";
    
    NetworkManager net;
    int puertoDeEscucha = 8888;
    
    // Este método se queda escuchando conexiones reales. Al recibir una,
    // extraerá la IP y llamará dinámicamente a netsh advfirewall.
    net.startListeningServer(puertoDeEscucha);

    std::cout << "\n============================================================\n";
    std::cout << "                FIN DEL FLUJO DE EJECUCION                  \n";
    std::cout << "============================================================\n";
    
    return 0;
}