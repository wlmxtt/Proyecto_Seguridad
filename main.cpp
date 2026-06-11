#include <iostream>
#include "auth.h"
#include "crypto.h"
#include "network.h"

int main() {
    std::cout << "=== Demostracion del Esqueleto del Sistema IPS ===\n\n";

    // 1. Demostración del Sistema de Autenticación
    std::cout << "[Fase 1] Probando Autenticacion...\n";
    AuthSystem auth;
    UserRole activeRole = UserRole::NONE;

    // Primer intento fallido
    auth.login("admin", "incorrecta", activeRole);
    // Segundo intento fallido
    auth.login("admin", "incorrecta2", activeRole);
    // Intento exitoso
    if (auth.login("admin", "admin123", activeRole)) {
        std::cout << "Acceso concedido al sistema.\n";
    }
    std::cout << "\n";

    // 2. Demostración de Criptografía
    std::cout << "[Fase 2] Probando Cifrado XOR...\n";
    std::string testMsg = "Alerta de Intrusion";
    std::vector<char> buffer(testMsg.begin(), testMsg.end());
    char key = 0x5A;

    std::cout << "Original: " << testMsg << "\n";
    CryptoSystem::xorEncryptDecrypt(buffer, key);
    std::cout << "Cifrado (bytes): ";
    for (char c : buffer) std::cout << std::hex << (static_cast<int>(c) & 0xFF) << " ";
    std::cout << "\n";

    CryptoSystem::xorEncryptDecrypt(buffer, key);
    std::string decryptedMsg(buffer.begin(), buffer.end());
    std::cout << "Descifrado: " << decryptedMsg << "\n\n";

    // 3. Demostración de Red (Bloqueo IP)
    std::cout << "[Fase 3] Probando Comando de Red...\n";
    NetworkManager net;
    net.startListeningServer(8888);
    net.blockIpAddress("192.168.1.50");

    std::cout << "\n=== Fin de la Demostracion ===\n";
    return 0;
}
