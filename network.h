#ifndef NETWORK_H
#define NETWORK_H

#include <string>
#include <vector>
#include <iostream>
#include <cstdlib> // Necesario para std::system

// Configuración nativa para Windows Sockets (Evita conflictos de cabeceras)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

// Directiva para enlazar la librería de red automáticamente si usas MSVC
#pragma comment(lib, "ws2_32.lib")

class NetworkManager {
public:
    /**
     * @brief Levanta un socket TCP real en el puerto especificado y bloquea la ejecución
     * hasta que detecta una conexión entrante (intento de ataque/escaneo), capturando la IP.
     */
    bool startListeningServer(int port) {
        std::cout << "[NETWORK] Inicializando Winsock (Capa de Red Real de Windows)...\n";
        
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "[NETWORK] Error: No se pudo inicializar Winsock. Código: " << WSAGetLastError() << "\n";
            return false;
        }

        // Crear el socket TCP real
        SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (serverSocket == INVALID_SOCKET) {
            std::cerr << "[NETWORK] Error: No se pudo crear el socket. Código: " << WSAGetLastError() << "\n";
            WSACleanup();
            return false;
        }

        // Configurar la dirección del servidor (escuchar en cualquier interfaz de red de la PC)
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY; 
        serverAddr.sin_port = htons(port);

        // Vincular el puerto real de la computadora
        if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            std::cerr << "[NETWORK] Error: Fallo en BIND. El puerto " << port << " ya está en uso.\n";
            closesocket(serverSocket);
            WSACleanup();
            return false;
        }

        // Poner el puerto a la escucha
        if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
            std::cerr << "[NETWORK] Error: Fallo al poner el socket en modo listen.\n";
            closesocket(serverSocket);
            WSACleanup();
            return false;
        }

        std::cout << "\n[MONITOR IPS ACTIVO] Escuchando conexiones REALES en el puerto TCP: " << port << "...\n";
        std::cout << "[MONITOR IPS ACTIVO] Esperando intrusión o escaneo de red en vivo...\n";

        // EL PROGRAMA SE DETIENE AQUÍ ESPERANDO EL ATAQUE REAL
        sockaddr_in clientAddr;
        int clientSize = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientSize);

        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "[NETWORK] Error al aceptar la conexión entrante.\n";
            closesocket(serverSocket);
            WSACleanup();
            return false;
        }

        // EXTRAER LA IP REAL DEL ATACANTE
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), ipStr, INET_ADDRSTRLEN);
        std::string attackerIp(ipStr);

        std::cout << "\n[¡ALERTA CRÍTICA!] Intento de acceso no autorizado desde la IP: " << attackerIp << "\n";

        // EJECUTAR EL IPS: Pasar la IP detectada dinámicamente al Firewall
        bool blockSuccess = blockIpAddress(attackerIp);

        // Limpieza de sockets
        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return blockSuccess;
    }

    /**
     * @brief Agrega una regla de bloqueo real e inmediato al Firewall de Windows mediante netsh.
     */
    bool blockIpAddress(const std::string& ipAddress) {
        // Validación estricta para evitar inyección de comandos
        if (ipAddress.empty() || ipAddress.find_first_not_of("0123456789.") != std::string::npos) {
            std::cerr << "[FIREWALL] Error: Dirección IP no válida o maliciosa.\n";
            return false;
        }

        std::cout << "[FIREWALL] Modificando las tablas del Kernel de Windows...\n";
        
        // Comando oficial dinámico de Windows para denegar todo tráfico entrante de esa IP específica
        std::string command = "netsh advfirewall firewall add rule name=\"IPS_Block_" + ipAddress + "\" dir=in action=block remoteip=" + ipAddress;
        
        std::cout << "[FIREWALL] Comando del Sistema Ejecutado: " << command << "\n";
        
        // EJECUCIÓN INTERACTIVA DIRECTA EN EL SISTEMA OPERATIVO
        int result = std::system(command.c_str());
        
        if (result == 0) {
            std::cout << "[ÉXITO] ¡La IP " << ipAddress << " ha sido bloqueada REALMENTE en el Firewall de Windows!\n";
            return true;
        } else {
            std::cerr << "[ERROR] No se pudo agregar la regla. Asegúrate de ejecutar el programa como ADMINISTRADOR.\n";
            return false;
        }
    }
};

#endif // NETWORK_H