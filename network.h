#ifndef NETWORK_H
#define NETWORK_H

#include <string>
#include <vector>
#include <iostream>

// Prototipos y macros mínimas para evitar dependencias obligatorias de Winsock2.h
// directas en la cabecera si el usuario prefiere incluirlo en el archivo de implementación,
// pero se definen aquí los esqueletos de administración de red y sockets TCP.

class NetworkManager {
public:
    /**
     * @brief Inicia un servidor socket TCP que escucha en el puerto especificado.
     * Diseñado para recibir alertas o comandos de control remotos.
     * @param port Puerto en el que escuchará el socket (ej. 8888).
     * @return true si el servidor se inició y procesó correctamente, false ante fallos.
     */
    bool startListeningServer(int port) {
        std::cout << "[NETWORK] Iniciando socket del servidor TCP en el puerto " << std::dec << port << "...\n";
        std::cout << "[NETWORK] Servidor a la escucha de conexiones entrantes (Esqueleto/Simulado)...\n";
        
        // Aquí se implementará la inicialización de Winsock (WSAStartup, socket, bind, listen, accept).
        // Para el esqueleto simularemos una respuesta exitosa.
        return true;
    }

    /**
     * @brief Bloquea una dirección IP ejecutando un comando del sistema (ej. Windows Firewall netsh o ruta estática).
     * @param ipAddress Dirección IP a bloquear (ej. "192.168.1.100").
     * @return true si el comando se ejecutó de forma segura, false en caso contrario.
     */
    bool blockIpAddress(const std::string& ipAddress) {
        // Validación básica del formato de la IP para evitar inyecciones de comandos en system()
        if (ipAddress.empty() || ipAddress.find_first_not_of("0123456789.") != std::string::npos) {
            std::cerr << "[NETWORK] Error: Dirección IP no válida o contiene caracteres sospechosos.\n";
            return false;
        }

        std::cout << "[NETWORK] Intentando bloquear IP: " << ipAddress << "\n";
        
        // Construimos el comando usando la sintaxis oficial de netsh en Windows de forma segura.
        // Comando: netsh advfirewall firewall add rule name="Block IP <ip>" dir=in action=block remoteip=<ip>
        std::string command = "netsh advfirewall firewall add rule name=\"IPS_Block_" + ipAddress + "\" dir=in action=block remoteip=" + ipAddress;
        
        std::cout << "[NETWORK] Comando a ejecutar: " << command << "\n";
        
        // Nota: En un entorno de producción, es preferible utilizar la API de Windows (Windows Filtering Platform)
        // o ejecutar el proceso mediante CreateProcess de manera controlada en lugar de system().
        // Como este es el esqueleto base solicitado, preparamos la llamada al sistema.
        
        // int result = std::system(command.c_str());
        // return (result == 0);
        
        return true;
    }
};

#endif // NETWORK_H
