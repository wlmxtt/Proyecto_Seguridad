#pragma once

// =============================================================================
// firewall_monitor.h - Monitor de Red y Firewall
// Módulo de SecureShield para monitorear conexiones TCP activas, puertos
// abiertos, y detectar escaneos de puertos sospechosos en el sistema.
// =============================================================================

// IMPORTANTE: winsock2.h DEBE incluirse ANTES de windows.h para evitar
// conflictos de redefinición de tipos de socket.
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <algorithm>
#include <set>
#include <conio.h>

#include "ui.h"
#include "security_logger.h"

// Vincular las bibliotecas necesarias para funciones de red
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// Umbral para detección de escaneo de puertos: máximo de conexiones nuevas
constexpr int PORT_SCAN_THRESHOLD = 5;

// Ventana de tiempo (segundos) para detección de escaneo de puertos
constexpr int PORT_SCAN_TIME_WINDOW = 5;

// Intervalo de monitoreo continuo en milisegundos (3 segundos)
constexpr DWORD MONITORING_INTERVAL_MS = 3000;

// =============================================================================
// Estructura que representa la información de una conexión TCP
// =============================================================================
struct ConnectionInfo {
    std::string localAddr;   // Dirección IP local
    int         localPort;   // Puerto local
    std::string remoteAddr;  // Dirección IP remota
    int         remotePort;  // Puerto remoto
    std::string state;       // Estado de la conexión (LISTENING, ESTABLISHED, etc.)
};

// =============================================================================
// Clase FirewallMonitor - Monitor de conexiones de red (Singleton)
// Utiliza la API GetTcpTable de iphlpapi para enumerar conexiones TCP activas.
// =============================================================================
class FirewallMonitor {
public:
    // Instantánea anterior de conexiones para detección de anomalías
    std::vector<ConnectionInfo> previousSnapshot;

    // Marca de tiempo de la última instantánea
    time_t lastSnapshotTime = 0;

    // =========================================================================
    // Obtener la instancia única del monitor (patrón Singleton)
    // =========================================================================
    static FirewallMonitor& getInstance() {
        static FirewallMonitor instance;
        return instance;
    }

    // =========================================================================
    // Obtener las conexiones TCP activas del sistema
    // Utiliza GetTcpTable de iphlpapi.h para enumerar la tabla TCP
    // =========================================================================
    std::vector<ConnectionInfo> getActiveConnections() {
        std::vector<ConnectionInfo> connections;

        // Determinar el tamaño necesario del búfer
        DWORD tableSize = 0;
        GetTcpTable(nullptr, &tableSize, TRUE);

        if (tableSize == 0) {
            UI::printWarning("No se pudo obtener el tamaño de la tabla TCP.");
            return connections;
        }

        // Asignar memoria para la tabla TCP
        std::vector<BYTE> buffer(tableSize);
        PMIB_TCPTABLE tcpTable = reinterpret_cast<PMIB_TCPTABLE>(buffer.data());

        DWORD result = GetTcpTable(tcpTable, &tableSize, TRUE);
        if (result != NO_ERROR) {
            UI::printError(
                "Error al obtener la tabla TCP. Código de error: " +
                std::to_string(result)
            );
            return connections;
        }

        // Recorrer todas las entradas de la tabla TCP
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            const MIB_TCPROW& row = tcpTable->table[i];

            ConnectionInfo conn;

            // Convertir direcciones IP de formato de red a cadena legible
            struct in_addr localAddrStruct;
            localAddrStruct.s_addr = row.dwLocalAddr;
            conn.localAddr = std::string(inet_ntoa(localAddrStruct));
            conn.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));

            struct in_addr remoteAddrStruct;
            remoteAddrStruct.s_addr = row.dwRemoteAddr;
            conn.remoteAddr = std::string(inet_ntoa(remoteAddrStruct));
            conn.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));

            // Mapear el estado numérico a una cadena descriptiva
            conn.state = mapTcpState(row.dwState);

            connections.push_back(conn);
        }

        return connections;
    }

    // =========================================================================
    // Mostrar las conexiones activas en formato de tabla formateada
    // =========================================================================
    void showConnections() {
        UI::printHeader("Conexiones TCP Activas");

        auto connections = getActiveConnections();

        if (connections.empty()) {
            UI::printWarning("No se encontraron conexiones TCP activas.");
            return;
        }

        std::cout << "  Total de conexiones: " << connections.size() << "\n\n";

        // Encabezado de la tabla
        std::cout << "  " << std::left
                  << std::setw(20) << "DIRECCION LOCAL"
                  << std::setw(10) << "PUERTO"
                  << std::setw(20) << "DIRECCION REMOTA"
                  << std::setw(10) << "PUERTO"
                  << std::setw(16) << "ESTADO"
                  << "\n";

        UI::printSeparator();

        for (const auto& conn : connections) {
            std::cout << "  " << std::left
                      << std::setw(20) << conn.localAddr
                      << std::setw(10) << conn.localPort
                      << std::setw(20) << conn.remoteAddr
                      << std::setw(10) << conn.remotePort;

            // Colorear según el estado de la conexión
            if (conn.state == "LISTENING") {
                UI::printColored(conn.state, UI::Color::CYAN);
            } else if (conn.state == "ESTABLISHED") {
                UI::printColored(conn.state, UI::Color::GREEN);
            } else if (conn.state == "CLOSE_WAIT" || conn.state == "TIME_WAIT") {
                UI::printColored(conn.state, UI::Color::YELLOW);
            } else {
                std::cout << conn.state;
            }

            std::cout << "\n";
        }

        std::cout << "\n";
    }

    // =========================================================================
    // Escanear un rango de puertos en localhost para verificar cuáles están
    // abiertos (en estado LISTENING)
    // =========================================================================
    void scanPorts(int startPort, int endPort) {
        // Validar el rango de puertos
        if (startPort < 1 || endPort > 65535 || startPort > endPort) {
            UI::printError(
                "Rango de puertos no válido. Debe ser entre 1 y 65535."
            );
            return;
        }

        UI::printHeader("Escaneo de Puertos Locales");
        std::cout << "  Escaneando puertos " << startPort << " - " << endPort << "...\n\n";

        auto connections = getActiveConnections();

        // Recopilar los puertos que están en estado LISTENING
        std::set<int> listeningPorts;
        for (const auto& conn : connections) {
            if (conn.state == "LISTENING" &&
                (conn.localAddr == "0.0.0.0" || conn.localAddr == "127.0.0.1")) {
                listeningPorts.insert(conn.localPort);
            }
        }

        // Mostrar los puertos abiertos dentro del rango solicitado
        int openCount = 0;
        for (int port = startPort; port <= endPort; port++) {
            if (listeningPorts.find(port) != listeningPorts.end()) {
                openCount++;
                std::cout << "  Puerto ";
                UI::printColored(std::to_string(port), UI::Color::GREEN);
                std::cout << " - ";
                UI::printColored("ABIERTO", UI::Color::GREEN);
                std::cout << " (" << getCommonServiceName(port) << ")\n";
            }
        }

        std::cout << "\n";

        if (openCount == 0) {
            UI::printInfo(
                "No se encontraron puertos abiertos en el rango especificado."
            );
        } else {
            UI::printInfo(
                "Se encontraron " + std::to_string(openCount) +
                " puerto(s) abierto(s) en el rango " +
                std::to_string(startPort) + "-" + std::to_string(endPort) + "."
            );
        }

        SecurityLogger::getInstance().log(SecurityLogger::INFO, "RED", "Escaneo de puertos completado: rango " +
            std::to_string(startPort) + "-" + std::to_string(endPort) +
            ", " + std::to_string(openCount) + " puerto(s) abierto(s).");
    }

    // =========================================================================
    // Mostrar todos los puertos que están actualmente en escucha (LISTENING)
    // =========================================================================
    void showOpenPorts() {
        UI::printHeader("Puertos Abiertos (LISTENING)");

        auto connections = getActiveConnections();

        // Filtrar las conexiones para obtener solo las que están escuchando
        // Usar set para evitar duplicados por dirección
        std::set<int> shownPorts;
        int count = 0;

        std::cout << "  " << std::left
                  << std::setw(10) << "PUERTO"
                  << std::setw(20) << "DIRECCION"
                  << std::setw(20) << "SERVICIO"
                  << "\n";

        UI::printSeparator();

        for (const auto& conn : connections) {
            if (conn.state == "LISTENING") {
                // Evitar mostrar el mismo puerto múltiples veces
                int portKey = conn.localPort;
                if (shownPorts.find(portKey) != shownPorts.end()) {
                    continue;
                }
                shownPorts.insert(portKey);

                std::cout << "  " << std::left
                          << std::setw(10) << conn.localPort
                          << std::setw(20) << conn.localAddr
                          << std::setw(20) << getCommonServiceName(conn.localPort)
                          << "\n";
                count++;
            }
        }

        std::cout << "\n";

        if (count == 0) {
            UI::printInfo("No se detectaron puertos en escucha.");
        } else {
            UI::printInfo(
                "Total de puertos en escucha: " + std::to_string(count)
            );
        }
    }

    // =========================================================================
    // Detectar posible escaneo de puertos
    // Compara la instantánea actual con la anterior. Si se detectan más de
    // PORT_SCAN_THRESHOLD conexiones nuevas a puertos diferentes en un período
    // de PORT_SCAN_TIME_WINDOW segundos, se genera una alerta crítica.
    // Retorna true si se detectó un escaneo de puertos.
    // =========================================================================
    bool detectPortScan() {
        auto currentConnections = getActiveConnections();
        time_t currentTime = std::time(nullptr);

        // Si no hay instantánea previa, guardar la actual como referencia
        if (previousSnapshot.empty() || lastSnapshotTime == 0) {
            previousSnapshot = currentConnections;
            lastSnapshotTime = currentTime;
            return false;
        }

        // Verificar si estamos dentro de la ventana de tiempo
        double elapsed = difftime(currentTime, lastSnapshotTime);

        // Construir un conjunto con las conexiones anteriores para búsqueda rápida
        std::set<std::string> previousKeys;
        for (const auto& conn : previousSnapshot) {
            std::string key = conn.remoteAddr + ":" + std::to_string(conn.remotePort) +
                              "->" + conn.localAddr + ":" + std::to_string(conn.localPort);
            previousKeys.insert(key);
        }

        // Encontrar conexiones nuevas que no estaban en la instantánea anterior
        std::set<int> newPorts;          // Puertos locales objetivo nuevos
        std::set<std::string> newSources; // Direcciones remotas nuevas
        int newConnectionCount = 0;

        for (const auto& conn : currentConnections) {
            std::string key = conn.remoteAddr + ":" + std::to_string(conn.remotePort) +
                              "->" + conn.localAddr + ":" + std::to_string(conn.localPort);

            if (previousKeys.find(key) == previousKeys.end()) {
                newConnectionCount++;
                newPorts.insert(conn.localPort);
                newSources.insert(conn.remoteAddr);
            }
        }

        // Actualizar la instantánea
        previousSnapshot = currentConnections;
        lastSnapshotTime = currentTime;

        // Determinar si hay un posible escaneo de puertos:
        // Más de PORT_SCAN_THRESHOLD conexiones nuevas a puertos diferentes
        // dentro de PORT_SCAN_TIME_WINDOW segundos
        if (elapsed <= PORT_SCAN_TIME_WINDOW &&
            static_cast<int>(newPorts.size()) > PORT_SCAN_THRESHOLD) {

            // Construir la lista de puertos detectados
            std::ostringstream portsStr;
            int portCount = 0;
            for (int port : newPorts) {
                if (portCount > 0) portsStr << ", ";
                portsStr << port;
                portCount++;
                if (portCount >= 10) {
                    portsStr << "...";
                    break;
                }
            }

            // Construir la lista de orígenes sospechosos
            std::ostringstream sourcesStr;
            for (const auto& src : newSources) {
                sourcesStr << src << " ";
            }

            std::string alertMsg =
                "¡POSIBLE ESCANEO DE PUERTOS DETECTADO! " +
                std::to_string(newPorts.size()) + " puertos nuevos contactados en " +
                std::to_string(static_cast<int>(elapsed)) + " segundos. " +
                "Puertos: [" + portsStr.str() + "] " +
                "Orígenes: [" + sourcesStr.str() + "]";

            // Registrar alerta CRITICA
            SecurityLogger::getInstance().log(SecurityLogger::CRITICAL, "RED", alertMsg);

            UI::printError("¡ALERTA CRITICA!");
            UI::printError(alertMsg);

            return true;
        }

        return false;
    }

    // =========================================================================
    // Iniciar modo de monitoreo continuo
    // Bucle con intervalo de 3 segundos. Muestra conexiones, detecta anomalías
    // y registra alertas. Presionar 'q' para salir.
    // =========================================================================
    void startMonitoring() {
        UI::printHeader("Modo de Monitoreo Continuo de Red");
        std::cout << "  Intervalo de actualización: "
                  << (MONITORING_INTERVAL_MS / 1000) << " segundos\n";
        std::cout << "  Presione 'q' para detener el monitoreo.\n\n";

        SecurityLogger::getInstance().log(SecurityLogger::INFO, "RED", "Monitoreo continuo de red iniciado.");

        // Tomar la primera instantánea
        previousSnapshot = getActiveConnections();
        lastSnapshotTime = std::time(nullptr);

        bool monitoring = true;

        while (monitoring) {
            // Limpiar pantalla para actualización limpia
            system("cls");

            UI::printHeader("Monitoreo de Red en Tiempo Real");

            // Mostrar marca de tiempo actual
            time_t now = std::time(nullptr);
            char timeBuffer[26];
            ctime_s(timeBuffer, sizeof(timeBuffer), &now);
            std::cout << "  Última actualización: " << timeBuffer;

            // Obtener y mostrar conexiones actuales
            auto connections = getActiveConnections();

            // Estadísticas rápidas
            int listening = 0, established = 0, other = 0;
            for (const auto& conn : connections) {
                if (conn.state == "LISTENING") listening++;
                else if (conn.state == "ESTABLISHED") established++;
                else other++;
            }

            std::cout << "  Conexiones: ";
            UI::printColored(std::to_string(connections.size()) + " total", UI::Color::WHITE);
            std::cout << " | ";
            UI::printColored(std::to_string(listening) + " escuchando", UI::Color::CYAN);
            std::cout << " | ";
            UI::printColored(std::to_string(established) + " establecidas", UI::Color::GREEN);
            std::cout << " | ";
            UI::printColored(std::to_string(other) + " otras", UI::Color::YELLOW);
            std::cout << "\n\n";

            // Mostrar tabla de conexiones (solo las primeras 20 para legibilidad)
            std::cout << "  " << std::left
                      << std::setw(18) << "LOCAL"
                      << std::setw(8)  << "PUERTO"
                      << std::setw(18) << "REMOTA"
                      << std::setw(8)  << "PUERTO"
                      << std::setw(14) << "ESTADO"
                      << "\n";

            UI::printSeparator();

            int displayed = 0;
            for (const auto& conn : connections) {
                if (displayed >= 20) {
                    std::cout << "  ... y " << (connections.size() - 20)
                              << " conexiones más.\n";
                    break;
                }

                std::cout << "  " << std::left
                          << std::setw(18) << conn.localAddr
                          << std::setw(8)  << conn.localPort
                          << std::setw(18) << conn.remoteAddr
                          << std::setw(8)  << conn.remotePort
                          << std::setw(14) << conn.state
                          << "\n";
                displayed++;
            }

            std::cout << "\n";

            // Detectar escaneo de puertos
            if (detectPortScan()) {
                UI::printError(
                    "¡ALERTA! Posible escaneo de puertos detectado. "
                    "Revise el registro de seguridad para más detalles."
                );
            }

            std::cout << "\n  Presione 'q' para detener el monitoreo...\n";

            // Esperar el intervalo de monitoreo, verificando si se presionó 'q'
            DWORD elapsed = 0;
            while (elapsed < MONITORING_INTERVAL_MS) {
                if (_kbhit()) {
                    int key = _getch();
                    if (key == 'q' || key == 'Q') {
                        monitoring = false;
                        break;
                    }
                }
                Sleep(100);
                elapsed += 100;
            }
        }

        SecurityLogger::getInstance().log(SecurityLogger::INFO, "RED", "Monitoreo continuo de red detenido por el usuario.");

        UI::printInfo("Monitoreo de red detenido.");
    }

    // =========================================================================
    // Menú interactivo del monitor de red
    // Opciones: Conexiones, Puertos abiertos, Monitoreo continuo, Escanear rango
    // =========================================================================
    void interactiveMenu() {
        bool running = true;

        while (running) {
            UI::printHeader("Monitor de Red y Firewall");

            std::cout << "  [1] Mostrar conexiones activas\n";
            std::cout << "  [2] Mostrar puertos abiertos\n";
            std::cout << "  [3] Iniciar monitoreo continuo\n";
            std::cout << "  [4] Escanear rango de puertos\n";
            std::cout << "  [5] Detectar escaneo de puertos\n";
            std::cout << "  [0] Volver al menú principal\n";

            UI::printSeparator();
            std::cout << "  Seleccione una opción: ";

            std::string input;
            std::getline(std::cin, input);

            if (input.empty()) continue;

            switch (input[0]) {
                case '1': {
                    // Mostrar conexiones TCP activas
                    showConnections();
                    break;
                }
                case '2': {
                    // Mostrar puertos en escucha
                    showOpenPorts();
                    break;
                }
                case '3': {
                    // Iniciar monitoreo continuo
                    startMonitoring();
                    break;
                }
                case '4': {
                    // Escanear rango de puertos
                    std::cout << "\n  Ingrese el puerto inicial: ";
                    std::string startStr;
                    std::getline(std::cin, startStr);

                    std::cout << "  Ingrese el puerto final: ";
                    std::string endStr;
                    std::getline(std::cin, endStr);

                    try {
                        int startPort = std::stoi(startStr);
                        int endPort = std::stoi(endStr);
                        scanPorts(startPort, endPort);
                    } catch (const std::exception&) {
                        UI::printError(
                            "Entrada no válida. Ingrese números enteros para los puertos."
                        );
                    }
                    break;
                }
                case '5': {
                    // Detección manual de escaneo de puertos
                    UI::printHeader("Detección de Escaneo de Puertos");
                    std::cout << "  Analizando conexiones actuales contra la instantánea anterior...\n\n";

                    if (detectPortScan()) {
                        UI::printError(
                            "¡Se detectó actividad sospechosa de escaneo de puertos!"
                        );
                    } else {
                        UI::printSuccess(
                            "No se detectó actividad sospechosa. Las conexiones parecen normales."
                        );
                    }
                    break;
                }
                case '0': {
                    // Salir del menú
                    running = false;
                    UI::printInfo("Regresando al menú principal...");
                    break;
                }
                default: {
                    UI::printWarning("Opción no válida. Intente de nuevo.");
                    break;
                }
            }

            if (running) {
                std::cout << "\n  Presione Enter para continuar...";
                std::cin.get();
            }
        }
    }

    // =========================================================================
    // Obtener el número total de conexiones activas
    // =========================================================================
    int getConnectionCount() {
        auto connections = getActiveConnections();
        return static_cast<int>(connections.size());
    }

private:
    // Constructor privado (patrón Singleton)
    FirewallMonitor() {
        // Inicializar Winsock para uso de funciones de red
        WSADATA wsaData;
        int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (wsaResult != 0) {
            std::cerr << "  [ERROR] No se pudo inicializar Winsock. "
                      << "Código de error: " << wsaResult << "\n";
        }
    }

    // Destructor: liberar recursos de Winsock
    ~FirewallMonitor() {
        WSACleanup();
    }

    // Eliminar constructor de copia y operador de asignación
    FirewallMonitor(const FirewallMonitor&) = delete;
    FirewallMonitor& operator=(const FirewallMonitor&) = delete;

    // =========================================================================
    // Mapear el estado numérico TCP a una cadena descriptiva en español/estándar
    // =========================================================================
    std::string mapTcpState(DWORD state) {
        switch (state) {
            case MIB_TCP_STATE_CLOSED:      return "CLOSED";
            case MIB_TCP_STATE_LISTEN:      return "LISTENING";
            case MIB_TCP_STATE_SYN_SENT:    return "SYN_SENT";
            case MIB_TCP_STATE_SYN_RCVD:    return "SYN_RCVD";
            case MIB_TCP_STATE_ESTAB:       return "ESTABLISHED";
            case MIB_TCP_STATE_FIN_WAIT1:   return "FIN_WAIT_1";
            case MIB_TCP_STATE_FIN_WAIT2:   return "FIN_WAIT_2";
            case MIB_TCP_STATE_CLOSE_WAIT:  return "CLOSE_WAIT";
            case MIB_TCP_STATE_CLOSING:     return "CLOSING";
            case MIB_TCP_STATE_LAST_ACK:    return "LAST_ACK";
            case MIB_TCP_STATE_TIME_WAIT:   return "TIME_WAIT";
            case MIB_TCP_STATE_DELETE_TCB:  return "DELETE_TCB";
            default:                        return "DESCONOCIDO";
        }
    }

    // =========================================================================
    // Obtener el nombre del servicio común asociado a un puerto conocido
    // =========================================================================
    std::string getCommonServiceName(int port) {
        switch (port) {
            case 20:    return "FTP-DATA";
            case 21:    return "FTP";
            case 22:    return "SSH";
            case 23:    return "TELNET";
            case 25:    return "SMTP";
            case 53:    return "DNS";
            case 80:    return "HTTP";
            case 110:   return "POP3";
            case 135:   return "RPC";
            case 139:   return "NetBIOS";
            case 143:   return "IMAP";
            case 443:   return "HTTPS";
            case 445:   return "SMB";
            case 993:   return "IMAPS";
            case 995:   return "POP3S";
            case 1433:  return "MSSQL";
            case 1521:  return "Oracle";
            case 3306:  return "MySQL";
            case 3389:  return "RDP";
            case 5432:  return "PostgreSQL";
            case 5900:  return "VNC";
            case 8080:  return "HTTP-ALT";
            case 8443:  return "HTTPS-ALT";
            default:    return "Desconocido";
        }
    }
};
