/*
 * ============================================================================
 *  ATTACKER TOOL v1.0 - Herramienta de Simulacion de Ataques
 * ============================================================================
 *  Herramienta complementaria para demostrar como SecureShield protege
 *  el sistema ante ataques comunes.
 * 
 *  NOTA: Esta herramienta es SOLO para fines educativos y de demostracion.
 * ============================================================================
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <conio.h>
#include <ctime>
#include <thread>
#include <chrono>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

// ============================================================================
//  UTILIDADES DE CONSOLA
// ============================================================================
namespace AttackUI {
    const int RED = 12;
    const int GREEN = 10;
    const int YELLOW = 14;
    const int CYAN = 11;
    const int WHITE = 15;
    const int DARK_RED = 4;
    const int MAGENTA = 13;
    
    void setColor(int color) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
    }
    
    void resetColor() {
        setColor(WHITE);
    }
    
    void clearScreen() {
        system("cls");
    }
    
    void printBanner() {
        clearScreen();
        setColor(RED);
        cout << endl;
        cout << "  ================================================================" << endl;
        cout << "  |                                                              |" << endl;
        cout << "  |     ___  ______ _____  ___   _____ _   __ ___________        |" << endl;
        cout << "  |    / _ \\|_   _||_   _|/ _ \\ /  __ | | / /|  ___| ___ \\      |" << endl;
        cout << "  |   / /_\\ \\ | |    | | / /_\\ \\| /  \\| |/ / | |__ | |_/ /      |" << endl;
        cout << "  |   |  _  | | |    | | |  _  || |   |    \\ |  __||    /        |" << endl;
        cout << "  |   | | | | | |    | | | | | || \\__/| |\\  \\| |___| |\\ \\       |" << endl;
        cout << "  |   \\_| |_/ \\_/    \\_/ \\_| |_/ \\____|_| \\_/\\____/\\_| \\_|      |" << endl;
        cout << "  |                                                              |" << endl;
        cout << "  |       HERRAMIENTA DE SIMULACION DE ATAQUES v1.0              |" << endl;
        cout << "  |       Solo para fines educativos y demostracion              |" << endl;
        cout << "  |                                                              |" << endl;
        cout << "  ================================================================" << endl;
        resetColor();
    }
    
    void printProgress(const string& msg, int current, int total) {
        setColor(YELLOW);
        cout << "\r  [";
        int barWidth = 30;
        int pos = (int)((float)current / total * barWidth);
        for (int i = 0; i < barWidth; i++) {
            if (i < pos) cout << "=";
            else if (i == pos) cout << ">";
            else cout << " ";
        }
        cout << "] " << current << "/" << total << " " << msg << "   " << flush;
        resetColor();
    }
}

// ============================================================================
//  ATAQUE 1: FUERZA BRUTA AL LOGIN
// ============================================================================
void atacqueFuerzaBruta() {
    AttackUI::clearScreen();
    AttackUI::setColor(AttackUI::RED);
    cout << endl;
    cout << "  ================================================================" << endl;
    cout << "  |  ATAQUE 1: FUERZA BRUTA AL SISTEMA DE AUTENTICACION         |" << endl;
    cout << "  ================================================================" << endl;
    AttackUI::resetColor();
    cout << endl;
    
    AttackUI::setColor(AttackUI::YELLOW);
    cout << "  Este ataque intenta adivinar la contrasena del administrador" << endl;
    cout << "  probando multiples contrasenas comunes rapidamente." << endl;
    cout << endl;
    cout << "  SecureShield deberia detectar los intentos fallidos repetidos" << endl;
    cout << "  y bloquear la cuenta para prevenir el acceso no autorizado." << endl;
    AttackUI::resetColor();
    cout << endl;
    
    // Lista de contrasenas comunes
    vector<string> passwords = {
        "123456", "password", "admin", "root", "letmein",
        "qwerty", "abc123", "monkey", "master", "dragon",
        "login", "princess", "football", "shadow", "sunshine",
        "trustno1", "iloveyou", "batman", "access", "hello",
        "charlie", "donald", "password1", "qwerty123", "admin123"
    };
    
    string targetUser;
    cout << "  Usuario objetivo (default: admin): ";
    getline(cin, targetUser);
    if (targetUser.empty()) targetUser = "admin";
    
    cout << endl;
    AttackUI::setColor(AttackUI::RED);
    cout << "  [*] Iniciando ataque de fuerza bruta contra '" << targetUser << "'..." << endl;
    cout << "  [*] Diccionario cargado: " << passwords.size() << " contrasenas" << endl;
    AttackUI::resetColor();
    cout << endl;
    
    // Abrir archivo de usuarios para intentar login
    // Simulamos los intentos escribiendo a un archivo que SecureShield puede monitorear
    ofstream attackLog("attack_bruteforce.log", ios::app);
    
    for (int i = 0; i < (int)passwords.size(); i++) {
        AttackUI::printProgress("Probando: " + passwords[i], i + 1, (int)passwords.size());
        
        // Registrar intento
        time_t now = time(nullptr);
        char timeStr[64];
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &timeinfo);
        
        attackLog << "[" << timeStr << "] Intento de login - Usuario: " 
                  << targetUser << " - Contrasena: " << passwords[i] << endl;
        
        // Intentar conectar al puerto de SecureShield (si esta escuchando)
        // En la demo real, SecureShield detecta los intentos por el archivo de log
        Sleep(200); // Pausa para efecto visual
    }
    
    attackLog.close();
    
    cout << endl << endl;
    AttackUI::setColor(AttackUI::RED);
    cout << "  [!] Ataque completado." << endl;
    cout << "  [!] Se realizaron " << passwords.size() << " intentos de acceso." << endl;
    AttackUI::setColor(AttackUI::YELLOW);
    cout << endl;
    cout << "  >>> Verifica SecureShield - La cuenta deberia estar BLOQUEADA <<<" << endl;
    cout << "  >>> y las alertas registradas en el log de seguridad.          <<<" << endl;
    AttackUI::resetColor();
    cout << endl;
    
    cout << "  Presione Enter para continuar...";
    cin.get();
}

// ============================================================================
//  ATAQUE 2: MODIFICACION DE ARCHIVOS (TAMPERING)
// ============================================================================
void ataqueTampering() {
    AttackUI::clearScreen();
    AttackUI::setColor(AttackUI::RED);
    cout << endl;
    cout << "  ================================================================" << endl;
    cout << "  |  ATAQUE 2: MODIFICACION DE ARCHIVOS PROTEGIDOS (TAMPERING)  |" << endl;
    cout << "  ================================================================" << endl;
    AttackUI::resetColor();
    cout << endl;
    
    AttackUI::setColor(AttackUI::YELLOW);
    cout << "  Este ataque modifica archivos que estan siendo monitoreados" << endl;
    cout << "  por SecureShield, simulando un malware que altera archivos" << endl;
    cout << "  criticos del sistema." << endl;
    cout << endl;
    cout << "  SecureShield deberia detectar que el hash del archivo cambio" << endl;
    cout << "  y generar una alerta CRITICA de integridad comprometida." << endl;
    AttackUI::resetColor();
    cout << endl;
    
    string targetFile;
    cout << "  Archivo a modificar (o Enter para crear uno de prueba): ";
    getline(cin, targetFile);
    
    if (targetFile.empty()) {
        targetFile = "archivo_protegido.txt";
        
        // Crear archivo de prueba si no existe
        ifstream checkFile(targetFile);
        if (!checkFile.good()) {
            ofstream createFile(targetFile);
            createFile << "Este es un archivo protegido del sistema." << endl;
            createFile << "Contenido original - No debe ser modificado." << endl;
            createFile << "Datos criticos de configuracion del sistema." << endl;
            createFile << "Fecha de creacion: " << __DATE__ << " " << __TIME__ << endl;
            createFile.close();
            
            AttackUI::setColor(AttackUI::CYAN);
            cout << "  [*] Archivo de prueba creado: " << targetFile << endl;
            cout << "  [!] IMPORTANTE: Primero agrega este archivo al Monitor de" << endl;
            cout << "      Integridad de SecureShield (Opcion 4 > Agregar archivo)" << endl;
            cout << "      y luego vuelve aqui para ejecutar el ataque." << endl;
            AttackUI::resetColor();
            cout << endl;
            cout << "  Presione Enter cuando haya agregado el archivo al monitor...";
            cin.get();
        }
    }
    
    cout << endl;
    AttackUI::setColor(AttackUI::RED);
    cout << "  [*] Leyendo archivo original..." << endl;
    Sleep(500);
    
    // Leer contenido original
    ifstream fileIn(targetFile);
    string originalContent = "";
    if (fileIn.is_open()) {
        string line;
        while (getline(fileIn, line)) {
            originalContent += line + "\n";
        }
        fileIn.close();
    }
    
    cout << "  [*] Contenido original:" << endl;
    AttackUI::setColor(AttackUI::WHITE);
    cout << "  ---" << endl;
    cout << "  " << originalContent.substr(0, 200) << endl;
    cout << "  ---" << endl;
    
    Sleep(500);
    AttackUI::setColor(AttackUI::RED);
    cout << "  [*] Inyectando codigo malicioso en el archivo..." << endl;
    Sleep(800);
    
    // Modificar el archivo (simular malware)
    ofstream fileOut(targetFile);
    if (fileOut.is_open()) {
        fileOut << originalContent;
        fileOut << endl;
        fileOut << "=== CONTENIDO INYECTADO POR MALWARE ===" << endl;
        fileOut << "Este contenido fue insertado por un atacante." << endl;
        fileOut << "El archivo ha sido comprometido." << endl;
        fileOut << "Datos robados y enviados al servidor del atacante." << endl;
        fileOut << "Timestamp del ataque: ";
        
        time_t now = time(nullptr);
        char timeStr[64];
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &timeinfo);
        fileOut << timeStr << endl;
        fileOut << "=========================================" << endl;
        fileOut.close();
        
        cout << "  [!] Archivo modificado exitosamente!" << endl;
        cout << "  [!] Se inyecto codigo malicioso en: " << targetFile << endl;
    } else {
        AttackUI::setColor(AttackUI::YELLOW);
        cout << "  [X] Error: No se pudo acceder al archivo." << endl;
    }
    
    cout << endl;
    AttackUI::setColor(AttackUI::YELLOW);
    cout << "  >>> Verifica SecureShield - El Monitor de Integridad deberia    <<<" << endl;
    cout << "  >>> detectar que el hash del archivo cambio y generar alerta.   <<<" << endl;
    cout << "  >>> Ve a Opcion 4 > Verificar todos los archivos               <<<" << endl;
    AttackUI::resetColor();
    cout << endl;
    
    cout << "  Presione Enter para continuar...";
    cin.get();
}

// ============================================================================
//  ATAQUE 3: ESCANEO DE PUERTOS
// ============================================================================
void ataqueEscaneoPuertos() {
    AttackUI::clearScreen();
    AttackUI::setColor(AttackUI::RED);
    cout << endl;
    cout << "  ================================================================" << endl;
    cout << "  |  ATAQUE 3: ESCANEO DE PUERTOS (PORT SCANNING)               |" << endl;
    cout << "  ================================================================" << endl;
    AttackUI::resetColor();
    cout << endl;
    
    AttackUI::setColor(AttackUI::YELLOW);
    cout << "  Este ataque escanea los puertos de la computadora local" << endl;
    cout << "  para descubrir servicios activos y posibles vulnerabilidades." << endl;
    cout << endl;
    cout << "  SecureShield deberia detectar el escaneo masivo de puertos" << endl;
    cout << "  y generar una alerta en el firewall." << endl;
    AttackUI::resetColor();
    cout << endl;
    
    int startPort, endPort;
    cout << "  Puerto inicial (default: 1): ";
    string input;
    getline(cin, input);
    startPort = input.empty() ? 1 : stoi(input);
    
    cout << "  Puerto final (default: 1024): ";
    getline(cin, input);
    endPort = input.empty() ? 1024 : stoi(input);
    
    cout << endl;
    AttackUI::setColor(AttackUI::RED);
    cout << "  [*] Iniciando escaneo de puertos " << startPort << " - " << endPort << " en localhost..." << endl;
    cout << "  [*] Metodo: TCP Connect Scan" << endl;
    AttackUI::resetColor();
    cout << endl;
    
    vector<int> openPorts;
    int scanned = 0;
    int total = endPort - startPort + 1;
    
    for (int port = startPort; port <= endPort; port++) {
        scanned++;
        
        if (scanned % 10 == 0 || port == endPort) {
            AttackUI::printProgress("escaneando...", scanned, total);
        }
        
        // Intentar conexion TCP al puerto
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) continue;
        
        // Configurar timeout corto
        DWORD timeout = 100; // 100ms
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
        
        // Modo no bloqueante para scan rapido
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        
        int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        
        if (result == 0) {
            // Puerto abierto inmediatamente
            openPorts.push_back(port);
        } else {
            // Esperar un poco para ver si la conexion se completa
            fd_set writeSet;
            FD_ZERO(&writeSet);
            FD_SET(sock, &writeSet);
            
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 50000; // 50ms
            
            if (select(0, NULL, &writeSet, NULL, &tv) > 0) {
                int error = 0;
                int len = sizeof(error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
                if (error == 0) {
                    openPorts.push_back(port);
                }
            }
        }
        
        closesocket(sock);
    }
    
    cout << endl << endl;
    
    // Mostrar resultados
    AttackUI::setColor(AttackUI::RED);
    cout << "  [!] Escaneo completado. " << scanned << " puertos escaneados." << endl;
    cout << endl;
    
    if (!openPorts.empty()) {
        AttackUI::setColor(AttackUI::GREEN);
        cout << "  Puertos abiertos encontrados: " << openPorts.size() << endl;
        cout << "  +--------+-------------------+" << endl;
        cout << "  | Puerto | Estado            |" << endl;
        cout << "  +--------+-------------------+" << endl;
        
        for (int port : openPorts) {
            string service = "Desconocido";
            if (port == 80) service = "HTTP";
            else if (port == 443) service = "HTTPS";
            else if (port == 21) service = "FTP";
            else if (port == 22) service = "SSH";
            else if (port == 23) service = "Telnet";
            else if (port == 25) service = "SMTP";
            else if (port == 53) service = "DNS";
            else if (port == 110) service = "POP3";
            else if (port == 135) service = "RPC";
            else if (port == 139) service = "NetBIOS";
            else if (port == 445) service = "SMB";
            else if (port == 3306) service = "MySQL";
            else if (port == 3389) service = "RDP";
            else if (port == 5432) service = "PostgreSQL";
            else if (port == 8080) service = "HTTP-Alt";
            
            cout << "  | " << port;
            for (int s = 0; s < (int)(6 - to_string(port).length()); s++) cout << " ";
            cout << "| " << service;
            for (int s = 0; s < (int)(18 - service.length()); s++) cout << " ";
            cout << "|" << endl;
        }
        cout << "  +--------+-------------------+" << endl;
    } else {
        AttackUI::setColor(AttackUI::YELLOW);
        cout << "  No se encontraron puertos abiertos en el rango escaneado." << endl;
    }
    
    cout << endl;
    AttackUI::setColor(AttackUI::YELLOW);
    cout << "  >>> Verifica SecureShield - El Firewall deberia haber detectado  <<<" << endl;
    cout << "  >>> el escaneo masivo de puertos y registrado alertas.           <<<" << endl;
    cout << "  >>> Ve a Opcion 5 > Ver conexiones activas                      <<<" << endl;
    AttackUI::resetColor();
    cout << endl;
    
    // Guardar log del escaneo
    ofstream scanLog("attack_portscan.log");
    time_t now = time(nullptr);
    char timeStr[64];
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &timeinfo);
    scanLog << "Port Scan realizado: " << timeStr << endl;
    scanLog << "Rango: " << startPort << " - " << endPort << endl;
    scanLog << "Puertos abiertos: " << openPorts.size() << endl;
    for (int p : openPorts) scanLog << "  Puerto " << p << " ABIERTO" << endl;
    scanLog.close();
    
    cout << "  Presione Enter para continuar...";
    cin.get();
}

// ============================================================================
//  ATAQUE 4: ATAQUE COMBINADO
// ============================================================================
void ataqueCombinado() {
    AttackUI::clearScreen();
    AttackUI::setColor(AttackUI::RED);
    cout << endl;
    cout << "  ================================================================" << endl;
    cout << "  |  ATAQUE 4: ATAQUE COMBINADO (TODOS LOS ATAQUES)             |" << endl;
    cout << "  ================================================================" << endl;
    AttackUI::resetColor();
    cout << endl;
    
    AttackUI::setColor(AttackUI::YELLOW);
    cout << "  Este modo ejecuta TODOS los ataques en secuencia:" << endl;
    cout << "    1. Escaneo de puertos" << endl;
    cout << "    2. Fuerza bruta" << endl;
    cout << "    3. Modificacion de archivos" << endl;
    cout << endl;
    cout << "  Ideal para la demostracion final." << endl;
    AttackUI::resetColor();
    cout << endl;
    
    cout << "  Presione Enter para iniciar el ataque combinado...";
    cin.get();
    
    AttackUI::setColor(AttackUI::RED);
    cout << endl;
    cout << "  ====== FASE 1: Reconocimiento (Escaneo de Puertos) ======" << endl;
    AttackUI::resetColor();
    Sleep(1000);
    
    // Escaneo rapido de puertos comunes
    vector<int> commonPorts = {21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 
                                993, 995, 1433, 3306, 3389, 5432, 8080, 8443};
    
    cout << "  Escaneando " << commonPorts.size() << " puertos comunes..." << endl;
    for (int i = 0; i < (int)commonPorts.size(); i++) {
        int port = commonPorts[i];
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock != INVALID_SOCKET) {
            u_long mode = 1;
            ioctlsocket(sock, FIONBIO, &mode);
            
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            addr.sin_addr.s_addr = inet_addr("127.0.0.1");
            
            connect(sock, (struct sockaddr*)&addr, sizeof(addr));
            
            fd_set writeSet;
            FD_ZERO(&writeSet);
            FD_SET(sock, &writeSet);
            struct timeval tv = {0, 30000};
            
            AttackUI::setColor(AttackUI::DARK_RED);
            if (select(0, NULL, &writeSet, NULL, &tv) > 0) {
                cout << "  [+] Puerto " << port << " - ABIERTO" << endl;
            } else {
                cout << "  [-] Puerto " << port << " - cerrado" << endl;
            }
            closesocket(sock);
        }
        Sleep(100);
    }
    
    cout << endl;
    AttackUI::setColor(AttackUI::RED);
    cout << "  ====== FASE 2: Fuerza Bruta ======" << endl;
    AttackUI::resetColor();
    Sleep(1000);
    
    vector<string> quickPasswords = {"admin", "123456", "password", "root", "admin123", 
                                      "letmein", "qwerty", "master"};
    
    ofstream bruteLog("attack_bruteforce.log", ios::app);
    for (const auto& pwd : quickPasswords) {
        AttackUI::setColor(AttackUI::DARK_RED);
        cout << "  [*] Probando contrasena: " << pwd << " ... ";
        
        time_t now = time(nullptr);
        char timeStr[64];
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &timeinfo);
        bruteLog << "[" << timeStr << "] Intento: admin / " << pwd << endl;
        
        AttackUI::setColor(AttackUI::RED);
        cout << "FALLIDO" << endl;
        Sleep(300);
    }
    bruteLog.close();
    
    cout << endl;
    AttackUI::setColor(AttackUI::RED);
    cout << "  ====== FASE 3: Tampering de Archivos ======" << endl;
    AttackUI::resetColor();
    Sleep(1000);
    
    // Modificar archivo protegido
    string targetFile = "archivo_protegido.txt";
    ifstream checkFile(targetFile);
    if (checkFile.good()) {
        checkFile.close();
        
        // Leer y modificar
        ifstream fin(targetFile);
        string content((istreambuf_iterator<char>(fin)), istreambuf_iterator<char>());
        fin.close();
        
        ofstream fout(targetFile);
        fout << content;
        fout << "\n=== MALWARE INYECTADO [" << __TIMESTAMP__ << "] ===" << endl;
        fout << "Sistema comprometido por atacante." << endl;
        fout.close();
        
        AttackUI::setColor(AttackUI::DARK_RED);
        cout << "  [!] Archivo '" << targetFile << "' modificado con exito." << endl;
    } else {
        AttackUI::setColor(AttackUI::YELLOW);
        cout << "  [X] Archivo protegido no encontrado. Creando uno..." << endl;
        ofstream newFile(targetFile);
        newFile << "Archivo critico del sistema" << endl;
        newFile << "=== MALWARE INYECTADO ===" << endl;
        newFile.close();
        cout << "  [!] Archivo creado y comprometido." << endl;
    }
    
    cout << endl;
    AttackUI::setColor(AttackUI::RED);
    cout << "  ================================================================" << endl;
    cout << "  |  ATAQUE COMBINADO COMPLETADO                                 |" << endl;
    cout << "  ================================================================" << endl;
    AttackUI::setColor(AttackUI::YELLOW);
    cout << endl;
    cout << "  >>> AHORA ve a SecureShield y verifica:                        <<<" << endl;
    cout << "  >>> 1. Panel de Seguridad (Opcion 6) - Estado general          <<<" << endl;
    cout << "  >>> 2. Monitor de Integridad (Opcion 4) - Archivos modificados <<<" << endl;
    cout << "  >>> 3. Registros de Seguridad (Opcion 7) - Todas las alertas   <<<" << endl;
    AttackUI::resetColor();
    cout << endl;
    
    cout << "  Presione Enter para continuar...";
    cin.get();
}

// ============================================================================
//  MENU PRINCIPAL DEL ATACANTE
// ============================================================================
int main() {
    // Configurar consola
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    
    // Inicializar Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    bool running = true;
    while (running) {
        AttackUI::printBanner();
        
        cout << endl;
        AttackUI::setColor(AttackUI::YELLOW);
        cout << "  +--------------------------------------------+" << endl;
        cout << "  |          ATAQUES DISPONIBLES               |" << endl;
        cout << "  +--------------------------------------------+" << endl;
        AttackUI::resetColor();
        cout << endl;
        
        AttackUI::setColor(AttackUI::RED);
        cout << "   [1] ";
        AttackUI::setColor(AttackUI::WHITE);
        cout << "Ataque de Fuerza Bruta (Login)" << endl;
        
        AttackUI::setColor(AttackUI::RED);
        cout << "   [2] ";
        AttackUI::setColor(AttackUI::WHITE);
        cout << "Modificacion de Archivos (Tampering)" << endl;
        
        AttackUI::setColor(AttackUI::RED);
        cout << "   [3] ";
        AttackUI::setColor(AttackUI::WHITE);
        cout << "Escaneo de Puertos (Port Scan)" << endl;
        
        AttackUI::setColor(AttackUI::RED);
        cout << "   [4] ";
        AttackUI::setColor(AttackUI::WHITE);
        cout << "Ataque Combinado (Todos)" << endl;
        
        AttackUI::setColor(AttackUI::RED);
        cout << "   [0] ";
        AttackUI::setColor(AttackUI::WHITE);
        cout << "Salir" << endl;
        
        cout << endl;
        AttackUI::setColor(AttackUI::WHITE);
        cout << "  Seleccione un ataque: ";
        AttackUI::setColor(AttackUI::RED);
        
        int option;
        cin >> option;
        cin.ignore(10000, '\n');
        
        AttackUI::resetColor();
        
        switch (option) {
            case 1: atacqueFuerzaBruta(); break;
            case 2: ataqueTampering(); break;
            case 3: ataqueEscaneoPuertos(); break;
            case 4: ataqueCombinado(); break;
            case 0:
                AttackUI::clearScreen();
                AttackUI::setColor(AttackUI::RED);
                cout << endl;
                cout << "  Herramienta de ataque cerrada." << endl;
                AttackUI::resetColor();
                cout << endl;
                running = false;
                break;
            default:
                AttackUI::setColor(AttackUI::YELLOW);
                cout << "  Opcion no valida." << endl;
                AttackUI::resetColor();
                Sleep(1000);
                break;
        }
    }
    
    WSACleanup();
    return 0;
}
