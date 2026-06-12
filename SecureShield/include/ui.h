#pragma once
// =============================================================================
// ui.h - Utilidades de interfaz de consola para SecureShield
// Proporciona funciones de color, banners, mensajes formateados y entrada segura.
// =============================================================================

#include <windows.h>
#include <iostream>
#include <string>
#include <conio.h>

namespace UI {

// -------------------------------------------------------------------------
// Constantes de color para la consola de Windows
// -------------------------------------------------------------------------
constexpr int GREEN        = 10;
constexpr int RED          = 12;
constexpr int YELLOW       = 14;
constexpr int CYAN         = 11;
constexpr int WHITE        = 15;
constexpr int MAGENTA      = 13;
constexpr int DARK_GREEN   = 2;
constexpr int DARK_RED     = 4;
constexpr int BRIGHT_WHITE = 15;

namespace Color {
    constexpr int GREEN        = 10;
    constexpr int RED          = 12;
    constexpr int YELLOW       = 14;
    constexpr int CYAN         = 11;
    constexpr int WHITE        = 15;
    constexpr int MAGENTA      = 13;
    constexpr int DARK_GREEN   = 2;
    constexpr int DARK_RED     = 4;
    constexpr int BRIGHT_WHITE = 15;
}

// -------------------------------------------------------------------------
// Establecer el color del texto en la consola
// -------------------------------------------------------------------------
inline void setColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));
}

// -------------------------------------------------------------------------
// Restablecer el color al blanco por defecto
// -------------------------------------------------------------------------
inline void resetColor() {
    setColor(WHITE);
}

// -------------------------------------------------------------------------
// Imprimir el banner principal de SecureShield con arte ASCII
// -------------------------------------------------------------------------
inline void printBanner() {
    setColor(CYAN);
    std::cout << "\n";
    std::cout << "  ============================================================================\n";
    std::cout << "  ||                                                                        ||\n";
    setColor(GREEN);
    std::cout << "  ||    ____  _____ ____ _   _ ____  _____   ____  _   _ ___ _____ _     __ ||\n";
    std::cout << "  ||   / ___|| ____/ ___| | | |  _ \\| ____| / ___|| | | |_ _| ____| |   |  |||\n";
    std::cout << "  ||   \\___ \\|  _|| |   | | | | |_) |  _|   \\___ \\| |_| || ||  _| | |   | ||||\n";
    std::cout << "  ||    ___) | |__| |___| |_| |  _ <| |___   ___) |  _  || || |___| |___| ||||\n";
    std::cout << "  ||   |____/|_____\\____|\\___/|_| \\_\\|_____| |____/|_| |_|___|_____|_____|__|||\n";
    setColor(CYAN);
    std::cout << "  ||                                                                        ||\n";
    setColor(YELLOW);
    std::cout << "  ||         SECURE SHIELD v1.0 - Sistema de Seguridad Integral             ||\n";
    setColor(CYAN);
    std::cout << "  ||                                                                        ||\n";
    setColor(DARK_GREEN);
    std::cout << "  ||   [*] Proteccion de archivos    [*] Monitoreo de red                   ||\n";
    std::cout << "  ||   [*] Analisis de integridad    [*] Cifrado avanzado                   ||\n";
    setColor(CYAN);
    std::cout << "  ||                                                                        ||\n";
    std::cout << "  ============================================================================\n";
    resetColor();
    std::cout << "\n";
}

// -------------------------------------------------------------------------
// Imprimir una linea separadora decorativa
// -------------------------------------------------------------------------
inline void printSeparator() {
    setColor(CYAN);
    std::cout << "  ";
    for (int i = 0; i < 76; ++i) {
        std::cout << "=";
    }
    std::cout << "\n";
    resetColor();
}

// -------------------------------------------------------------------------
// Imprimir mensaje de exito [OK]
// -------------------------------------------------------------------------
inline void printSuccess(const std::string& msg) {
    setColor(GREEN);
    std::cout << "  [OK] ";
    resetColor();
    std::cout << msg << "\n";
}

// -------------------------------------------------------------------------
// Imprimir mensaje de error [ERROR]
// -------------------------------------------------------------------------
inline void printError(const std::string& msg) {
    setColor(RED);
    std::cout << "  [ERROR] ";
    resetColor();
    std::cout << msg << "\n";
}

// -------------------------------------------------------------------------
// Imprimir mensaje de advertencia [AVISO]
// -------------------------------------------------------------------------
inline void printWarning(const std::string& msg) {
    setColor(YELLOW);
    std::cout << "  [AVISO] ";
    resetColor();
    std::cout << msg << "\n";
}

// -------------------------------------------------------------------------
// Imprimir mensaje de alerta critica [ALERTA]
// -------------------------------------------------------------------------
inline void printAlert(const std::string& msg) {
    setColor(RED);
    std::cout << "  >>> [ALERTA] " << msg << " <<<" << "\n";
    resetColor();
}

// -------------------------------------------------------------------------
// Imprimir mensaje informativo [INFO]
// -------------------------------------------------------------------------
inline void printInfo(const std::string& msg) {
    setColor(CYAN);
    std::cout << "  [INFO] ";
    resetColor();
    std::cout << msg << "\n";
}

// -------------------------------------------------------------------------
// Imprimir un elemento de menu numerado con formato
// -------------------------------------------------------------------------
inline void printMenuItem(int num, const std::string& text) {
    setColor(YELLOW);
    std::cout << "    [" << num << "] ";
    resetColor();
    std::cout << text << "\n";
}

// -------------------------------------------------------------------------
// Imprimir texto coloreado sin salto de linea
// -------------------------------------------------------------------------
inline void printColored(const std::string& text, int color) {
    setColor(color);
    std::cout << text;
    resetColor();
}

// -------------------------------------------------------------------------
// Imprimir texto destacado con salto de linea
// -------------------------------------------------------------------------
inline void printHighlight(const std::string& msg) {
    setColor(BRIGHT_WHITE);
    std::cout << msg << "\n";
    resetColor();
}

// -------------------------------------------------------------------------
// Limpiar la pantalla de la consola
// -------------------------------------------------------------------------
inline void clearScreen() {
    // Usamos la API de Windows para limpiar correctamente la consola
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD coordScreen = { 0, 0 };
    DWORD charsWritten;
    CONSOLE_SCREEN_BUFFER_INFO csbi;

    if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) {
        // Si falla, intentar con el comando del sistema
        system("cls");
        return;
    }

    DWORD dwConSize = static_cast<DWORD>(csbi.dwSize.X) * static_cast<DWORD>(csbi.dwSize.Y);
    FillConsoleOutputCharacterW(hConsole, L' ', dwConSize, coordScreen, &charsWritten);
    FillConsoleOutputAttribute(hConsole, csbi.wAttributes, dwConSize, coordScreen, &charsWritten);
    SetConsoleCursorPosition(hConsole, coordScreen);
}

// -------------------------------------------------------------------------
// Imprimir un encabezado de seccion con recuadro
// -------------------------------------------------------------------------
inline void printHeader(const std::string& title) {
    std::cout << "\n";
    setColor(CYAN);

    // Calcular el ancho del recuadro (titulo + margen)
    size_t titleLen = title.size();
    size_t boxWidth = titleLen + 6; // 3 espacios de margen a cada lado
    if (boxWidth < 40) boxWidth = 40;

    // Linea superior
    std::cout << "  +";
    for (size_t i = 0; i < boxWidth; ++i) std::cout << "-";
    std::cout << "+\n";

    // Linea del titulo centrado
    size_t padding = (boxWidth - titleLen) / 2;
    std::cout << "  |";
    for (size_t i = 0; i < padding; ++i) std::cout << " ";
    setColor(YELLOW);
    std::cout << title;
    setColor(CYAN);
    for (size_t i = 0; i < boxWidth - padding - titleLen; ++i) std::cout << " ";
    std::cout << "|\n";

    // Linea inferior
    std::cout << "  +";
    for (size_t i = 0; i < boxWidth; ++i) std::cout << "-";
    std::cout << "+\n";

    resetColor();
    std::cout << "\n";
}

// -------------------------------------------------------------------------
// Pausar la ejecucion hasta que el usuario presione Enter
// -------------------------------------------------------------------------
inline void pressEnter() {
    setColor(DARK_GREEN);
    std::cout << "\n  Presione Enter para continuar...";
    resetColor();
    // Consumir cualquier caracter pendiente en el buffer
    std::cin.ignore(10000, '\n');
    std::cin.get();
}

// -------------------------------------------------------------------------
// Leer una contrasena enmascarando la entrada con asteriscos
// Utiliza _getch() de <conio.h> para captura sin eco
// -------------------------------------------------------------------------
inline std::string getPassword() {
    std::string password;
    char ch;

    while (true) {
        ch = static_cast<char>(_getch());

        if (ch == '\r' || ch == '\n') {
            // El usuario presiono Enter, finalizar entrada
            std::cout << "\n";
            break;
        } else if (ch == '\b' || ch == 127) {
            // Retroceso: eliminar el ultimo caracter
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
            }
        } else if (ch >= 32) {
            // Caracter imprimible: agregarlo y mostrar asterisco
            password += ch;
            std::cout << "*";
        }
        // Ignorar caracteres de control no relevantes
    }

    return password;
}

} // namespace UI
