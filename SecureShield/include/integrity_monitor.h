#pragma once

// =============================================================================
// integrity_monitor.h - Monitor de Integridad de Archivos
// Módulo de SecureShield para verificar la integridad de archivos del sistema
// mediante hashes SHA-256. Detecta modificaciones no autorizadas.
// =============================================================================

#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <algorithm>

#include "sha256.h"
#include "ui.h"
#include "security_logger.h"

// Tamaño del búfer para lectura de archivos al calcular hash
constexpr size_t INTEGRITY_READ_BUFFER_SIZE = 8192;

// Nombre del archivo de base de datos de integridad
constexpr const char* INTEGRITY_DB_FILENAME = "integrity_db.dat";

// Delimitador usado en el archivo de base de datos
constexpr char INTEGRITY_DB_DELIMITER = '|';

// =============================================================================
// Estructura que representa un archivo monitoreado
// =============================================================================
struct MonitoredFile {
    std::string filepath;       // Ruta completa del archivo
    std::string originalHash;   // Hash SHA-256 original calculado al agregar
    time_t      lastChecked;    // Última vez que se verificó la integridad
    bool        compromised;    // Indica si el archivo fue modificado
};

// =============================================================================
// Clase IntegrityMonitor - Monitor de integridad de archivos (Singleton)
// Calcula y almacena hashes SHA-256, detecta cambios no autorizados.
// =============================================================================
class IntegrityMonitor {
public:
    // =========================================================================
    // Obtener la instancia única del monitor (patrón Singleton)
    // =========================================================================
    static IntegrityMonitor& getInstance() {
        static IntegrityMonitor instance;
        return instance;
    }

    // =========================================================================
    // Agregar un archivo al monitoreo, calcula y almacena su hash SHA-256
    // Retorna true si se agregó exitosamente, false si ya existe o hay error
    // =========================================================================
    bool addFile(const std::string& filepath) {
        // Verificar si el archivo ya está siendo monitoreado
        if (monitoredFiles.find(filepath) != monitoredFiles.end()) {
            UI::printWarning("El archivo ya está siendo monitoreado: " + filepath);
            return false;
        }

        // Calcular el hash del archivo
        std::string hash = calculateFileHash(filepath);
        if (hash.empty()) {
            UI::printError("No se pudo calcular el hash del archivo: " + filepath);
            return false;
        }

        // Crear la entrada del archivo monitoreado
        MonitoredFile entry;
        entry.filepath = filepath;
        entry.originalHash = hash;
        entry.lastChecked = std::time(nullptr);
        entry.compromised = false;

        monitoredFiles[filepath] = entry;

        SecurityLogger::getInstance().log(
            SecurityLogger::INFO,
            "INTEGRIDAD",
            "Archivo agregado al monitoreo: " + filepath + " [SHA-256: " + hash.substr(0, 16) + "...]"
        );

        UI::printSuccess("Archivo agregado al monitoreo exitosamente.");
        return true;
    }

    // =========================================================================
    // Remover un archivo del monitoreo
    // Retorna true si se removió, false si no se encontró
    // =========================================================================
    bool removeFile(const std::string& filepath) {
        auto it = monitoredFiles.find(filepath);
        if (it == monitoredFiles.end()) {
            UI::printWarning("El archivo no está siendo monitoreado: " + filepath);
            return false;
        }

        monitoredFiles.erase(it);

        SecurityLogger::getInstance().log(
            SecurityLogger::INFO,
            "INTEGRIDAD",
            "Archivo removido del monitoreo: " + filepath
        );

        UI::printSuccess("Archivo removido del monitoreo exitosamente.");
        return true;
    }

    // =========================================================================
    // Verificar la integridad de un archivo individual contra el hash almacenado
    // Retorna true si el archivo está íntegro, false si fue comprometido
    // =========================================================================
    bool checkFile(const std::string& filepath) {
        auto it = monitoredFiles.find(filepath);
        if (it == monitoredFiles.end()) {
            UI::printWarning("El archivo no está siendo monitoreado: " + filepath);
            return false;
        }

        MonitoredFile& entry = it->second;
        entry.lastChecked = std::time(nullptr);

        // Calcular el hash actual del archivo
        std::string currentHash = calculateFileHash(filepath);

        if (currentHash.empty()) {
            // El archivo no se pudo leer (posiblemente eliminado)
            entry.compromised = true;
            SecurityLogger::getInstance().log(
                SecurityLogger::CRITICAL,
                "INTEGRIDAD",
                "ALERTA: Archivo no encontrado o inaccesible: " + filepath
            );
            return false;
        }

        // Comparar con el hash original
        if (currentHash != entry.originalHash) {
            entry.compromised = true;
            SecurityLogger::getInstance().log(
                SecurityLogger::CRITICAL,
                "INTEGRIDAD",
                "ALERTA CRITICA: Archivo comprometido detectado: " + filepath +
                " [Original: " + entry.originalHash.substr(0, 16) + "...] " +
                "[Actual: " + currentHash.substr(0, 16) + "...]"
            );
            UI::printError("¡ARCHIVO COMPROMETIDO! " + filepath);
            return false;
        }

        entry.compromised = false;
        return true;
    }

    // =========================================================================
    // Verificar todos los archivos monitoreados
    // Retorna una lista con las rutas de los archivos comprometidos
    // =========================================================================
    std::vector<std::string> checkAll() {
        std::vector<std::string> compromisedList;

        UI::printHeader("Verificación de Integridad Global");
        std::cout << "  Verificando " << monitoredFiles.size() << " archivos...\n\n";

        int checked = 0;
        for (auto& pair : monitoredFiles) {
            checked++;
            std::cout << "  [" << checked << "/" << monitoredFiles.size() << "] "
                      << pair.first << " ... ";

            if (!checkFile(pair.first)) {
                compromisedList.push_back(pair.first);
                // El color rojo ya se muestra en checkFile()
            } else {
                UI::printSuccess("OK");
            }
        }

        std::cout << "\n";
        UI::printSeparator();

        if (compromisedList.empty()) {
            UI::printSuccess(
                "Todos los archivos están íntegros. No se detectaron modificaciones."
            );
        } else {
            UI::printError(
                "Se detectaron " + std::to_string(compromisedList.size()) +
                " archivo(s) comprometido(s)."
            );

            SecurityLogger::getInstance().log(
                SecurityLogger::CRITICAL,
                "INTEGRIDAD",
                "Escaneo completo: " + std::to_string(compromisedList.size()) +
                " de " + std::to_string(monitoredFiles.size()) + " archivos comprometidos."
            );
        }

        return compromisedList;
    }

    // =========================================================================
    // Mostrar el estado de todos los archivos monitoreados con colores
    // Verde = OK, Rojo = COMPROMETIDO, Amarillo = ARCHIVO NO ENCONTRADO
    // =========================================================================
    void showStatus() {
        UI::printHeader("Estado de Archivos Monitoreados");

        if (monitoredFiles.empty()) {
            UI::printWarning("No hay archivos siendo monitoreados actualmente.");
            return;
        }

        std::cout << "  Total de archivos monitoreados: " << monitoredFiles.size() << "\n\n";

        // Encabezado de la tabla
        std::cout << "  " << std::left
                  << std::setw(45) << "ARCHIVO"
                  << std::setw(20) << "HASH (parcial)"
                  << std::setw(22) << "ULTIMA VERIFICACION"
                  << std::setw(15) << "ESTADO"
                  << "\n";

        UI::printSeparator();

        for (const auto& pair : monitoredFiles) {
            const MonitoredFile& entry = pair.second;

            // Truncar la ruta si es muy larga
            std::string displayPath = entry.filepath;
            if (displayPath.length() > 42) {
                displayPath = "..." + displayPath.substr(displayPath.length() - 39);
            }

            // Hash parcial para la visualización
            std::string hashPreview = entry.originalHash.substr(0, 16) + "...";

            // Formatear la fecha de última verificación
            char timeBuffer[20];
            struct tm timeInfo;
            localtime_s(&timeInfo, &entry.lastChecked);
            std::strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M", &timeInfo);

            std::cout << "  " << std::left
                      << std::setw(45) << displayPath
                      << std::setw(20) << hashPreview
                      << std::setw(22) << timeBuffer;

            // Verificar si el archivo existe actualmente
            std::ifstream testFile(entry.filepath);
            bool fileExists = testFile.good();
            testFile.close();

            if (!fileExists) {
                // Amarillo: archivo no encontrado
                UI::printColored("NO ENCONTRADO", UI::Color::YELLOW);
            } else if (entry.compromised) {
                // Rojo: archivo comprometido
                UI::printColored("COMPROMETIDO", UI::Color::RED);
            } else {
                // Verde: archivo íntegro
                UI::printColored("OK", UI::Color::GREEN);
            }

            std::cout << "\n";
        }

        std::cout << "\n";

        // Resumen de estado
        int okCount = 0, compromisedCount = 0, missingCount = 0;
        for (const auto& pair : monitoredFiles) {
            std::ifstream testFile(pair.second.filepath);
            bool exists = testFile.good();
            testFile.close();

            if (!exists) {
                missingCount++;
            } else if (pair.second.compromised) {
                compromisedCount++;
            } else {
                okCount++;
            }
        }

        std::cout << "  Resumen: ";
        UI::printColored(std::to_string(okCount) + " OK", UI::Color::GREEN);
        std::cout << " | ";
        UI::printColored(std::to_string(compromisedCount) + " Comprometidos", UI::Color::RED);
        std::cout << " | ";
        UI::printColored(std::to_string(missingCount) + " No encontrados", UI::Color::YELLOW);
        std::cout << "\n\n";
    }

    // =========================================================================
    // Guardar la base de datos de archivos monitoreados en disco
    // Formato: filepath|hash|lastChecked|compromised
    // =========================================================================
    void saveDatabase() {
        std::ofstream outFile(INTEGRITY_DB_FILENAME, std::ios::out | std::ios::trunc);

        if (!outFile.is_open()) {
            UI::printError(
                "No se pudo guardar la base de datos de integridad: " +
                std::string(INTEGRITY_DB_FILENAME)
            );
            return;
        }

        // Escribir encabezado del archivo
        outFile << "# SecureShield - Base de Datos de Integridad\n";
        outFile << "# Formato: ruta|hash_sha256|ultima_verificacion|comprometido\n";

        for (const auto& pair : monitoredFiles) {
            const MonitoredFile& entry = pair.second;
            outFile << entry.filepath
                    << INTEGRITY_DB_DELIMITER << entry.originalHash
                    << INTEGRITY_DB_DELIMITER << entry.lastChecked
                    << INTEGRITY_DB_DELIMITER << (entry.compromised ? 1 : 0)
                    << "\n";
        }

        outFile.close();

        SecurityLogger::getInstance().log(
            SecurityLogger::INFO,
            "INTEGRIDAD",
            "Base de datos guardada: " + std::to_string(monitoredFiles.size()) + " entradas."
        );

        UI::printSuccess(
            "Base de datos de integridad guardada exitosamente (" +
            std::to_string(monitoredFiles.size()) + " archivos)."
        );
    }

    // =========================================================================
    // Cargar la base de datos de archivos monitoreados desde disco
    // =========================================================================
    void loadDatabase() {
        std::ifstream inFile(INTEGRITY_DB_FILENAME, std::ios::in);

        if (!inFile.is_open()) {
            UI::printWarning(
                "No se encontró base de datos de integridad existente. Se creará una nueva."
            );
            return;
        }

        monitoredFiles.clear();
        std::string line;
        int loadedCount = 0;

        while (std::getline(inFile, line)) {
            // Saltar comentarios y líneas vacías
            if (line.empty() || line[0] == '#') {
                continue;
            }

            // Parsear la línea: filepath|hash|lastChecked|compromised
            std::istringstream iss(line);
            std::string filepath, hash, lastCheckedStr, compromisedStr;

            if (!std::getline(iss, filepath, INTEGRITY_DB_DELIMITER) ||
                !std::getline(iss, hash, INTEGRITY_DB_DELIMITER) ||
                !std::getline(iss, lastCheckedStr, INTEGRITY_DB_DELIMITER) ||
                !std::getline(iss, compromisedStr)) {
                continue; // Línea con formato inválido, omitir
            }

            MonitoredFile entry;
            entry.filepath = filepath;
            entry.originalHash = hash;

            // Convertir lastChecked de string a time_t
            try {
                entry.lastChecked = static_cast<time_t>(std::stoll(lastCheckedStr));
            } catch (...) {
                entry.lastChecked = std::time(nullptr);
            }

            entry.compromised = (compromisedStr == "1");

            monitoredFiles[filepath] = entry;
            loadedCount++;
        }

        inFile.close();

        SecurityLogger::getInstance().log(
            SecurityLogger::INFO,
            "INTEGRIDAD",
            "Base de datos cargada: " + std::to_string(loadedCount) + " entradas."
        );

        UI::printSuccess(
            "Base de datos de integridad cargada: " +
            std::to_string(loadedCount) + " archivos."
        );
    }

    // =========================================================================
    // Calcular el hash SHA-256 de un archivo
    // Lee el archivo en bloques para manejar archivos grandes eficientemente
    // Retorna cadena vacía si el archivo no se puede leer
    // =========================================================================
    std::string calculateFileHash(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file.is_open()) {
            return "";
        }

        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        file.close();
        return SHA256::hash(content);
    }

    // =========================================================================
    // Menú interactivo del monitor de integridad
    // Opciones: Agregar, Remover, Verificar todo, Estado, Auto-escaneo
    // =========================================================================
    void interactiveMenu() {
        bool running = true;

        while (running) {
            UI::printHeader("Monitor de Integridad de Archivos");

            std::cout << "  [1] Agregar archivo al monitoreo\n";
            std::cout << "  [2] Remover archivo del monitoreo\n";
            std::cout << "  [3] Verificar todos los archivos\n";
            std::cout << "  [4] Mostrar estado de archivos\n";
            std::cout << "  [5] Auto-escaneo (verificación continua)\n";
            std::cout << "  [6] Guardar base de datos\n";
            std::cout << "  [7] Cargar base de datos\n";
            std::cout << "  [0] Volver al menú principal\n";

            UI::printSeparator();
            std::cout << "  Seleccione una opción: ";

            std::string input;
            std::getline(std::cin, input);

            if (input.empty()) continue;

            switch (input[0]) {
                case '1': {
                    // Agregar archivo al monitoreo
                    std::cout << "\n  Ingrese la ruta completa del archivo: ";
                    std::string filepath;
                    std::getline(std::cin, filepath);
                    if (!filepath.empty()) {
                        addFile(filepath);
                    }
                    break;
                }
                case '2': {
                    // Remover archivo del monitoreo
                    std::cout << "\n  Ingrese la ruta del archivo a remover: ";
                    std::string filepath;
                    std::getline(std::cin, filepath);
                    if (!filepath.empty()) {
                        removeFile(filepath);
                    }
                    break;
                }
                case '3': {
                    // Verificar todos los archivos
                    checkAll();
                    break;
                }
                case '4': {
                    // Mostrar estado
                    showStatus();
                    break;
                }
                case '5': {
                    // Auto-escaneo continuo
                    UI::printHeader("Auto-Escaneo Continuo");
                    std::cout << "  Iniciando verificación automática cada 10 segundos...\n";
                    std::cout << "  Presione Ctrl+C para detener.\n\n";

                    // Bucle de escaneo automático
                    bool autoRunning = true;
                    while (autoRunning) {
                        auto compromised = checkAll();

                        if (!compromised.empty()) {
                            UI::printError(
                                "¡ALERTA! Se detectaron " +
                                std::to_string(compromised.size()) +
                                " archivos comprometidos durante el auto-escaneo."
                            );
                        }

                        // Esperar 10 segundos antes del próximo escaneo
                        std::cout << "\n  Próximo escaneo en 10 segundos... "
                                  << "(Presione Ctrl+C para detener)\n";
                        Sleep(10000);
                    }
                    break;
                }
                case '6': {
                    // Guardar base de datos
                    saveDatabase();
                    break;
                }
                case '7': {
                    // Cargar base de datos
                    loadDatabase();
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
    // Obtener la cantidad de archivos comprometidos
    // =========================================================================
    int getCompromisedCount() {
        int count = 0;
        for (const auto& pair : monitoredFiles) {
            if (pair.second.compromised) {
                count++;
            }
        }
        return count;
    }

    // =========================================================================
    // Obtener la cantidad total de archivos monitoreados
    // =========================================================================
    int getMonitoredCount() {
        return static_cast<int>(monitoredFiles.size());
    }

private:
    // Constructor privado (patrón Singleton)
    IntegrityMonitor() = default;

    // Eliminar constructor de copia y operador de asignación
    IntegrityMonitor(const IntegrityMonitor&) = delete;
    IntegrityMonitor& operator=(const IntegrityMonitor&) = delete;

    // Mapa de archivos monitoreados: ruta -> datos del archivo
    std::map<std::string, MonitoredFile> monitoredFiles;
};
