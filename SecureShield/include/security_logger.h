#pragma once
// ============================================================================
// SecureShield - Modulo de Registro de Eventos de Seguridad
// Proporciona un sistema centralizado de registro (logging) con niveles de
// severidad, almacenamiento en archivo y visualizacion con colores en consola.
// ============================================================================

#include <fstream>
#include <vector>
#include <string>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <mutex>
#include <windows.h>
#include <iostream>

#include "ui.h"

// ============================================================================
// Clase SecurityLogger - Singleton
// ============================================================================
class SecurityLogger {
public:
    // Niveles de registro disponibles
    enum LogLevel {
        INFO,       // Informacion general del sistema
        WARNING,    // Advertencia: situacion potencialmente problematica
        ALERT,      // Alerta: evento de seguridad que requiere atencion
        CRITICAL    // Critico: evento de seguridad grave
    };

    // Estructura que representa una entrada individual en el registro
    struct LogEntry {
        time_t      timestamp;
        LogLevel    level;
        std::string module;
        std::string message;
    };

    // Obtener la instancia unica del logger (patron Singleton)
    static SecurityLogger& getInstance() {
        static SecurityLogger instancia;
        return instancia;
    }

    // ------------------------------------------------------------------
    // Registrar un evento de seguridad
    // ------------------------------------------------------------------
    void log(LogLevel level, const std::string& module, const std::string& message) {
        std::lock_guard<std::mutex> bloqueo(mutex_);

        LogEntry entrada{};
        entrada.timestamp = std::time(nullptr);
        entrada.level     = level;
        entrada.module    = module;
        entrada.message   = message;

        registros_.push_back(entrada);
        escribirEnArchivo(entrada);
    }

    // ------------------------------------------------------------------
    // Mostrar los registros mas recientes en la consola con colores
    // ------------------------------------------------------------------
    void printRecentLogs(int count = 20) {
        std::lock_guard<std::mutex> bloqueo(mutex_);

        std::cout << "\n";
        UI::setColor(UI::CYAN);
        std::cout << "  ========================================" << std::endl;
        std::cout << "    Registros de Seguridad Recientes" << std::endl;
        std::cout << "  ========================================" << std::endl;
        UI::resetColor();

        if (registros_.empty()) {
            std::cout << "  (Sin registros disponibles)" << std::endl << std::endl;
            return;
        }

        int total = static_cast<int>(registros_.size());
        int inicio = (total > count) ? (total - count) : 0;

        for (int i = inicio; i < total; ++i) {
            const LogEntry& entrada = registros_[i];

            switch (entrada.level) {
                case INFO:
                    UI::setColor(UI::GREEN);
                    break;
                case WARNING:
                    UI::setColor(UI::YELLOW);
                    break;
                case ALERT:
                    UI::setColor(UI::RED);
                    break;
                case CRITICAL:
                    UI::setColor(UI::RED);
                    break;
            }

            std::cout << "  " << formatearEntrada(entrada) << std::endl;
        }

        UI::resetColor();
        std::cout << std::endl;
    }

    // ------------------------------------------------------------------
    // Obtener todas las entradas de nivel ALERT y CRITICAL
    // ------------------------------------------------------------------
    std::vector<LogEntry> getAlerts() {
        std::lock_guard<std::mutex> bloqueo(mutex_);

        std::vector<LogEntry> alertas;
        for (const auto& entrada : registros_) {
            if (entrada.level == ALERT || entrada.level == CRITICAL) {
                alertas.push_back(entrada);
            }
        }
        return alertas;
    }

    // ------------------------------------------------------------------
    // Obtener la cantidad de eventos de nivel ALERT
    // ------------------------------------------------------------------
    int getAlertCount() {
        std::lock_guard<std::mutex> bloqueo(mutex_);
        int conteo = 0;
        for (const auto& entrada : registros_) {
            if (entrada.level == ALERT) ++conteo;
        }
        return conteo;
    }

    // ------------------------------------------------------------------
    // Obtener la cantidad de eventos de nivel CRITICAL
    // ------------------------------------------------------------------
    int getCriticalCount() {
        std::lock_guard<std::mutex> bloqueo(mutex_);
        int conteo = 0;
        for (const auto& entrada : registros_) {
            if (entrada.level == CRITICAL) ++conteo;
        }
        return conteo;
    }

    // ------------------------------------------------------------------
    // Limpiar todo el historial de registros en memoria
    // ------------------------------------------------------------------
    void clearLogs() {
        std::lock_guard<std::mutex> bloqueo(mutex_);
        registros_.clear();
    }

private:
    std::vector<LogEntry>   registros_;
    std::string             rutaArchivo_ = "secureshield_log.txt";
    mutable std::mutex      mutex_;

    SecurityLogger() {
        std::ofstream archivo(rutaArchivo_, std::ios::app);
        if (archivo.is_open()) {
            archivo << "================================================================" << std::endl;
            archivo << " SecureShield - Registro de Eventos Iniciado" << std::endl;
            archivo << " Fecha: " << obtenerMarcaDeTiempo(std::time(nullptr)) << std::endl;
            archivo << "================================================================" << std::endl;
            archivo.close();
        }
    }

    SecurityLogger(const SecurityLogger&) = delete;
    SecurityLogger& operator=(const SecurityLogger&) = delete;

    static std::string nivelATexto(LogLevel level) {
        switch (level) {
            case INFO:     return "INFO    ";
            case WARNING:  return "WARNING ";
            case ALERT:    return "ALERT   ";
            case CRITICAL: return "CRITICAL";
            default:       return "UNKNOWN ";
        }
    }

    static std::string obtenerMarcaDeTiempo(time_t tiempo) {
        struct tm infoTiempo{};
        localtime_s(&infoTiempo, &tiempo);

        std::ostringstream oss;
        oss << std::setfill('0')
            << std::setw(4) << (infoTiempo.tm_year + 1900) << "-"
            << std::setw(2) << (infoTiempo.tm_mon + 1)     << "-"
            << std::setw(2) << infoTiempo.tm_mday          << " "
            << std::setw(2) << infoTiempo.tm_hour          << ":"
            << std::setw(2) << infoTiempo.tm_min            << ":"
            << std::setw(2) << infoTiempo.tm_sec;
        return oss.str();
    }

    static std::string formatearEntrada(const LogEntry& entrada) {
        std::ostringstream oss;
        oss << "[" << obtenerMarcaDeTiempo(entrada.timestamp) << "] "
            << "[" << nivelATexto(entrada.level)              << "] "
            << "[" << entrada.module                          << "] "
            << entrada.message;
        return oss.str();
    }

    void escribirEnArchivo(const LogEntry& entrada) {
        std::ofstream archivo(rutaArchivo_, std::ios::app);
        if (archivo.is_open()) {
            archivo << formatearEntrada(entrada) << std::endl;
            archivo.close();
        }
    }
};
