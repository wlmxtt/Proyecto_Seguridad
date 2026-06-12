#pragma once
// =============================================================================
// SecureShield - Motor de Cifrado (CryptoEngine)
// =============================================================================
// Módulo de cifrado/descifrado de archivos y cadenas de texto.
// Utiliza un cifrado de flujo XOR con clave derivada mediante SHA-256.
// =============================================================================

#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#include "sha256.h"
#include "ui.h"
#include "security_logger.h"

// Cabecera mágica para identificar archivos cifrados por SecureShield
static constexpr const char MAGIC_HEADER[] = "SSHIELD1";
static constexpr size_t MAGIC_HEADER_SIZE = 8;

// Sal utilizada para la derivación de la clave
static const std::string KEY_DERIVATION_SALT = "SecureShieldSalt2024";

// =============================================================================
// Clase CryptoEngine
// Proporciona funciones estáticas para cifrar y descifrar archivos y cadenas.
// =============================================================================
class CryptoEngine {
public:
    // -------------------------------------------------------------------------
    // Cifrar un archivo.
    // Lee el archivo de entrada en modo binario, cifra su contenido y lo
    // escribe en el archivo de salida con la cabecera mágica 'SSHIELD1'.
    // Retorna true si la operación fue exitosa, false en caso contrario.
    // -------------------------------------------------------------------------
    static bool encryptFile(const std::string& inputFile,
                            const std::string& outputFile,
                            const std::string& password) {
        // Abrir archivo de entrada en modo binario
        std::ifstream fin(inputFile, std::ios::binary);
        if (!fin.is_open()) {
            UI::printError("No se pudo abrir el archivo de entrada: " + inputFile);
            SecurityLogger::getInstance().log(SecurityLogger::ALERT, "CRIPTO", "Fallo al abrir archivo para cifrado: " + inputFile);
            return false;
        }

        // Leer todo el contenido del archivo
        std::vector<unsigned char> data(
            (std::istreambuf_iterator<char>(fin)),
            std::istreambuf_iterator<char>()
        );
        fin.close();

        // Derivar la clave a partir de la contraseña
        std::string key = deriveKey(password);

        // Aplicar cifrado XOR sobre cada byte
        for (size_t i = 0; i < data.size(); ++i) {
            data[i] ^= static_cast<unsigned char>(key[i % key.length()]);
        }

        // Escribir archivo de salida con cabecera mágica
        std::ofstream fout(outputFile, std::ios::binary);
        if (!fout.is_open()) {
            UI::printError("No se pudo crear el archivo de salida: " + outputFile);
            SecurityLogger::getInstance().log(SecurityLogger::ALERT, "CRIPTO", "Fallo al crear archivo cifrado: " + outputFile);
            return false;
        }

        // Escribir la cabecera mágica 'SSHIELD1' (8 bytes)
        fout.write(MAGIC_HEADER, MAGIC_HEADER_SIZE);

        // Escribir los datos cifrados
        if (!data.empty()) {
            fout.write(reinterpret_cast<const char*>(data.data()),
                       static_cast<std::streamsize>(data.size()));
        }
        fout.close();

        UI::printSuccess("Archivo cifrado exitosamente: " + outputFile);
        SecurityLogger::getInstance().log(SecurityLogger::INFO, "CRIPTO", "Archivo cifrado: " + inputFile + " -> " + outputFile);
        return true;
    }

    // -------------------------------------------------------------------------
    // Descifrar un archivo.
    // Verifica la cabecera mágica, lee los datos cifrados y los descifra.
    // Retorna true si la operación fue exitosa, false en caso contrario.
    // -------------------------------------------------------------------------
    static bool decryptFile(const std::string& inputFile,
                            const std::string& outputFile,
                            const std::string& password) {
        // Abrir archivo cifrado en modo binario
        std::ifstream fin(inputFile, std::ios::binary);
        if (!fin.is_open()) {
            UI::printError("No se pudo abrir el archivo cifrado: " + inputFile);
            SecurityLogger::getInstance().log(SecurityLogger::ALERT, "CRIPTO", "Fallo al abrir archivo para descifrado: " + inputFile);
            return false;
        }

        // Verificar la cabecera mágica
        char header[MAGIC_HEADER_SIZE + 1] = {};
        fin.read(header, MAGIC_HEADER_SIZE);
        if (std::string(header, MAGIC_HEADER_SIZE) != std::string(MAGIC_HEADER, MAGIC_HEADER_SIZE)) {
            UI::printError("El archivo no tiene el formato de SecureShield o esta corrupto.");
            SecurityLogger::getInstance().log(SecurityLogger::ALERT, "CRIPTO", "Cabecera magica invalida en: " + inputFile);
            fin.close();
            return false;
        }

        // Leer los datos cifrados (después de la cabecera)
        std::vector<unsigned char> data(
            (std::istreambuf_iterator<char>(fin)),
            std::istreambuf_iterator<char>()
        );
        fin.close();

        // Derivar la clave a partir de la contraseña
        std::string key = deriveKey(password);

        // Aplicar descifrado XOR (operación simétrica)
        for (size_t i = 0; i < data.size(); ++i) {
            data[i] ^= static_cast<unsigned char>(key[i % key.length()]);
        }

        // Escribir archivo de salida descifrado
        std::ofstream fout(outputFile, std::ios::binary);
        if (!fout.is_open()) {
            UI::printError("No se pudo crear el archivo de salida: " + outputFile);
            SecurityLogger::getInstance().log(SecurityLogger::ALERT, "CRIPTO", "Fallo al crear archivo descifrado: " + outputFile);
            return false;
        }

        if (!data.empty()) {
            fout.write(reinterpret_cast<const char*>(data.data()),
                       static_cast<std::streamsize>(data.size()));
        }
        fout.close();

        UI::printSuccess("Archivo descifrado exitosamente: " + outputFile);
        SecurityLogger::getInstance().log(SecurityLogger::INFO, "CRIPTO", "Archivo descifrado: " + inputFile + " -> " + outputFile);
        return true;
    }

    // -------------------------------------------------------------------------
    // Cifrar una cadena de texto.
    // Retorna la cadena cifrada codificada en hexadecimal.
    // -------------------------------------------------------------------------
    static std::string encryptString(const std::string& plaintext,
                                     const std::string& password) {
        // Derivar la clave a partir de la contraseña
        std::string key = deriveKey(password);

        // Aplicar cifrado XOR byte a byte
        std::vector<unsigned char> encrypted(plaintext.size());
        for (size_t i = 0; i < plaintext.size(); ++i) {
            encrypted[i] = static_cast<unsigned char>(plaintext[i]) ^
                           static_cast<unsigned char>(key[i % key.length()]);
        }

        // Convertir a representación hexadecimal para facilitar almacenamiento
        return bytesToHex(encrypted);
    }

    // -------------------------------------------------------------------------
    // Descifrar una cadena de texto.
    // Recibe la cadena cifrada en formato hexadecimal y retorna el texto plano.
    // -------------------------------------------------------------------------
    static std::string decryptString(const std::string& ciphertext,
                                     const std::string& password) {
        // Convertir de hexadecimal a bytes
        std::vector<unsigned char> encrypted = hexToBytes(ciphertext);

        // Derivar la clave a partir de la contraseña
        std::string key = deriveKey(password);

        // Aplicar descifrado XOR (operación simétrica)
        std::string decrypted(encrypted.size(), '\0');
        for (size_t i = 0; i < encrypted.size(); ++i) {
            decrypted[i] = static_cast<char>(
                encrypted[i] ^ static_cast<unsigned char>(key[i % key.length()])
            );
        }

        return decrypted;
    }

    // -------------------------------------------------------------------------
    // Demostración interactiva del motor de cifrado.
    // Permite al usuario ingresar texto y una contraseña, mostrando el
    // proceso completo de cifrado y descifrado.
    // -------------------------------------------------------------------------
    static void demonstrateCrypto() {
        UI::printHeader("Demostracion del Motor de Cifrado");

        // Solicitar texto al usuario
        UI::printInfo("Ingrese el texto que desea cifrar:");
        std::string texto;
        std::getline(std::cin, texto);

        if (texto.empty()) {
            UI::printWarning("No se ingreso ningun texto. Operacion cancelada.");
            return;
        }

        // Solicitar contraseña al usuario
        UI::printInfo("Ingrese la contrasena para el cifrado:");
        std::string contrasena;
        std::getline(std::cin, contrasena);

        if (contrasena.empty()) {
            UI::printWarning("No se ingreso ninguna contrasena. Operacion cancelada.");
            return;
        }

        UI::printSeparator();

        // Mostrar el texto original
        UI::printInfo("Texto original:");
        UI::printHighlight("  " + texto);

        // Cifrar el texto
        std::string textoCifrado = encryptString(texto, contrasena);

        // Mostrar el texto cifrado en hexadecimal
        UI::printInfo("Texto cifrado (hexadecimal):");
        UI::printWarning("  " + textoCifrado);

        // Descifrar el texto para verificar
        std::string textoDescifrado = decryptString(textoCifrado, contrasena);

        // Mostrar el texto descifrado
        UI::printInfo("Texto descifrado (verificacion):");
        UI::printSuccess("  " + textoDescifrado);

        UI::printSeparator();

        // Verificar que el cifrado/descifrado funciona correctamente
        if (texto == textoDescifrado) {
            UI::printSuccess("Verificacion exitosa: el texto descifrado coincide con el original.");
        } else {
            UI::printError("Error de verificacion: el texto descifrado NO coincide con el original.");
        }

        // Registrar la operación en el log de seguridad
        SecurityLogger::getInstance().log(SecurityLogger::INFO, "CRIPTO",
            "Demostracion de cifrado realizada. Longitud del texto: " +
            std::to_string(texto.size()) + " bytes.");
    }

private:
    // -------------------------------------------------------------------------
    // Derivar una clave a partir de la contraseña usando SHA-256.
    // Se concatena la contraseña con una sal fija para mayor seguridad.
    // -------------------------------------------------------------------------
    static std::string deriveKey(const std::string& password) {
        return SHA256::hash(password + KEY_DERIVATION_SALT);
    }

    // -------------------------------------------------------------------------
    // Convertir un vector de bytes a su representación hexadecimal.
    // Cada byte se convierte a dos caracteres hexadecimales en minúsculas.
    // -------------------------------------------------------------------------
    static std::string bytesToHex(const std::vector<unsigned char>& bytes) {
        std::ostringstream oss;
        for (unsigned char byte : bytes) {
            oss << std::hex << std::setfill('0') << std::setw(2)
                << static_cast<int>(byte);
        }
        return oss.str();
    }

    // -------------------------------------------------------------------------
    // Convertir una cadena hexadecimal a un vector de bytes.
    // Cada par de caracteres hexadecimales se convierte a un byte.
    // -------------------------------------------------------------------------
    static std::vector<unsigned char> hexToBytes(const std::string& hex) {
        std::vector<unsigned char> bytes;
        bytes.reserve(hex.size() / 2);
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            unsigned int byte = 0;
            std::istringstream iss(hex.substr(i, 2));
            iss >> std::hex >> byte;
            bytes.push_back(static_cast<unsigned char>(byte));
        }
        return bytes;
    }
};
