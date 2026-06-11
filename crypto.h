#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <cstdint>

// Clase para funciones de integridad y cifrado básico dentro del IPS
class CryptoSystem {
public:
    /**
     * @brief Aplica un cifrado/descifrado simple XOR sobre un buffer de datos.
     * Esta función es reversible (aplicarla dos veces con la misma clave devuelve el original).
     * @param data Datos a cifrar o descifrar.
     * @param key Clave de cifrado XOR.
     */
    static void xorEncryptDecrypt(std::vector<char>& data, char key) {
        for (size_t i = 0; i < data.size(); ++i) {
            data[i] ^= key;
        }
    }

    /**
     * @brief Calcula un checksum (Fletcher-16 o suma modular simple) de un archivo para verificar su integridad.
     * Esto permite detectar si el archivo de configuración o reglas ha sido alterado.
     * @param filePath Ruta del archivo a validar.
     * @param outChecksum Referencia para retornar la suma de verificación calculada.
     * @return true si el archivo pudo leerse y procesarse con éxito, false de lo contrario.
     */
    static bool calculateFileChecksum(const std::string& filePath, uint16_t& outChecksum) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "[CRYPTO] Error al abrir el archivo para checksum: " << filePath << "\n";
            return false;
        }

        uint16_t sum1 = 0;
        uint16_t sum2 = 0;
        char byte;

        while (file.get(byte)) {
            sum1 = (sum1 + static_cast<uint8_t>(byte)) % 255;
            sum2 = (sum2 + sum1) % 255;
        }

        outChecksum = (sum2 << 8) | sum1;
        file.close();
        return true;
    }
};

#endif // CRYPTO_H
