// test_sha256.cpp - Verificacion rapida de la implementacion SHA-256
#include <iostream>
#include "include/sha256.h"

int main() {
    // Caso de prueba 1: cadena vacia
    // Resultado esperado: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    std::string emptyHash = SHA256::hash("");
    std::cout << "SHA-256('') = " << emptyHash << std::endl;
    std::cout << "Esperado:     e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" << std::endl;
    std::cout << (emptyHash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ? "CORRECTO" : "INCORRECTO") << std::endl;
    std::cout << std::endl;

    // Caso de prueba 2: "abc"
    // Resultado esperado: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    std::string abcHash = SHA256::hash("abc");
    std::cout << "SHA-256('abc') = " << abcHash << std::endl;
    std::cout << "Esperado:        ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" << std::endl;
    std::cout << (abcHash == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ? "CORRECTO" : "INCORRECTO") << std::endl;
    std::cout << std::endl;

    // Caso de prueba 3: cadena mas larga (multi-bloque)
    std::string longHash = SHA256::hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    std::cout << "SHA-256('abcdbcde...nopq') = " << longHash << std::endl;
    std::cout << "Esperado:                     248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" << std::endl;
    std::cout << (longHash == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" ? "CORRECTO" : "INCORRECTO") << std::endl;

    return 0;
}
