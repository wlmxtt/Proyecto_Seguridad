# 🛡️ Sistema IPS Interactivo en C++ - Trabajo Práctico Final

¡Saludos, equipo! Este es el repositorio base para el proyecto final de **Seguridad de Tecnología de la Información (Corte 3)**. El objetivo es construir una aplicación funcional en C++ que asegure un sistema computacional contra ataques comunes, aplicando mecanismos de autenticación, control de acceso e integridad, y demostrando un bloqueo real con el Firewall del sistema.

La entrega y presentación en vivo es este **viernes 12-06-2026**.

---

## 👥 Asignación de Módulos (¿Qué hará cada quién mañana?)

Para avanzar en paralelo de forma eficiente en la mañana, nos dividiremos el desarrollo en 3 componentes independientes (ya estructurados en los archivos `.h` correspondientes):

### 🔑 1. Autenticación y Control de Acceso (`auth.h`)
* **Responsable:** [Nombre de tu compañero 1]
* **Tareas obligatorias:**
  * Implementar el sistema de login con un límite estricto de **3 intentos**.
  * Definir e implementar el modelo de roles utilizando **Listas de Control de Acceso (ACL)**: `ADMIN` (acceso total a la configuración) y `OPERADOR` (solo visualización de eventos).
  * Validar el uso de contraseñas seguras y simular el mecanismo de reto/responder en el sistema operativo.

### 🔐 2. Encriptación y Verificación de Integridad (`crypto.h`)
* **Responsable:** [Nombre de tu compañero 2]
* **Tareas obligatorias:**
  * Desarrollar funciones de encriptación tradicional/simétrica (algoritmo XOR simple) para proteger los datos sensibles en reposo.
  * Diseñar un mecanismo de **verificación de integridad** (checksum/hash básico) que lea los archivos de configuración y detecte si han sido alterados de forma no autorizada antes de arrancar el sistema.

### 🌐 3. Servidor de Red, Detección de Ataques e IPS (`network.h` / `main.cpp`)
* **Responsable:** Wilmer Niño (Integración a partir de las 2:00 PM)
* **Tareas obligatorias:**
  * Levantar un servidor socket TCP nativo que escuche de forma activa en el puerto `8888`.
  * Simular un ataque común (como un escaneo de puertos o intentos masivos de conexión no autorizada).
  * Monitorear la actividad y, al detectar el ataque, ejecutar una instrucción del sistema operativo (`std::system`) para invocar al **Firewall real** (bloqueando físicamente la IP del atacante) y registrar el evento en `audit_log.txt`.

---

## 📋 Tareas Generales para Mañana Jueves

1. **Mañana (Asincrónico):** Revisar las plantillas de código generadas por los agentes de IA en cada uno de sus archivos (`auth.h` o `crypto.h`). Completar la lógica interna de sus funciones y asegurarse de que su módulo compile de forma aislada.
2. **Documentación:** Cada integrante debe redactar **una página y media** detallando el Análisis y Diseño de su módulo para unificarlo en el informe final de 5 puntos.
3. **Tarde (2:00 PM en adelante):** Nos reuniremos para unificar los módulos en el flujo principal de `main.cpp`, realizar las pruebas de fuego reales bloqueando IPs con el firewall y ensayar la presentación oral de 10 puntos.

---

## 🚀 Flujo de Trabajo con Git

Para evitar pisarnos el código, sigan estos pasos al trabajar en su módulo:

1. **Actualizar su repositorio local antes de programar:**
   ```bash
   git pull origin main