# Práctica: Ataque Hombre en el Medio (MITM) por Inyección de Paquetes

## Objetivo

Describir y demostrar un ataque de tipo Man in the Middle (MITM) basado en inyección de paquetes, en un entorno de laboratorio controlado.

## Archivos incluidos

- `mitm_packet_injection.py`: script de consola en Python con Scapy para capturar y modificar paquetes.
- `mitm_gui_server.py`: servidor web interactivo (Flask + Scapy) que actúa como panel de control gráfico (GUI) premium para el ataque en tiempo real.
- `templates/` y `static/`: plantillas HTML5, estilos CSS3 modernos (con modo oscuro refinado, efectos de cristal y micro-animaciones) y JavaScript dinámico para el panel interactivo.
- `requirements.txt`: dependencias necesarias del proyecto (Scapy, Flask).

## Requisitos

- Linux con privilegios de administrador (`sudo`), indispensable para habilitar el modo promiscuo e inyectar paquetes a nivel de socket de bajo nivel con Scapy.
- Python 3.x.
- Dependencias indicadas en `requirements.txt` (`scapy` y `flask`).
- Entorno de laboratorio controlado con una víctima y un atacante (o una VM de prueba).

## Instalación

Instala las dependencias necesarias ejecutando:

```bash
python3 -m pip install -r requirements.txt
```

---

## Modos de Ejecución

### Opción A: Modo Consola (Script básico)

1. **Habilitar reenvío de paquetes en el atacante:**
   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1
   ```
2. **Ejecutar el script:**
   ```bash
   sudo python3 mitm_packet_injection.py --iface eth0 --victim 192.168.1.10
   ```
   - Cambia `eth0` por la interfaz correcta de tu atacante.
   - Cambia `192.168.1.10` por la IP de la víctima remota.
3. **Realizar ARP spoofing** (usando `arpspoof` u otra herramienta) desde el atacante hacia la víctima y el gateway.
4. **Observar la salida** en consola al modificarse los paquetes HTTP.

---

### Opción B: Panel de Control Web Interactiva (GUI Premium) — *¡NUEVO!*

Hemos desarrollado un panel visual premium e interactivo que facilita enormemente el control y monitoreo del ataque, mostrando estadísticas dinámicas en tiempo real e inyecciones en vivo a través de una interfaz gráfica moderna.

#### Características del Panel:
- **Detección Automática de Interfaces:** Menú desplegable dinámico que recupera en tiempo real las interfaces de red activas en el atacante.
- **Configuración Dinámica:** Ajusta la interfaz, IP de la víctima, filtro de puertos, texto original a buscar (`target_str`) y texto de reemplazo (`replacement_str`) directamente desde el navegador.
- **Indicadores en Tiempo Real:** Dashboard con widgets visuales que muestran paquetes capturados, inyecciones exitosas y el tiempo de actividad (`Uptime`).
- **Live Stream de Eventos (SSE):** Flujo en vivo de paquetes interceptados y modificados en tiempo real, detallando IP/puerto origen, IP/puerto destino, y el antes/después del payload modificado.
- **Control de Inicio/Parada:** Botón de arranque y detención segura del sniffer en un hilo de ejecución independiente en segundo plano.

#### Instrucciones de Ejecución:

1. **Habilitar reenvío de paquetes en el atacante:**
   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1
   ```
2. **Ejecutar el servidor web interactivo con privilegios de administrador:**
   ```bash
   sudo python3 mitm_gui_server.py
   ```
   *(Nota: Se requiere obligatoriamente `sudo` para que Scapy pueda abrir sockets crudos en la interfaz de red).*
3. **Acceder al Panel Web:**
   Abre tu navegador de preferencia e ingresa a: **`http://localhost:5000`**
4. **Realizar ARP spoofing** hacia la víctima y el gateway en otra pestaña de terminal.
5. **Configurar e Iniciar:**
   - Selecciona la interfaz de red correspondiente.
   - Especifica la IP de la víctima (opcional para interceptar todo el tráfico del filtro).
   - Define el texto a buscar (ej: `Hello`) y el de reemplazo (ej: `Hola`).
   - Presiona **"Iniciar Captura"**. ¡Verás los datos actualizarse al instante!

> Este panel y script están diseñados para escenarios de laboratorio controlado donde la PC víctima reside en la misma red local (LAN) permitiendo al atacante interceptar tráfico HTTP sin cifrar (puerto 80).

## Descripción general

Un ataque MITM por inyección de paquetes se basa en:

- Colocar al atacante entre una víctima y un gateway.
- Capturar el tráfico de la víctima.
- Modificar o crear paquetes antes de reenviarlos.

### Conceptos clave

- **ARP spoofing**: engañar a la víctima para que direccione su tráfico al atacante.
- **Reenvío IP**: permitir que el atacante reenvíe paquetes hacia el destino legítimo.
- **Inyección de paquetes**: crear o modificar paquetes con herramientas como Scapy.

## Advertencia

Solo use este código en un entorno autorizado y de laboratorio. Nunca realice ataques MITM en redes ajenas o sin permiso.
