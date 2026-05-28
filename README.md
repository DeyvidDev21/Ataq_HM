# Práctica: Ataque Hombre en el Medio (MITM) por Inyección de Paquetes

## Objetivo

Describir y demostrar un ataque de tipo Man in the Middle (MITM) basado en inyección de paquetes, en un entorno de laboratorio controlado.

## Archivos incluidos

- `mitm_packet_injection.py`: script de ejemplo en Python con Scapy para capturar y modificar paquetes.
- `requirements.txt`: dependencias necesarias.

## Requisitos

- Linux con privilegios de administrador (sudo).
- Python 3.
- Paquete `scapy`.
- Entorno de laboratorio con una víctima y un atacante, o una VM de prueba.

## Uso recomendado

1. Instalar dependencias:

```bash
python3 -m pip install -r requirements.txt
```

2. Habilitar reenvío de paquetes en el atacante:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

3. Ejecutar el script en el equipo atacante.

```bash
sudo python3 mitm_packet_injection.py --iface eth0 --victim 192.168.1.10
```

- Cambia `eth0` por la interfaz correcta de tu atacante.
- Cambia `192.168.1.10` por la IP de la PC remota víctima.

4. Realizar el ARP spoofing desde el atacante hacia la víctima y el gateway.

5. Observar la salida y la modificación de paquetes HTTP.

> Este script funciona en un escenario de laboratorio donde la PC remota está en la misma red local (LAN) y el atacante puede interceptar su tráfico mediante MITM.

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
