/**
 * MITM Packet Injection Dashboard Control Panel
 * Manejo interactivo del lado del cliente, conexión SSE y visualizaciones.
 */

document.addEventListener("DOMContentLoaded", () => {
    // Referencias del DOM
    const ifaceSelect = document.getElementById("iface-select");
    const victimIpInput = document.getElementById("victim-ip");
    const bpfFilterInput = document.getElementById("bpf-filter");
    const targetStrInput = document.getElementById("target-str");
    const replacementStrInput = document.getElementById("replacement-str");
    const configForm = document.getElementById("config-form");
    const toggleBtn = document.getElementById("toggle-btn");
    const btnText = document.getElementById("btn-text");
    const playIcon = toggleBtn.querySelector(".play-icon");
    const stopIcon = toggleBtn.querySelector(".stop-icon");
    
    const globalIndicator = document.getElementById("global-indicator");
    const statusText = document.getElementById("status-text");
    const liveBadge = document.getElementById("live-badge");
    
    // Estadísticas
    const statCaptured = document.getElementById("stat-captured");
    const statInjected = document.getElementById("stat-injected");
    const statUptime = document.getElementById("stat-uptime");
    
    // Consola de logs
    const logStream = document.getElementById("log-stream");
    const emptyState = document.getElementById("empty-state");
    const clearLogsBtn = document.getElementById("clear-logs");

    // Gráfica
    const canvas = document.getElementById("activity-chart");
    const ctx = canvas.getContext("2d");
    
    let isRunning = false;
    let eventSource = null;
    let activityData = Array(30).fill(0); // Últimos 30 segundos
    let chartAnimationId = null;

    // Configurar Canvas para alta resolución de pantalla
    function setupCanvas() {
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.getBoundingClientRect();
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.scale(dpr, dpr);
    }
    window.addEventListener("resize", setupCanvas);
    setupCanvas();

    // Dibujar la gráfica de actividad de inyección en vivo
    function drawChart() {
        const width = canvas.width / (window.devicePixelRatio || 1);
        const height = canvas.height / (window.devicePixelRatio || 1);
        ctx.clearRect(0, 0, width, height);

        const padding = 10;
        const chartWidth = width - padding * 2;
        const chartHeight = height - padding * 2;

        const maxVal = Math.max(...activityData, 4); // Mínimo escala de 4 unidades de altura

        // Dibujar líneas guía horizontales
        ctx.strokeStyle = "#223047";
        ctx.lineWidth = 1;
        for (let i = 0; i <= 4; i++) {
            const y = padding + (chartHeight / 4) * i;
            ctx.beginPath();
            ctx.moveTo(padding, y);
            ctx.lineTo(width - padding, y);
            ctx.stroke();
        }

        // Crear gradiente para el gráfico de área
        const gradient = ctx.createLinearGradient(0, padding, 0, height - padding);
        gradient.addColorStop(0, "rgba(255, 170, 0, 0.4)");
        gradient.addColorStop(1, "rgba(255, 170, 0, 0.0)");

        ctx.beginPath();
        const step = chartWidth / (activityData.length - 1);
        
        // Empezar el camino desde la base izquierda
        ctx.moveTo(padding, height - padding);

        for (let i = 0; i < activityData.length; i++) {
            const x = padding + i * step;
            const y = height - padding - (activityData[i] / maxVal) * chartHeight;
            ctx.lineTo(x, y);
        }

        ctx.lineTo(width - padding, height - padding);
        ctx.closePath();
        ctx.fillStyle = gradient;
        ctx.fill();

        // Dibujar la línea superior con brillo
        ctx.strokeStyle = "#ffaa00";
        ctx.lineWidth = 2;
        ctx.shadowColor = "rgba(255, 170, 0, 0.4)";
        ctx.shadowBlur = 8;
        ctx.beginPath();
        for (let i = 0; i < activityData.length; i++) {
            const x = padding + i * step;
            const y = height - padding - (activityData[i] / maxVal) * chartHeight;
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        }
        ctx.stroke();
        
        // Resetear sombras
        ctx.shadowBlur = 0;

        chartAnimationId = requestAnimationFrame(drawChart);
    }

    // Actualizar datos del gráfico dinámicamente cada segundo
    let currentSecondInjections = 0;
    setInterval(() => {
        if (isRunning) {
            activityData.push(currentSecondInjections);
            activityData.shift();
            currentSecondInjections = 0;
        } else {
            // Decaimiento natural al estar inactivo
            activityData.push(0);
            activityData.shift();
        }
    }, 1000);

    // Obtener interfaces de red locales
    async function loadInterfaces() {
        try {
            const res = await fetch("/api/interfaces");
            const data = await res.json();
            if (data.status === "success" && data.interfaces.length > 0) {
                ifaceSelect.innerHTML = "";
                data.interfaces.forEach(iface => {
                    const option = document.createElement("option");
                    option.value = iface;
                    option.textContent = iface;
                    if (iface === "eth0") option.selected = true;
                    ifaceSelect.appendChild(option);
                });
            } else {
                ifaceSelect.innerHTML = '<option value="">No se encontraron interfaces</option>';
            }
        } catch (e) {
            ifaceSelect.innerHTML = '<option value="">Error al cargar interfaces</option>';
            console.error("Error al obtener interfaces:", e);
        }
    }

    // Comprobar estado inicial del Sniffer al cargar la página
    async function checkStatus() {
        try {
            const res = await fetch("/api/status");
            const data = await res.json();
            updateUI(data.active, data.stats);
            if (data.active) {
                // Rellenar formulario con la config activa
                ifaceSelect.value = data.config.iface;
                victimIpInput.value = data.config.victim;
                bpfFilterInput.value = data.config.filter;
                targetStrInput.value = data.config.target_str;
                replacementStrInput.value = data.config.replacement_str;
                startSSE();
            }
        } catch (e) {
            console.error("Error comprobando estado:", e);
        }
    }

    // Cambiar estados de UI según si el Sniffer está activo o no
    function updateUI(active, stats = null) {
        isRunning = active;
        if (active) {
            toggleBtn.className = "btn btn-primary stop";
            btnText.textContent = "Detener Sniffer";
            playIcon.classList.add("hidden");
            stopIcon.classList.remove("hidden");
            
            globalIndicator.className = "pulse-indicator active";
            statusText.textContent = "ESCUCHANDO RED ACTIVA";
            statusText.style.color = "var(--color-accent)";
            liveBadge.classList.remove("hidden");
            
            // Habilitar/Deshabilitar entradas de formulario
            ifaceSelect.disabled = true;
            victimIpInput.disabled = true;
            bpfFilterInput.disabled = true;
            targetStrInput.disabled = true;
            replacementStrInput.disabled = true;
        } else {
            toggleBtn.className = "btn btn-primary start";
            btnText.textContent = "Iniciar Sniffer";
            playIcon.classList.remove("hidden");
            stopIcon.classList.add("hidden");
            
            globalIndicator.className = "pulse-indicator inactive";
            statusText.textContent = "Sistema Apagado";
            statusText.style.color = "var(--text-secondary)";
            liveBadge.classList.add("hidden");
            
            // Habilitar entradas
            ifaceSelect.disabled = false;
            victimIpInput.disabled = false;
            bpfFilterInput.disabled = false;
            targetStrInput.disabled = false;
            replacementStrInput.disabled = false;
        }

        if (stats) {
            statCaptured.textContent = stats.captured.toLocaleString();
            statInjected.textContent = stats.injected.toLocaleString();
            statUptime.textContent = formatUptime(stats.uptime);
        }
    }

    // Formatear segundos a formato H:M:S legible
    function formatUptime(secs) {
        if (!secs) return "0s";
        const h = Math.floor(secs / 3600);
        const m = Math.floor((secs % 3600) / 60);
        const s = secs % 60;
        
        let out = "";
        if (h > 0) out += `${h}h `;
        if (m > 0 || h > 0) out += `${m}m `;
        out += `${s}s`;
        return out;
    }

    // Crear diferencias de texto resaltadas en la consola
    function highlightDiff(str, target, replacement) {
        if (!str || !target) return escapeHTML(str);
        
        const escapedTarget = escapeHTML(target);
        const escapedReplacement = escapeHTML(replacement);
        
        // Crear versión original tachada
        const regexTarget = new RegExp(escapedTarget, "gi");
        const originalText = escapeHTML(str).replace(regexTarget, match => `<span class="highlight">${match}</span>`);
        
        // Crear versión modificada
        const modifiedText = escapeHTML(str).replace(regexTarget, `<span class="highlight-new">${escapedReplacement}</span>`);
        
        return { originalText, modifiedText };
    }

    // Escapar entidades HTML para prevenir vulnerabilidades de XSS
    function escapeHTML(str) {
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Iniciar conexión Server-Sent Events (SSE)
    function startSSE() {
        if (eventSource) {
            eventSource.close();
        }

        eventSource = new EventSource("/api/events");

        eventSource.onmessage = (event) => {
            const data = JSON.parse(event.data);
            
            // Actualizar contadores de estadísticas globales
            if (data.stats) {
                statCaptured.textContent = data.stats.captured.toLocaleString();
                statInjected.textContent = data.stats.injected.toLocaleString();
                statUptime.textContent = formatUptime(data.stats.uptime);
            }

            if (data.type === "injection") {
                currentSecondInjections += 1;
                appendPacketLog(data.data);
            } else if (data.type === "status_change") {
                updateUI(data.data.active);
            } else if (data.type === "error") {
                alert(`Error en el Sniffer de Red: ${data.data.message}`);
                stopSniffer();
            }
        };

        eventSource.onerror = () => {
            console.warn("Conexión SSE perdida. Intentando reconectar...");
        };
    }

    // Añadir fila de paquete inyectado a la consola virtual
    function appendPacketLog(pkt) {
        if (emptyState) {
            emptyState.style.display = "none";
        }

        const now = new Date().toLocaleTimeString();
        const diffs = highlightDiff(pkt.original, pkt.target, pkt.replacement);

        const row = document.createElement("div");
        row.className = "packet-row";
        row.innerHTML = `
            <div class="pkt-meta">
                <div class="pkt-addresses">
                    <span class="pkt-src">${pkt.src}:${pkt.sport}</span>
                    <span class="pkt-arrow">➔</span>
                    <span class="pkt-dst">${pkt.dst}:${pkt.dport}</span>
                </div>
                <span class="pkt-time">${now}</span>
            </div>
            <div class="pkt-payload-diff">
                <div class="diff-col">
                    <span class="diff-title">Payload Original</span>
                    <div class="diff-content original">${diffs.originalText}</div>
                </div>
                <div class="diff-col">
                    <span class="diff-title">Payload Inyectado</span>
                    <div class="diff-content modified">${diffs.modifiedText}</div>
                </div>
            </div>
        `;

        logStream.appendChild(row);
        
        // Auto-scroll al fondo
        const terminalBody = document.querySelector(".terminal-body");
        terminalBody.scrollTop = terminalBody.scrollHeight;

        // Limitar logs acumulados en el navegador a 50 filas para no degradar rendimiento
        while (logStream.children.length > 50) {
            // Omitir el empty state si existiera
            if (logStream.firstChild.id !== "empty-state") {
                logStream.removeChild(logStream.firstChild);
            } else {
                break;
            }
        }
    }

    // Detener la conexión SSE del lado del cliente
    function stopSSE() {
        if (eventSource) {
            eventSource.close();
            eventSource = null;
        }
    }

    // Detener el Sniffer a través de API HTTP POST
    async function stopSniffer() {
        try {
            const res = await fetch("/api/stop", { method: "POST" });
            const data = await res.json();
            if (data.status === "success") {
                updateUI(false);
                stopSSE();
            } else {
                alert(`Error: ${data.message}`);
            }
        } catch (e) {
            console.error("Error al detener:", e);
        }
    }

    // Manejar evento Submit del formulario (Iniciar/Detener el ataque)
    configForm.addEventListener("submit", async (e) => {
        e.preventDefault();

        if (isRunning) {
            await stopSniffer();
        } else {
            // Recoger configuración del formulario
            const config = {
                iface: ifaceSelect.value,
                victim: victimIpInput.value,
                filter: bpfFilterInput.value,
                target_str: targetStrInput.value,
                replacement_str: replacementStrInput.value
            };

            try {
                const res = await fetch("/api/start", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(config)
                });
                const data = await res.json();
                
                if (data.status === "success") {
                    updateUI(true, { captured: 0, injected: 0, uptime: 0 });
                    startSSE();
                } else {
                    alert(`Error al iniciar: ${data.message}`);
                }
            } catch (err) {
                console.error("Error en petición start:", err);
                alert("Error al intentar comunicarse con el servidor. ¿El servidor está corriendo?");
            }
        }
    });

    // Limpiar logs de la consola virtual
    clearLogsBtn.addEventListener("click", () => {
        logStream.innerHTML = "";
        logStream.appendChild(emptyState);
        emptyState.style.display = "flex";
    });

    // Iniciar flujo del Dashboard
    loadInterfaces();
    checkStatus();
    drawChart(); // Iniciar bucle de animación de la gráfica
});
