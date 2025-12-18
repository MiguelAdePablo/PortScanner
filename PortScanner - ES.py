"""
Escáner de Puertos con Interfaz Gráfica
Autor: Miguel Angel de Pablo
Licencia: MIT
Web: https://github.com/MiguelAdePablo/PortScanner
Versión: 3.23

"""
# =============================================================================
# Escáner de Puertos con Interfaz Gráfica basada en CustomTkinter
# =============================================================================

import socket
import ipaddress
import re
import datetime
import threading
import csv
import base64
from typing import Callable, List, Tuple, Optional

import customtkinter as ctk
from tkinter import scrolledtext, filedialog
from PIL import Image
import io

# =============================================================================
# Requisitos
# =============================================================================

"""
pip install customtkinter Pillow
"""

# =============================================================================
# 1. CONFIGURACIÓN INICIAL DE LA APLICACIÓN
# =============================================================================

# Configuración global del tema de CustomTkinter: oscuro con acento azul.
# Esto afecta a todos los widgets creados posteriormente.
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

# =============================================================================
# 2. UTILIDADES DE VALIDACIÓN Y CONVERSIÓN
# =============================================================================

def validar_direccion_ip(ip: str) -> bool:
    """
    Valida si una cadena representa una dirección IPv4 válida en formato decimal.
    
    - Usa regex para verificar el formato base (cuatro octetos separados por puntos).
    - Luego comprueba que cada octeto esté en el rango [0, 255].
    - Evita excepciones mediante manejo explícito de ValueError.
    """
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return False
    try:
        return all(0 <= int(octeto) <= 255 for octeto in ip.split('.'))
    except ValueError:
        return False


def validar_puerto(puerto) -> bool:
    """
    Valida si un valor puede interpretarse como un número de puerto TCP/UDP válido (0-65535).
    """
    try:
        p = int(puerto)
        return 0 <= p <= 65535
    except (ValueError, TypeError):
        return False

# =============================================================================
# 3. LÓGICA DEL ESCÁNER DE PUERTOS (THREAD-SAFE)
# =============================================================================

def scan_ips(
    start_ip: str,
    end_ip: str,
    start_port: int,
    end_port: int,
    verbose: bool,
    stop_event: threading.Event,
    log_callback: Optional[Callable[[str], None]] = None,
    result_callback: Optional[Callable[[List[Tuple[str, int]]], None]] = None,
) -> None:
    """
    Escanea un rango de direcciones IP y puertos usando connect_ex() con timeout corto.
    
    - Operación no bloqueante: se ejecuta en hilo separado.
    - Soporta rango de IPs (inclusive) y rango de puertos (inclusive).
    - `stop_event` permite detener el escaneo desde otro hilo (cancelación cooperativa).
    - Los callbacks permiten comunicación segura con la interfaz gráfica (usando root.after).
    """
    try:
        start = ipaddress.ip_address(start_ip)
        end = ipaddress.ip_address(end_ip)

        if int(start) > int(end):
            if log_callback:
                log_callback("Error: La IP inicial no puede ser mayor que la final.")
            if result_callback:
                result_callback([])
            return

        open_ports: List[Tuple[str, int]] = []
        current_ip_int = int(start)

        while current_ip_int <= int(end):
            if stop_event.is_set():
                if log_callback:
                    log_callback("⏹️ Escaneo detenido por el usuario.")
                if result_callback:
                    result_callback(open_ports)
                return

            ip_address = str(ipaddress.ip_address(current_ip_int))
            for port in range(start_port, end_port + 1):
                if stop_event.is_set():
                    if log_callback:
                        log_callback("⏹️ Escaneo detenido por el usuario.")
                    if result_callback:
                        result_callback(open_ports)
                    return

                # Usamos socket en modo no bloqueante con timeout muy corto (~5 ms)
                # para mantener la interfaz gráfica responsiva.
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.005)
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    open_ports.append((ip_address, port))
                    if log_callback:
                        log_callback(f"✓ Puerto ABIERTO → IP: {ip_address}, Puerto: {port}")
                elif verbose and log_callback:
                    log_callback(f"  Puerto CERRADO → IP: {ip_address}, Puerto: {port}")
                sock.close()
            current_ip_int += 1

        if result_callback:
            result_callback(open_ports)

    except Exception as e:
        if log_callback:
            log_callback(f"❌ Error durante el escaneo: {e}")
        if result_callback:
            result_callback([])

# =============================================================================
# 4. INTERFAZ GRÁFICA CON CUSTOMTKINTER
# =============================================================================

class PortScannerGUI:
    """
    Aplicación GUI para escanear rangos de puertos en direcciones IP.
    
    - Usa hilos para no bloquear la interfaz durante el escaneo.
    - Incluye soporte para detención en caliente mediante threading.Event.
    - Permite guardar resultados en CSV.
    - Muestra IPs locales al inicio usando getaddrinfo().
    """

    def __init__(self, root: ctk.CTk) -> None:
        self.root = root
        self._configurar_ventana()
        self._inicializar_estado()
        self._crear_widgets()

    def _configurar_ventana(self) -> None:
        """Define el tamaño, título y restricciones mínimas de la ventana."""
        self.root.title("📡 Escáner de Puertos")
        self.root.geometry("500x620")
        self.root.minsize(500, 500)

    def _inicializar_estado(self) -> None:
        """Inicializa variables de control del estado del escaneo."""
        self.scan_thread: Optional[threading.Thread] = None
        self.stop_event: Optional[threading.Event] = None
        self.last_scan_results: List[Tuple[str, int]] = []

    def _crear_widgets(self) -> None:
        """Construye todos los elementos visuales de la interfaz."""
        # Frame contenedor principal (usa grid para alineación precisa)
        main_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=15)

        # === LOGO (OPCIONAL, CODIFICADO EN BASE64) ===
        # Si se proporciona una cadena base64 válida, se muestra un logo junto al título.
        # Esto evita dependencias de archivos externos.
        image_b64 = "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"  # Reemplazar por cadena real
        try:
            if image_b64.strip():
                image_data = base64.b64decode(image_b64)
                image = Image.open(io.BytesIO(image_data)).convert("RGBA")
                self.logo_image = ctk.CTkImage(light_image=image, dark_image=image, size=(70, 50))
                self.logo_label = ctk.CTkLabel(main_frame, image=self.logo_image, text="")
                self.logo_label.grid(row=0, column=0, padx=(0, 10), sticky="w")
        except Exception as e:
            print("Error cargando logo Base64:", e)

        # === TÍTULO ===
        title_label = ctk.CTkLabel(
            main_frame,
            text="\nEscáner de Puertos 📡 ",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title_label.grid(row=0, column=1, pady=(0, 20))

        # === CONFIGURACIÓN DE GRID ===
        main_frame.grid_columnconfigure(1, weight=1)

        # === ENTRADAS Y CONTROLES ===
        self._crear_campos_entrada(main_frame)
        self._crear_boton_escaneo(main_frame)
        self._crear_area_logs(main_frame)

        # Cargar IPs locales al inicio (útil para redes locales)
        self.load_local_ips()

    def _crear_campos_entrada(self, parent: ctk.CTkFrame) -> None:
        """Crea los campos de entrada para IPs y puertos, y el modo verbose."""
        labels = ["IP Inicial:", "IP Final (opcional):", "Puerto Inicial:", "Puerto Final (opcional):"]
        self.entries = []

        for i, text in enumerate(labels, start=1):
            label = ctk.CTkLabel(parent, text=text)
            label.grid(row=i, column=0, sticky="w", pady=5)

            entry = ctk.CTkEntry(parent, width=200)
            entry.grid(row=i, column=1, padx=(10, 0), pady=5, sticky="w")
            self.entries.append(entry)

        self.entry_start_ip, self.entry_end_ip, self.entry_start_port, self.entry_end_port = self.entries

        # Checkbox para modo detallado (logs de puertos cerrados)
        self.verbose_var = ctk.BooleanVar()
        verbose_check = ctk.CTkCheckBox(
            parent,
            text="Modo Verbose",
            variable=self.verbose_var,
            checkbox_width=14,
            checkbox_height=14,
            font=ctk.CTkFont(size=12),
            corner_radius=2,
            border_width=1
        )
        verbose_check.grid(row=5, column=0, columnspan=2, sticky="w", pady=(5, 10))

    def _crear_boton_escaneo(self, parent: ctk.CTkFrame) -> None:
        """Crea el botón principal que alterna entre iniciar y detener el escaneo."""
        self.scan_button = ctk.CTkButton(
            parent,
            text="🔍 Iniciar Escaneo",
            command=self.toggle_scan,
            font=ctk.CTkFont(weight="bold")
        )
        self.scan_button.grid(row=6, column=0, columnspan=2, pady=15)

    def _crear_area_logs(self, parent: ctk.CTkFrame) -> None:
        """Crea el área de texto con scroll para mostrar logs y resultados."""
        log_frame = ctk.CTkFrame(parent, fg_color="transparent")
        log_frame.grid(row=7, column=0, columnspan=2, sticky="nsew", pady=(15, 0))
        log_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(log_frame, text="Resultados / Logs:").grid(row=0, column=0, sticky="w")

        self.save_button = ctk.CTkButton(
            log_frame,
            text="💾 Guardar CSV",
            command=self.save_results_to_csv,
            width=100,
            font=ctk.CTkFont(size=12)
        )
        self.save_button.grid(row=0, column=1, sticky="e")

        # CustomTkinter no tiene ScrolledText, por lo que usamos el de tkinter estándar.
        text_frame = ctk.CTkFrame(log_frame, fg_color="transparent", border_width=1)
        text_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(5, 0))

        self.log_area = scrolledtext.ScrolledText(
            text_frame,
            wrap="word",
            bg="#2b2b2b",
            fg="white",
            insertbackground="white",
            relief="flat",
            font=("Consolas", 10),
            padx=10,
            pady=10
        )
        self.log_area.pack(fill="both", expand=True)
        self.log_area.config(state="disabled")

        log_frame.grid_rowconfigure(1, weight=1)
        parent.grid_rowconfigure(7, weight=1)

    # -------------------------------------------------------------------------
    # 5. FUNCIONALIDAD PRINCIPAL
    # -------------------------------------------------------------------------

    def load_local_ips(self) -> None:
        """
        Detecta y muestra las direcciones IPv4 locales del equipo actual.
        Útil para ayudar al usuario a escanear su propia red.
        """
        self.log_area.config(state="normal")
        self.log_area.insert("end", "📡 Direcciones IP locales del equipo:\n")
        host_name = socket.gethostname()
        ip_list = set()
        try:
            for info in socket.getaddrinfo(host_name, None):
                ip = info[4][0]
                try:
                    if ipaddress.ip_address(ip).version == 4:
                        ip_list.add(ip)
                except ValueError:
                    continue
        except Exception as e:
            self.log_area.insert("end", f"⚠️ No se pudieron obtener IPs locales: {e}\n")
        for ip in sorted(ip_list, key=lambda x: ipaddress.IPv4Address(x)):
            self.log_area.insert("end", f"  » {ip}\n")
        self.log_area.insert("end", "\n" + "="*60 + "\n\n")
        self.log_area.config(state="disabled")
        self.log_area.see("end")

    def log_message(self, msg: str) -> None:
        """
        Envía un mensaje al área de logs de forma segura desde cualquier hilo.
        Usa root.after para garantizar que la actualización ocurra en el hilo principal.
        """
        self.root.after(0, self._log_message_safe, msg)

    def _log_message_safe(self, msg: str) -> None:
        """Actualiza el área de logs en el hilo principal (thread-safe)."""
        self.log_area.config(state="normal")
        self.log_area.insert("end", msg + "\n")
        self.log_area.config(state="disabled")
        self.log_area.see("end")

    def toggle_scan(self) -> None:
        """
        Alterna entre iniciar un nuevo escaneo y detener uno en curso.
        Cambia dinámicamente el texto y estado del botón.
        """
        if self.scan_thread and self.scan_thread.is_alive() and self.stop_event is not None:
            self.stop_event.set()
            self.scan_button.configure(state="disabled", text="⏹️ Deteniendo...")
        else:
            self.start_new_scan()

    def start_new_scan(self) -> None:
        """
        Valida entradas, limpia logs previos e inicia un nuevo hilo de escaneo.
        """
        start_ip = self.entry_start_ip.get().strip()
        end_ip = self.entry_end_ip.get().strip() or start_ip
        start_port = self.entry_start_port.get().strip()
        end_port = self.entry_end_port.get().strip() or start_port

        if not validar_direccion_ip(start_ip):
            self.log_message("❌ Error: IP inicial no válida.")
            return
        if not validar_direccion_ip(end_ip):
            self.log_message("❌ Error: IP final no válida.")
            return
        if not validar_puerto(start_port):
            self.log_message("❌ Error: Puerto inicial no válido.")
            return
        if not validar_puerto(end_port):
            self.log_message("❌ Error: Puerto final no válido.")
            return

        start_port = int(start_port)
        end_port = int(end_port)
        if start_port > end_port:
            self.log_message("❌ Error: Puerto inicial no puede ser mayor que el final.")
            return

        # Limpiar área de logs antes de nuevo escaneo
        self.log_area.config(state="normal")
        self.log_area.delete(1.0, "end")
        self.log_area.config(state="disabled")
        self.last_scan_results = []

        self.stop_event = threading.Event()
        self.log_message("⏳ Iniciando escaneo...")

        t1 = datetime.datetime.now()

        def on_scan_complete(results: List[Tuple[str, int]]) -> None:
            """Callback ejecutado tras finalizar el escaneo (en hilo principal)."""
            self.last_scan_results = results
            t2 = datetime.datetime.now()
            total = t2 - t1
            horas = total.seconds // 3600
            minutos = (total.seconds % 3600) // 60
            segundos = total.seconds % 60

            if results:
                self.log_message("\n✅ Puertos abiertos encontrados:")
                for ip, port in results:
                    self.log_message(f"  → IP: {ip}, Puerto: {port}")
            else:
                self.log_message("\n⚠️ No se encontraron puertos abiertos.")
            self.log_message(f"\n🕒 Duración total: {horas} h {minutos} min {segundos} s")
            # Restaurar botón en hilo principal
            self.root.after(0, lambda: self.scan_button.configure(text="🔍 Iniciar Escaneo", state="normal"))

        self.scan_thread = threading.Thread(
            target=scan_ips,
            args=(start_ip, end_ip, start_port, end_port, self.verbose_var.get(), self.stop_event),
            kwargs={"log_callback": self.log_message, "result_callback": on_scan_complete},
            daemon=True
        )
        self.scan_thread.start()
        self.scan_button.configure(text="❌ Detener escaneo", state="normal")

    def save_results_to_csv(self) -> None:
        """Guarda los resultados del último escaneo en un archivo CSV elegido por el usuario."""
        if not self.last_scan_results:
            self.log_message("ℹ️ No hay resultados para guardar.")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("Archivos CSV", "*.csv"), ("Todos los archivos", "*.*")],
            title="Guardar resultados como CSV"
        )
        if not filepath:
            return

        try:
            with open(filepath, mode='w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["IP", "Puerto"])
                writer.writerows(self.last_scan_results)
            self.log_message(f"✅ Resultados guardados en: {filepath}")
        except Exception as e:
            self.log_message(f"❌ Error al guardar el archivo: {e}")

# =============================================================================
# 6. PUNTO DE ENTRADA
# =============================================================================

if __name__ == "__main__":
    app = ctk.CTk()
    gui = PortScannerGUI(app)
    app.mainloop()