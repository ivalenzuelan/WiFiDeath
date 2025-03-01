#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sistema de detección y mitigación de ataques de desautenticación en redes WiFi

"""

from scapy.all import *
import argparse
import logging
import time
import os
import threading
import signal
import sys

# Configuración del sistema de logs
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("wifi_protection.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger()

class DeauthProtector:
    def __init__(self, interface, bssid=None, essid=None, mitigation=False, threshold=10, time_window=60):
        self.interface = interface
        self.bssid = bssid
        self.essid = essid
        self.mitigation_enabled = mitigation
        self.threshold = threshold
        self.time_window = time_window
        
        # Contadores y seguimiento
        self.deauth_counter = {}
        self.suspicious_macs = set()
        self.ap_clients = set()
        self.running = True
        
        # Lista blanca de MACs (punto de acceso legítimo)
        self.whitelist = set()
        if bssid:
            self.whitelist.add(bssid)
    
    def setup_monitor_mode(self):
        """Configura la interfaz en modo monitor"""
        try:
            os.system(f"ip link set {self.interface} down")
            os.system(f"iw dev {self.interface} set type monitor")
            os.system(f"ip link set {self.interface} up")
            logger.info(f"Interfaz {self.interface} configurada en modo monitor")
            return True
        except Exception as e:
            logger.error(f"Error al configurar modo monitor: {e}")
            return False
    
    def stop_monitor_mode(self):
        """Restaura la interfaz a modo administrado"""
        try:
            os.system(f"ip link set {self.interface} down")
            os.system(f"iw dev {self.interface} set type managed")
            os.system(f"ip link set {self.interface} up")
            logger.info(f"Interfaz {self.interface} restaurada a modo administrado")
        except Exception as e:
            logger.error(f"Error al restaurar modo administrado: {e}")
    
    def scan_for_ap(self):
        """Escanea redes disponibles para encontrar el AP objetivo por ESSID"""
        if not self.essid:
            logger.error("No se especificó ESSID para el escaneo")
            return False
            
        logger.info(f"Escaneando redes en busca de '{self.essid}'...")
        
        networks = {}
        
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                try:
                    ssid = pkt[Dot11Elt].info.decode()
                    bssid = pkt[Dot11].addr2
                    if ssid not in networks:
                        networks[ssid] = bssid
                        logger.info(f"Red encontrada: {ssid} ({bssid})")
                        
                    if ssid == self.essid:
                        return True
                except Exception as e:
                    pass
            return False
        
        sniff(iface=self.interface, prn=packet_handler, stop_filter=packet_handler, timeout=10)
        
        if self.essid in networks:
            self.bssid = networks[self.essid]
            self.whitelist.add(self.bssid)
            logger.info(f"AP encontrado: {self.essid} ({self.bssid})")
            return True
        else:
            logger.error(f"No se encontró AP con ESSID '{self.essid}'")
            return False
    
    def detect_deauth(self, pkt):
        """Detecta paquetes de desautenticación"""
        # Verificar si es un paquete de desautenticación (tipo=0, subtipo=12)
        if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 12:
            src = pkt.addr2
            dst = pkt.addr1
            
            # Registrar información del paquete
            logger.debug(f"Paquete deauth detectado: {src} -> {dst}")
            
            # Si tenemos un BSSID objetivo específico, solo nos interesan los paquetes relacionados
            if self.bssid and not (src == self.bssid or dst == self.bssid):
                return
            
            # Incrementar contador para la fuente del paquete
            current_time = int(time.time())
            if src not in self.deauth_counter:
                self.deauth_counter[src] = []
            
            # Añadir marca de tiempo
            self.deauth_counter[src].append(current_time)
            
            # Limpiar registros antiguos
            self.deauth_counter[src] = [t for t in self.deauth_counter[src] 
                                       if t > current_time - self.time_window]
            
            # Comprobar umbral
            if len(self.deauth_counter[src]) >= self.threshold:
                if src not in self.suspicious_macs:
                    self.suspicious_macs.add(src)
                    logger.warning(f"ALERTA: Posible ataque de desautenticación desde {src}")
                    logger.warning(f"Se detectaron {len(self.deauth_counter[src])} paquetes en {self.time_window} segundos")
                    
                    # Acciones de mitigación
                    if self.mitigation_enabled:
                        self.apply_mitigation(src)
    
    def apply_mitigation(self, attacker_mac):
        """Aplica medidas de mitigación contra MAC sospechosa"""
        if attacker_mac in self.whitelist:
            logger.warning(f"La MAC {attacker_mac} está en la lista blanca. No se aplicará mitigación.")
            return
            
        logger.info(f"Aplicando mitigación contra {attacker_mac}")
        
        # Opción 1: Enviar paquetes de autenticación para contrarrestar
        if self.bssid and self.ap_clients:
            threading.Thread(target=self.send_auth_packets, args=(attacker_mac,)).start()
    
    def send_auth_packets(self, attacker_mac):
        """Envía paquetes de autenticación para contrarrestar el ataque"""
        if not self.bssid:
            return
            
        logger.info(f"Enviando paquetes de autenticación para contrarrestar ataque desde {attacker_mac}")
        
        # Construir paquete de autenticación
        for client in self.ap_clients:
            try:
                # Enviar paquete de autenticación
                auth_packet = RadioTap() / Dot11(type=0, subtype=11, addr1=client, 
                                               addr2=self.bssid, addr3=self.bssid) / \
                             Dot11Auth(seqnum=2)
                
                # Enviar varias veces para asegurar recepción
                for _ in range(5):
                    sendp(auth_packet, iface=self.interface, verbose=0)
                    time.sleep(0.1)
                
                logger.info(f"Paquetes de autenticación enviados para {client}")
            except Exception as e:
                logger.error(f"Error al enviar paquete de autenticación: {e}")
    
    def monitor_clients(self, pkt):
        """Mantiene una lista de clientes conectados al AP"""
        if not self.bssid:
            return
            
        if pkt.haslayer(Dot11):
            # Paquetes de datos (tipo=2)
            if pkt.type == 2:
                # Si hay comunicación con nuestro AP, registrar cliente
                if pkt.addr1 == self.bssid and pkt.addr2 not in self.ap_clients:
                    self.ap_clients.add(pkt.addr2)
                    logger.debug(f"Nuevo cliente detectado: {pkt.addr2}")
                elif pkt.addr2 == self.bssid and pkt.addr1 not in self.ap_clients:
                    self.ap_clients.add(pkt.addr1)
                    logger.debug(f"Nuevo cliente detectado: {pkt.addr1}")
    
    def packet_handler(self, pkt):
        """Manejador principal de paquetes"""
        if not self.running:
            return
            
        # Detectar desautenticaciones
        self.detect_deauth(pkt)
        
        # Monitorizar clientes
        self.monitor_clients(pkt)
    
    def start(self):
        """Inicia el sistema de protección"""
        # Configurar modo monitor
        if not self.setup_monitor_mode():
            logger.error("No se pudo configurar el modo monitor. Saliendo...")
            return
        
        # Si tenemos ESSID pero no BSSID, escanear para encontrar el AP
        if self.essid and not self.bssid:
            if not self.scan_for_ap():
                logger.warning("Continuando sin un AP objetivo específico")
        
        logger.info("=== Sistema de Protección WiFi Iniciado ===")
        if self.bssid:
            logger.info(f"Monitorizando AP: {self.bssid}")
        if self.mitigation_enabled:
            logger.info("Modo de mitigación: ACTIVADO")
        else:
            logger.info("Modo de mitigación: DESACTIVADO (solo detección)")
        
        # Configurar manejador de señales para salida limpia
        def signal_handler(sig, frame):
            logger.info("Deteniendo el sistema...")
            self.running = False
            self.stop_monitor_mode()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Iniciar captura de paquetes
        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=0)
        except Exception as e:
            logger.error(f"Error en la captura de paquetes: {e}")
        finally:
            self.stop_monitor_mode()

def main():
    parser = argparse.ArgumentParser(description='Sistema de protección contra ataques de desautenticación WiFi')
    parser.add_argument('-i', '--interface', required=True, help='Interfaz de red a utilizar')
    parser.add_argument('-b', '--bssid', help='BSSID del punto de acceso a proteger')
    parser.add_argument('-e', '--essid', help='ESSID (nombre) del punto de acceso a proteger')
    parser.add_argument('-m', '--mitigation', action='store_true', help='Activar modo de mitigación')
    parser.add_argument('-t', '--threshold', type=int, default=10, help='Umbral de paquetes para detección (default: 10)')
    parser.add_argument('-w', '--window', type=int, default=60, help='Ventana de tiempo en segundos para el umbral (default: 60)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Habilitar modo detallado (logs adicionales)')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Verificar permisos de administrador
    if os.geteuid() != 0:
        logger.error("Este script requiere permisos de administrador. Ejecute con sudo.")
        sys.exit(1)
    
    # Iniciar protector
    protector = DeauthProtector(
        interface=args.interface,
        bssid=args.bssid,
        essid=args.essid,
        mitigation=args.mitigation,
        threshold=args.threshold,
        time_window=args.window
    )
    
    protector.start()

if __name__ == "__main__":
    main()
