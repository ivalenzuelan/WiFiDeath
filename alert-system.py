#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sistema de alertas para ataques de desautenticación WiFi
Permite notificaciones por correo, SMS o notificaciones de escritorio
"""

import logging
import smtplib
import subprocess
import json
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# Configuración del sistema de logs
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("alert_system.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger()

class AlertSystem:
    def __init__(self, config_file="alert_config.json"):
        self.config = self.load_config(config_file)
        self.alert_history = []
    
    def load_config(self, config_file):
        """Carga la configuración del sistema de alertas"""
        default_config = {
            "email": {
                "enabled": False,
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 587,
                "username": "",
                "password": "",
                "recipients": []
            },
            "desktop": {
                "enabled": True
            },
            "telegram": {
                "enabled": False,
                "bot_token": "",
                "chat_id": ""
            },
            "alert_cooldown": 300,  # 5 minutos entre alertas similares
            "severity_thresholds": {
                "low": 5,
                "medium": 15,
                "high": 30
            }
        }
        
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Archivo de configuración {config_file} no encontrado. Usando valores predeterminados.")
                return default_config
        except Exception as e:
            logger.error(f"Error al cargar la configuración: {e}")
            return default_config
    
    def send_email_alert(self, subject, message):
        """Envía una alerta por correo electrónico"""
        if not self.config["email"]["enabled"]:
            return False
            
        try:
            msg = MIMEMultipart()
            msg["From"] = self.config["email"]["username"]
            msg["To"] = ", ".join(self.config["email"]["recipients"])
            msg["Subject"] = subject
            
            msg.attach(MIMEText(message, "plain"))
            
            server = smtplib.SMTP(self.config["email"]["smtp_server"], self.config["email"]["smtp_port"])
            server.starttls()
            server.login(self.config["email"]["username"], self.config["email"]["password"])
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Alerta por correo enviada a {len(self.config['email']['recipients'])} destinatarios")
            return True
        except Exception as e:
            logger.error(f"Error al enviar alerta por correo: {e}")
            return False
    
    def send_desktop_alert(self, title, message):
        """Envía una notificación de escritorio"""
        if not self.config["desktop"]["enabled"]:
            return False
            
        try:
            # Detectar sistema operativo
            if os.name == "posix":  # Linux/Unix
                subprocess.run(["notify-send", title, message])
                logger.info("Notificación de escritorio enviada (Linux)")
                return True
            elif os.name == "nt":  # Windows
                # Requiere modulo win10toast
                try:
                    from win10toast import ToastNotifier
                    toaster = ToastNotifier()
                    toaster.show_toast(title, message, duration=10)
                    logger.info("Notificación de escritorio enviada (Windows)")
                    return True
                except ImportError:
                    logger.error("Módulo win10toast no encontrado. No se pudo enviar notificación en Windows.")
                    return False
            elif sys.platform == "darwin":  # macOS
                subprocess.run(["osascript", "-e", f'display notification "{message}" with title "{title}"'])
                logger.info("Notificación de escritorio enviada (macOS)")
                return True
            else:
                logger.error("Sistema operativo no soportado para notificaciones de escritorio")
                return False
        except Exception as e:
            logger.error(f"Error al enviar notificación de escritorio: {e}")
            return False
    
    def send_telegram_alert(self, message):
        """Envía una alerta a través de Telegram"""
        if not self.config["telegram"]["enabled"]:
            return False
            
        try:
            import requests
            bot_token = self.config["telegram"]["bot_token"]
            chat_id = self.config["telegram"]["chat_id"]
            
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }
            
            response = requests.post(url, json=payload)
            
            if response.status_code == 200:
                logger.info("Alerta de Telegram enviada")
                return True
            else:
                logger.error(f"Error al enviar alerta de Telegram: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Error al enviar alerta de Telegram: {e}")
            return False
    
    def calculate_severity(self, deauth_count):
        """Calcula la severidad del ataque basado en la cantidad de paquetes"""
        thresholds = self.config["severity_thresholds"]
        
        if deauth_count >= thresholds["high"]:
            return "ALTA"
        elif deauth_count >= thresholds["medium"]:
            return "MEDIA"
        elif deauth_count >= thresholds["low"]:
            return "BAJA"
        else:
            return "INFORMATIVA"
    
    def should_alert(self, attacker_mac, deauth_count):
        """Determina si se debe enviar una alerta basada en la historia reciente"""
        current_time = datetime.now()
        cooldown = self.config["alert_cooldown"]
        
        # Buscar alertas recientes para la misma MAC
        for alert in self.alert_history:
            if alert["mac"] == attacker_mac:
                time_diff = (current_time - alert["timestamp"]).total_seconds()
                
                # Si no ha pasado el tiempo de enfriamiento, omitir alerta
                if time_diff < cooldown:
                    # Excepto si la severidad ha aumentado significativamente
                    if deauth_count > alert["count"] * 2:
                        logger.info(f"Escalada significativa de ataque desde {attacker_mac}. Enviando alerta.")
                        return True
                    else:
                        logger.info(f"Alerta omitida para {attacker_mac} (en periodo de enfriamiento: {time_diff}s < {cooldown}s)")
                        return False
        
        return True
    
    def trigger_alert(self, attacker_mac, victim_mac, bssid, deauth_count, interface):
        """Dispara alertas por todos los canales configurados"""
        if not self.should_alert(attacker_mac, deauth_count):
            return False
            
        severity = self.calculate_severity(deauth_count)
        timestamp = datetime.now()
        
        # Registrar esta alerta
        self.alert_history.append({
            "mac": attacker_mac,
            "count": deauth_count,
            "severity": severity,
            "timestamp": timestamp
        })
        
        # Limpiar alertas antiguas
        self.alert_history = [alert for alert in self.alert_history 
                             if (timestamp - alert["timestamp"]).total_seconds() < 3600]  # 1 hora
        
        # Construir mensaje
        subject = f"[ALERTA WiFi] Ataque de desautenticación detectado - Severidad: {severity}"
        
        message = f"""
ALERTA DE SEGURIDAD WiFi
------------------------
Tipo de ataque: Desautenticación
Severidad: {severity}
Fecha y hora: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}

Detalles:
- MAC atacante: {attacker_mac}
- MAC víctima: {victim_mac if victim_mac else 'Múltiples/Broadcast'}
- BSSID de la red: {bssid if bssid else 'Desconocido'}
- Interfaz: {interface}
- Paquetes detectados: {deauth_count}

Este tipo de ataque puede causar la desconexión de dispositivos de la red WiFi.
Se recomienda investigar la fuente del ataque y activar protección 802.11w si es posible.
"""
        
        # Enviar por todos los canales configurados
        desktop_sent = self.send_desktop_alert(subject, message) if self.config["desktop"]["enabled"] else False
        email_sent = self.send_email_alert(subject, message) if self.config["email"]["enabled"] else False
        telegram_sent = self.send_telegram_alert(message) if self.config["telegram"]["enabled"] else False
        
        logger.info(f"Alerta enviada para ataque desde {attacker_mac} (Severidad: {severity})")
        logger.info(f"Canales: Desktop={desktop_sent}, Email={email_sent}, Telegram={telegram_sent}")
        
        return True

# Uso de ejemplo
if __name__ == "__main__":
    alert_system = AlertSystem()
    alert_system.trigger_alert(
        attacker_mac="00:11:22:33:44:55",
        victim_mac="AA:BB:CC:DD:EE:FF",
        bssid="FF:EE:DD:CC:BB:AA",
        deauth_count=25,
        interface="wlan0"
    )
