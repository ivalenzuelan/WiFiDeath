#!/bin/bash
# Script para configurar Management Frame Protection (MFP) en redes WiFi

# Colores para mensajes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para mostrar mensajes
log_msg() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar si se ejecuta como root
if [ "$EUID" -ne 0 ]; then
    log_error "Este script debe ejecutarse como root. Ejecute: sudo $0"
    exit 1
fi

# Verificar dependencias
check_dependencies() {
    local missing_deps=0
    
    log_msg "Verificando dependencias..."
    
    # Verificar iw
    if ! command -v iw &> /dev/null; then
        log_error "El paquete 'iw' no está instalado. Instálelo con 'apt install iw' o el gestor de paquetes correspondiente."
        missing_deps=1
    fi
    
    # Verificar hostapd (si se va a configurar un AP)
    if ! command -v hostapd &> /dev/null; then
        log_warn "El paquete 'hostapd' no está instalado. No se podrá configurar un punto de acceso."
    fi
    
    # Verificar wpa_supplicant (para clientes)
    if ! command -v wpa_supplicant &> /dev/null; then
        log_warn "El paquete 'wpa_supplicant' no está instalado. No se podrá configurar un cliente."
    fi
    
    if [ $missing_deps -eq 1 ]; then
        log_error "Faltan dependencias. Por favor, instale los paquetes necesarios."
        exit 1
    fi
    
    log_success "Todas las dependencias principales están instaladas."
}

# Detectar interfaces WiFi disponibles
detect_wifi_interfaces() {
    log_msg "Detectando interfaces WiFi..."
    
    local interfaces=$(iw dev | grep Interface | awk '{print $2}')
    
    if [ -z "$interfaces" ]; then
        log_error "No se detectaron interfaces WiFi."
        exit 1
    fi
    
    log_success "Interfaces WiFi detectadas:"
    
    local count=1
    for iface in $interfaces; do
        echo "  $count) $iface"
        count=$((count + 1))
    done
    
    return 0
}

# Configurar MFP en hostapd (punto de acceso)
configure_ap_mpf() {
    local interface=$1
    local config_file="/etc/hostapd/hostapd.conf"
    
    log_msg "Configurando MFP en punto de acceso ($interface)..."
    
    # Verificar si existe el archivo de configuración
    if [ ! -f "$config_file" ]; then
        log_error "No se encontró el archivo de configuración de hostapd ($config_file)"
        log_msg "Creando un archivo de configuración básico..."
        
        # Solicitar información básica
        read -p "Ingrese el nombre de la red (SSID): " ssid
        read -p "Ingrese la contraseña de la red (mínimo 8 caracteres): " password
        
        # Verificar longitud de contraseña
        if [ ${#password} -lt 8 ]; then
            log_error "La contraseña debe tener al menos 8 caracteres."
            exit 1
        fi
        
        # Crear archivo de configuración
        cat > "$config_file" << EOF
interface=$interface
driver=nl80211
ssid=$ssid
hw_mode=g
channel=6
wmm_enabled=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=$password

# Configuración MFP
ieee80211w=2
EOF

        log_success "Archivo de configuración creado con MFP obligatorio."
    else
        # Verificar si ya existe configuración MFP
        if grep -q "ieee80211w" "$config_file"; then
            log_warn "Ya existe configuración MFP en el archivo."
            
            # Actualizar configuración MFP
            read -p "¿Desea actualizar la configuración MFP? (s/n): " update_mpf
            if [ "$update_mpf" == "s" ] || [ "$update_mpf" == "S" ]; then
                read -p "Nivel de MFP (0=desactivado, 1=opcional, 2=obligatorio): " mpf_level
                
                # Validar nivel MFP
                if [ "$mpf_level" != "0" ] && [ "$mpf_level" != "1" ] && [ "$mpf_level" != "2" ]; then
                    log_error "Nivel MFP inválido. Debe ser 0, 1 o 2."
                    exit 1
                fi
                
                # Actualizar configuración
                sed -i "s/ieee80211w=.*/ieee80211w=$mpf_level/" "$config_file"
                log_success "Configuración MFP actualizada a nivel $mpf_level."
            fi
        else
            # Añadir configuración MFP
            read -p "¿Activar MFP obligatorio (2), opcional (1) o desactivado (0)? " mpf_level
            
            # Validar nivel MFP
            if [ "$mpf_level" != "0" ] && [ "$mpf_level" != "1" ] && [ "$mpf_level" != "2" ]; then
                log_error "Nivel MFP inválido. Debe ser 0, 1 o 2."
                exit 1
            fi
            
            # Añadir configuración
            echo -e "\n# Configuración MFP" >> "$config_file"
            echo "ieee80211w=$mpf_level" >> "$config_file"
            
            log_success "Configuración MFP añadida al archivo (nivel $mpf_level)."
        fi
    fi
    
    # Reiniciar servicio hostapd
    log_msg "Reiniciando servicio hostapd..."
    systemctl restart hostapd
    
    if [ $? -eq 0 ]; then
        log_success "Servicio hostapd reiniciado correctamente."
    else
        log_error "Error al reiniciar el servicio hostapd."
        log_msg "Verificar la configuración con: hostapd -dd $config_file"
    fi
}

# Configurar MFP en wpa_supplicant (cliente)
configure_client_mpf() {
    local interface=$1
    local config_file="/etc/wpa_supplicant/wpa_supplicant.conf"
    
    log_msg "Configurando MFP en cliente WiFi ($interface)..."
    
    # Verificar si existe el archivo de configuración
    if [ ! -f "$config_file" ]; then
        log_error "No se encontró el archivo de configuración de wpa_supplicant ($config_file)"
        log_msg "Creando un archivo de configuración básico..."
        
        # Crear archivo base
        cat > "$config_file" << EOF
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=ES
EOF
        
        log_success "Archivo de configuración básico creado."
    fi
    
    # Solicitar información de la red
    log_msg "Configurando red con soporte MFP..."
    read -p "Ingrese el nombre de la red (SSID): " ssid
    read -p "Ingrese la contraseña de la red: " password
    read -p "Nivel MFP (0=desactivado, 1=opcional, 2=obligatorio): " mpf_level
    
    # Validar nivel MFP
    if [ "$mpf_level" != "0" ] && [ "$mpf_level" != "1" ] && [ "$mpf_level" != "2" ]; then
        log_error "Nivel MFP inválido. Debe ser 0, 1 o 2."
        exit 1
    fi
    
    # Generar configuración de red con MFP
    log_msg "Generando configuración de red con MFP nivel $mpf_level..."
    
    # Usar wpa_passphrase para generar configuración base
    network_config=$(wpa_passphrase "$ssid" "$password")
    
    # Añadir configuración MFP
    network_config="${network_config}\n\tieee80211w=$mpf_level"
    
    # Agregar la red al archivo de configuración
    echo -e "$network_config" >> "$config_file"
    
    log_success "Red configurada con soporte MFP."
    
    # Reiniciar wpa_supplicant para aplicar cambios
    log_msg "Reiniciando wpa_supplicant en la interfaz $interface..."
    wpa_cli -i "$interface" reconfigure
    
    log_success "Configuración aplicada. Puede verificar la conexión con: wpa_cli -i $interface status"
}

# Verificar soporte de MFP en hardware
check_mpf_support() {
    local interface=$1
    
    log_msg "Verificando soporte de MFP en la interfaz $interface..."
    
    # Obtener capacidades
    local capabilities=$(iw phy phy0 info | grep "Extended capabilities")
    
    if echo "$capabilities" | grep -q "Protected Management Frames"; then
        log_success "La interfaz $interface soporta Protected Management Frames (PMF/MFP)."
        return 0
    else
        log_warn "La interfaz $interface puede no soportar Protected Management Frames (PMF/MFP)."
        log_warn "Algunos dispositivos con drivers antiguos podrían no reportar correctamente esta capacidad."
        return 1
    fi
}

# Verificar MFP en redes disponibles
scan_for_mpf_networks() {
    local interface=$1
    
    log_msg "Escaneando redes WiFi con soporte MFP en la interfaz $interface..."
    
    # Poner interfaz en modo up si no lo está
    ip link set "$interface" up
    
    # Escanear redes
    log_msg "Iniciando escaneo (puede tardar unos segundos)..."
    iw dev "$interface" scan | grep -E 'SSID:|RSN:|Management frame protection' > /tmp/wifi_scan.txt
    
    # Procesar resultados
    log_success "Redes con información de MFP encontradas:"
    echo "===========================================" 
    echo "SSID                  | MFP Status"
    echo "-------------------------------------------"
    
    local current_ssid=""
    while IFS= read -r line; do
        if [[ $line == *"SSID: "* ]]; then
            current_ssid=$(echo "$line" | sed 's/.*SSID: //')
        elif [[ $line == *"Management frame protection"* ]]; then
            local mpf_status=$(echo "$line" | sed 's/.*Management frame protection: //')
            echo "$current_ssid                  | $mpf_status"
        fi
    done < /tmp/wifi_scan.txt
    
    echo "===========================================" 
    log_msg "Nota: 'required' significa que MFP es obligatorio, 'optional' que es compatible pero no obligatorio."
    
    # Limpiar
    rm -f /tmp/wifi_scan.txt
}

# Menú principal
main_menu() {
    clear
    echo "===================================================="
    echo "  Configuración de Management Frame Protection (MFP)"
    echo "===================================================="
    echo ""
    echo "Este script ayuda a configurar la protección contra ataques"
    echo "de desautenticación mediante 802.11w (MFP/PMF)."
    echo ""
    echo "Opciones:"
    echo "  1) Verificar dependencias"
    echo "  2) Detectar interfaces WiFi"
    echo "  3) Verificar soporte de MFP en hardware"
    echo "  4) Escanear redes con soporte MFP"
    echo "  5) Configurar MFP en punto de acceso (hostapd)"
    echo "  6) Configurar MFP en cliente WiFi (wpa_supplicant)"
    echo "  7) Salir"
    echo ""
    read -p "Seleccione una opción: " option
    
    case $option in
        1)
            check_dependencies
            ;;
        2)
            detect_wifi_interfaces
            ;;
        3)
            detect_wifi_interfaces
            read -p "Seleccione una interfaz: " iface_number
            local interfaces=($(iw dev | grep Interface | awk '{print $2}'))
            local selected_iface=${interfaces[$((iface_number-1))]}
            check_mpf_support "$selected_iface"
            ;;
        4)
            detect_wifi_interfaces
            read -p "Seleccione una interfaz para escanear: " iface_number
            local interfaces=($(iw dev | grep Interface | awk '{print $2}'))
            local selected_iface=${interfaces[$((iface_number-1))]}
            scan_for_mpf_networks "$selected_iface"
            ;;
        5)
            detect_wifi_interfaces
            read -p "Seleccione una interfaz para el punto de acceso: " iface_number
            local interfaces=($(iw dev | grep Interface | awk '{print $2}'))
            local selected_iface=${interfaces[$((iface_number-1))]}
            configure_ap_mpf "$selected_iface"
            ;;
        6)
            detect_wifi_interfaces
            read -p "Seleccione una interfaz para el cliente: " iface_number
            local interfaces=($(iw dev | grep Interface | awk '{print $2}'))
            local selected_iface=${interfaces[$((iface_number-1))]}
            configure_client_mpf "$selected_iface"
            ;;
        7)
            log_msg "Saliendo..."
            exit 0
            ;;
        *)
            log_error "Opción inválida."
            ;;
    esac
    
    echo ""
    read -p "Presione Enter para continuar..."
    main_menu
}

# Iniciar script
main_menu
