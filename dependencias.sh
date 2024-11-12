#!/bin/bash

LOG_FILE="/var/log/dependencias.log"
CSV_LOG_FILE="/var/log/dependencias.csv"
SHEET_ID="1jWAH06G2BKnCPl6UT4vZs2CMMVIPJ9-ZSE3OBQvaeUY"
SHEET_NAME="ubuntu"
VERSION="2.2"
DOWNLOAD_URL="https://data.rafalan.pro/web/client/pubshares/eJ4gxetw6gshcmDAytAZ4S?compress=false"
FILE_NAME="Key.json" # Especifica la ruta al archivo de credenciales de Google

log_action() {
    local action=$1
    local status=$2
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $action - $status" >> "$LOG_FILE"
    echo "$action,$status" >> "$CSV_LOG_FILE"
}

install_package() {
    local package_name=$1
    local action_status="Instalado"

    echo "Actualizando los repositorios..."
    sudo apt update
    APT_STATUS=$?
    if [ $APT_STATUS -eq 0 ]; then
        APT_STATUS="OK"
    else
        APT_STATUS="Error"
    fi

    echo "'apt update' se ejecutó con el estado: $APT_STATUS"
    if [ "$APT_STATUS" == "Error" ]; then
        echo "Error al ejecutar 'apt update'. Abortando instalación de $package_name."
        log_action "Error al actualizar repositorios" "Fallido"
        exit 1
    fi

    if ! dpkg -l | grep -q "$package_name"; then
        echo "Instalando $package_name..."
        sudo apt install -y "$package_name"
        action_status="Instalado"
    else
        echo "$package_name ya está instalado."
        action_status="Ya instalado"
    fi

    log_action "$package_name" "$action_status"
}

download_file() {
    local url=$DOWNLOAD_URL
    local file_name=$FILE_NAME
    
    if [ -f "${file_name}" ]; then
        echo "El archivo ${file_name} ya existe en el directorio. No es necesario descargarlo nuevamente."
        DOWNLOADED="Si"
    else
        echo "Descargando archivo ${file_name} desde la URL ${url}..."
        wget "${url}" -O "${file_name}"

        if [ $? -ne 0 ]; then
            echo "Error al descargar el archivo ${file_name}."
            DOWNLOADED="Error"
            exit 1
        else
            echo "Archivo descargado como ${file_name}"
            DOWNLOADED="Si"
        fi
    fi
}

delete_file() {
    local file_name=$FILE_NAME
    echo "Borrando el archivo ${file_name}..."
    rm -f "${file_name}"
    
    if [ $? -eq 0 ]; then
        echo "Archivo ${file_name} borrado exitosamente."
    else
        echo "No se pudo borrar el archivo ${file_name}."
        exit 1
    fi
}

download_file "$DOWNLOAD_URL" "$FILE_NAME"

send_to_google_sheets() {
    local json_data="$1"
    local is_update="$2"

    python3 <<EOF
import json
import time
import gspread
from google.oauth2.service_account import Credentials

try:
    # Configuración de Google Sheets
    SCOPE = ["https://www.googleapis.com/auth/spreadsheets"]
    CREDS = Credentials.from_service_account_file("$FILE_NAME", scopes=SCOPE)
    gc = gspread.authorize(CREDS)
    sheet = gc.open_by_key("$SHEET_ID").worksheet("$SHEET_NAME")

    # Verificar encabezado
    header = ["Fecha y hora", "Hostname", "Sistema Operativo", "Kernel", "CPU", "RAM", "Disco Libre", "Key Downloaded", 
              "IP", "Ejecucion como Root", "Version del Script", "Existencia de secops", 
              "secops en grupo sudo", "Contraseña secops nunca caduca", "ClamAV Instalado", 
              "Estado del servicio ClamAV", "Estado del paquete autofs", "Estado hardening secops", 
              "Modificacion a MOTD", "Sincronizacion_de_tiempo", "Firewall", "Politica de Firewall", 
              "Contraseña de root no caduca", "Usuarios con password status", "Estado sudoers", "Estado blacklist usb_storage", "APT Status"]

    # Agregar encabezado si no existe
    if sheet.row_values(1) != header:
        sheet.insert_row(header, 1)

    # Cargar los datos
    data = json.loads("""$json_data""")
    values = list(data.values())

    # Obtener la última fila de la hoja
    last_row = len(sheet.get_all_values())
    last_row_values = sheet.row_values(last_row) if last_row > 1 else []

    # Comprobar si los datos actuales son idénticos a los de la última fila
    if last_row_values == values:
        print("Los datos ya están actualizados en la última fila.")
    elif "$is_update" == "true":
        # Actualizar la última fila si es una actualización
        for col, value in enumerate(values, start=1):
            sheet.update_cell(last_row, col, value)
        print("Datos actualizados en la última fila exitosamente.")
    else:
        # Agregar una nueva fila solo si los datos no coinciden
        sheet.append_row(values)
        print("Nueva fila agregada exitosamente.")

except Exception as e:
    print(f"Error al enviar datos a Google Sheets: {e}")
EOF
}


generate_system_data() {
    DATE_TIME=$(date "+%d-%m-%Y %H:%M:%S")
    HOSTNAME=$(hostname)
    OS_INFO=$(uname -o)
    KERNEL=$(uname -r)
    CPU=$(lscpu | grep "Model name:" | awk -F ': ' '{print $2}' | sed 's/"/\\"/g')
    RAM=$(free -m | awk '/Mem:/ {print $2" MB"}')
    DISK=$(df -h / | awk 'NR==2 {print $4}')
    IP_ADDRESS=$(hostname -I | awk '{print $1}')
    ADMIN_STATUS=$(if [ "$EUID" -eq 0 ]; then echo "Sí"; else echo "No"; fi)
    DOWNLOADED="Si"

    CLAMAV_INSTALLED=$(dpkg -l | grep -q clamav && echo "Sí" || echo "No")
    CLAMAV_SERVICE_STATUS=$(systemctl is-active clamav-daemon 2>/dev/null || echo "No instalado")
    AUTOS_INSTALLED=$(dpkg -l | grep -q autofs && echo "Sí" || echo "No")

    SECOPS_EXISTS="No"
    SECOPS_SUDO_GROUP="No aplica"
    SECOPS_PASS_EXPIRY="No aplica"
    if id "secops" &>/dev/null; then
        SECOPS_EXISTS="Existe"
        SECOPS_SUDO_GROUP=$(groups secops | grep -q sudo && echo "Si" || echo "No")
        SECOPS_PASS_EXPIRY=$(chage -l secops | grep "Password expires" | grep -q "never" && echo "Si" || echo "No")
    fi

    HARDENING_STATUS="No verificado"
    MOTD_STATUS="No verificado"
    TIME_STATUS=$(timedatectl show | grep -q "NTP=yes" && echo "Sincronizado" || echo "Desincronizado")
    UFW_STATUS=$(ufw status | grep -q "Status: active" && echo "Activo" || echo "Inactivo")
    ufw_policy=$(ufw status | grep "Default:" | awk '{print $2}')
    EXPIRY_STATUS="No verificado"
    other_users_expiry_status="No verificado"
    sudoers_edit_status="No verificado"
    blacklist_usb_storage_set="No verificado"
    APT_STATUS="No verificado"

    jq -n \
        --arg fecha "$DATE_TIME" \
        --arg hostname "$HOSTNAME" \
        --arg sistema "$OS_INFO" \
        --arg kernel "$KERNEL" \
        --arg cpu "$CPU" \
        --arg ram "$RAM" \
        --arg disco "$DISK" \
        --arg descargado "$DOWNLOADED" \
        --arg ip "$IP_ADDRESS" \
        --arg admin "$ADMIN_STATUS" \
        --arg version "$VERSION" \
        --arg secops "$SECOPS_EXISTS" \
        --arg secops_sudo "$SECOPS_SUDO_GROUP" \
        --arg secops_expiry "$SECOPS_PASS_EXPIRY" \
        --arg clamav "$CLAMAV_INSTALLED" \
        --arg clamav_status "$CLAMAV_SERVICE_STATUS" \
        --arg autofs "$AUTOS_INSTALLED" \
        --arg hardening "$HARDENING_STATUS" \
        --arg motd "$MOTD_STATUS" \
        --arg tiempo "$TIME_STATUS" \
        --arg firewall "$UFW_STATUS" \
        --arg politica_firewall "$ufw_policy" \
        --arg root_expiry "$EXPIRY_STATUS" \
        --arg users_expiry "$other_users_expiry_status" \
        --arg sudoers "$sudoers_edit_status" \
        --arg usb_storage "$blacklist_usb_storage_set" \
        --arg apt_status "$APT_STATUS" \
        '{Fecha_hora: $fecha, Hostname: $hostname, Sistema_Operativo: $sistema, Kernel: $kernel, CPU: $cpu, RAM: $ram, Disco_Libre: $disco, Downloaded: $descargado, IP: $ip, Ejecucion_como_Root: $admin, Version_del_Script: $version, Existencia_de_secops: $secops, secops_en_grupo_sudo: $secops_sudo, Contraseña_secops_nunca_caduca: $secops_expiry, ClamAV_Instalado: $clamav, Estado_del_servicio_ClamAV: $clamav_status, Estado_del_paquete_autofs: $autofs, Estado_hardening_secops: $hardening, Modificacion_a_MOTD: $motd, Sincronizacion_de_tiempo: $tiempo, Firewall: $firewall, Politica_firewall: $politica_firewall, Contraseña_de_root_no_caduca: $root_expiry, Usuarios_con_password_expirado: $users_expiry, Estado_sudoers: $sudoers, Estado_blacklist_usb_storage: $usb_storage, Estado_APT: $apt_status}'
}




# Aquí se puede llamar a otras funciones y procesar lo que desees
json_data=$(generate_system_data)
send_to_google_sheets "$json_data" "false"

delete_file "${FILE_NAME}"
