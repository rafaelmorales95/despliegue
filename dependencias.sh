#!/bin/bash


LOG_FILE="/var/log/hardening.log"
CSV_LOG_FILE="/var/log/hardening_log.csv"
SHEET_ID="1jWAH06G2BKnCPl6UT4vZs2CMMVIPJ9-ZSE3OBQvaeUY"
SHEET_NAME="test"
VERSION="2.2"
DOWNLOAD_URL="https://data.rafalan.pro/web/client/pubshares/eJ4gxetw6gshcmDAytAZ4S?compress=false"
FILE_NAME="Key.json"

send_to_google_sheets() {
    local json_data="$1"
    local is_update="$2"

    python3 <<EOF
import json
import time
import gspread
from google.oauth2.service_account import Credentials

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

# Si no existe el encabezado, agregarlo en la primera fila
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
    # Si es actualización, modifica la última fila
    for col, value in enumerate(values, start=1):
        sheet.update_cell(last_row, col, value)
    print("Datos actualizados en la última fila exitosamente.")
else:
    # Agregar una nueva fila solo si los datos no coinciden
    sheet.append_row(values)
    print("Nueva fila agregada exitosamente.")

time.sleep(5)
EOF
}

generate_system_data() {
    DATE_TIME=$(date "+%d-%m-%Y %H:%M:%S")
    HOSTNAME=$(hostname)
    OS_INFO=$(uname -o)
    KERNEL=$(uname -r)
    CPU=$(lscpu | grep "Model name:" | awk -F ': ' '{print $2}')
    RAM=$(free -m | awk '/Mem:/ {print $2" MB"}')
    DISK=$(df -h / | awk 'NR==2 {print $4}')
    IP_ADDRESS=$(hostname -I | awk '{print $1}')
    ADMIN_STATUS=$(if [ "$EUID" -eq 0 ]; then echo "Sí"; else echo "No"; fi)

    # Secops data (si no existe el usuario, se marca como "No Aplica")
    if id "secops" &>/dev/null; then
        SECOPS_EXISTS="Existe"
        SECOPS_SUDO_GROUP=$(groups secops | grep -q sudo && echo "Si" || echo "No")
        SECOPS_PASS_EXPIRY=$(chage -l secops | grep "Password expires" | grep -q "never" && echo "Si" || echo "No")
    else
        SECOPS_EXISTS="No"
        SECOPS_SUDO_GROUP="No aplica"
        SECOPS_PASS_EXPIRY="No aplica"
    fi

    # Generando el reporte como JSON
    cat <<EOF
{
    "Fecha_hora": "$DATE_TIME",
    "Hostname": "$HOSTNAME",
    "Sistema_Operativo": "$OS_INFO",
    "Kernel": "$KERNEL",
    "CPU": "$CPU",
    "RAM": "$RAM",
    "Disco_Libre": "$DISK",
    "Downloaded": "No",
    "IP": "$IP_ADDRESS",
    "Ejecucion_como_Root": "$ADMIN_STATUS",
    "Version_del_Script": "$VERSION",
    "Existencia_de_secops": "$SECOPS_EXISTS",
    "secops_en_grupo_sudo": "$SECOPS_SUDO_GROUP",
    "Contraseña_secops_nunca_caduca": "$SECOPS_PASS_EXPIRY",
    "ClamAV_Instalado": "No Revisado",
    "Estado_del_servicio_ClamAV": "No Revisado",
    "Estado_del_paquete_autofs": "No Revisado",
    "Estado_hardening_secops": "No Revisado",
    "Modificacion_a_MOTD": "No Revisado",
    "Sincronizacion_de_tiempo": "No Revisado",
    "Firewall": "No Revisado",
    "Politica_firewall": "No Revisado",
    "Contraseña_de_root_no_caduca": "No Revisado",
    "Usuarios_con_password_expirado": "No Revisado",
    "Estado_sudoers": "No Revisado",
    "Estado_blacklist_usb_storage": "No Revisado",
    "Estado_APT": "No Revisado"
}
EOF
}

download_file() {
    local url=$1
    local file_name=$2
    
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

download_file "$DOWNLOAD_URL" "$FILE_NAME"

# Generar los datos del sistema y enviarlos a Google Sheets
json_data=$(generate_system_data)
send_to_google_sheets "$json_data" "false"
