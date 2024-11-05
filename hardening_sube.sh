#!/bin/bash

# Variables
LOG_FILE="/var/log/hardening.log"
SHEET_ID="1jWAH06G2BKnCPl6UT4vZs2CMMVIPJ9-ZSE3OBQvaeUY"
SHEET_NAME="ubuntu"
VERSION="1.0"

# Función para verificar e instalar paquetes
install_package() {
    if ! dpkg -l | grep -q "$1"; then
        echo "Instalando $1..."
        sudo apt update && sudo apt install -y "$1"
        echo "$1 instalado correctamente."
    else
        echo "$1 ya está instalado."
    fi
}

# Instalar dependencias necesarias
install_package "python3-pip"
install_package "clamav"
install_package "autofs"

# Instalar dependencias de Python solo si faltan
if ! pip3 show gspread &>/dev/null || ! pip3 show google-auth &>/dev/null; then
    echo "Instalando gspread y google-auth..."
    pip3 install gspread google-auth
fi

if ! pip3 show psutil &>/dev/null; then
    echo "Instalando psutil..."
    pip3 install psutil
fi

# Recopilar información del sistema
HOSTNAME=$(hostname)
OS_INFO=$(uname -o)
KERNEL=$(uname -r)
CPU=$(lscpu | grep "Model name:" | awk -F ': ' '{print $2}')
RAM=$(free -m | awk '/Mem:/ {print $2" MB"}')
DISK=$(df -h / | awk 'NR==2 {print $4}')
IP_ADDRESS=$(hostname -I | awk '{print $1}')

# Verificaciones de seguridad
PERMISSIONS_STATUS=$(if [ -x "$0" ]; then echo "OK"; else echo "No tiene"; fi)
ADMIN_STATUS=$(if [ "$EUID" -ne 0 ]; then echo "No"; else echo "Sí"; fi)
SECOPS_EXISTS=$(if id "secops" &>/dev/null; then echo "Existe"; else echo "No existe"; fi)
SECOPS_SUDO_GROUP=$(if id -nG "secops" | grep -qw "sudo"; then echo "Sí"; else echo "No"; fi)
SECOPS_PASS_EXPIRY=$(chage -l secops 2>/dev/null | grep "never" &>/dev/null && echo "Nunca caduca" || echo "Caduca")
NVME_STATUS=$(lsblk -d -o rota | grep -q "0" && echo "Sí" || echo "No")
CLAMAV_INSTALLED=$(dpkg -l | grep -q clamav && echo "Instalado" || echo "No instalado")
CLAMAV_SERVICE_STATUS=$(systemctl is-active clamav-freshclam 2>/dev/null || echo "Error")
GRUB_PERMISSIONS=$(ls -l /boot/grub/grub.cfg | awk '{print $3" "$4}')

# Crear un archivo temporal con los datos
DATA_FILE="/tmp/hardening_data.json"
cat <<EOF > $DATA_FILE
{
    "Hostname": "$HOSTNAME",
    "Sistema_Operativo": "$OS_INFO",
    "Kernel": "$KERNEL",
    "CPU": "$CPU",
    "RAM": "$RAM",
    "Disco_Libre": "$DISK",
    "IP": "$IP_ADDRESS",
    "Permisos_de_Ejecucion": "$PERMISSIONS_STATUS",
    "Ejecucion_como_Root": "$ADMIN_STATUS",
    "Version_del_Script": "$VERSION",
    "Existencia_de_secops": "$SECOPS_EXISTS",
    "secops_en_grupo_sudo": "$SECOPS_SUDO_GROUP",
    "Contraseña_secops_nunca_caduca": "$SECOPS_PASS_EXPIRY",
    "Verificacion_NVMe": "$NVME_STATUS",
    "ClamAV_Instalado": "$CLAMAV_INSTALLED",
    "Estado_del_servicio_ClamAV": "$CLAMAV_SERVICE_STATUS",
    "Permisos_de_grub.cfg": "$GRUB_PERMISSIONS"
}
EOF

# Llamar al script de Python para subir los datos a Google Sheets
python3 <<EOF
import json
import gspread
from google.oauth2.service_account import Credentials

# Configuración de Google Sheets
SCOPE = ["https://www.googleapis.com/auth/spreadsheets"]
CREDS = Credentials.from_service_account_file("Key.json", scopes=SCOPE)
CLIENT = gspread.authorize(CREDS)
SHEET_ID = "$SHEET_ID"
SHEET_NAME = "$SHEET_NAME"

# Cargar datos desde el archivo JSON
with open("$DATA_FILE", "r") as f:
    data = json.load(f)

# Abrir la hoja de cálculo y seleccionar la hoja específica
sheet = CLIENT.open_by_key(SHEET_ID).worksheet(SHEET_NAME)

# Verificar si ya existe un encabezado
header = list(data.keys())
header_exists = len(sheet.row_values(1)) > 0

# Si el encabezado no existe, añadirlo
if not header_exists:
    sheet.append_row(header, value_input_option="USER_ENTERED")

# Añadir datos en la siguiente fila vacía
values = list(data.values())
sheet.append_row(values, value_input_option="USER_ENTERED")

print("Datos subidos con éxito a Google Sheets")
EOF

# Limpiar el archivo temporal
rm -f "$DATA_FILE"
