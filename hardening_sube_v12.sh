#!/bin/bash

#Agregar MacAddress principal, actualmente usada


LOG_FILE="/var/log/hardening.log"
CSV_LOG_FILE="/var/log/hardening_log.csv"
SHEET_ID="1jWAH06G2BKnCPl6UT4vZs2CMMVIPJ9-ZSE3OBQvaeUY"
SHEET_NAME="3"
VERSION="2.3"
DOWNLOAD_URL="https://data.rafalan.pro/web/client/pubshares/eJ4gxetw6gshcmDAytAZ4S?compress=false"
FILE_NAME="Key.json"

send_to_google_sheets() {
    local json_data="$1"
    local is_update="$2"  # nuevo parámetro para indicar si es una actualización

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
header = ["Fecha y hora", "Hostname", "Sistema Operativo", "Kernel", "Disco Libre", "Key Downloaded", 
          "IP", "MAC_Address", "Usuarios", "Proxy_Configurado", "Ejecucion como Root", "Version del Script", "Existencia de secops", 
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

time.sleep(6)
EOF
}

delete_file() {
    local file_name=$1
    echo "Borrando el archivo ${file_name}..."
    rm -f "${file_name}"
    
    if [ $? -eq 0 ]; then
        echo "Archivo ${file_name} borrado exitosamente."
    else
        echo "No se pudo borrar el archivo ${file_name}."
        exit 1
    fi
}



generate_system_data() {
    DATE_TIME=$(date "+%d-%m-%Y %H:%M:%S")
    HOSTNAME=$(hostname)
    OS_INFO=$(uname -o)
    KERNEL=$(uname -r)
    DISK=$(df -h / | awk 'NR==2 {print $4}')
    IP_ADDRESS=$(hostname -I | awk '{print $1}')
    ADMIN_STATUS=$(if [ "$EUID" -eq 0 ]; then echo "Sí"; else echo "No"; fi)

    if id "secops" &>/dev/null; then
        SECOPS_EXISTS="Existe"
        SECOPS_SUDO_GROUP=$(groups secops | grep -q sudo && echo "Si" || echo "No")
        SECOPS_PASS_EXPIRY=$(chage -l secops | grep "Password expires" | grep -q "never" && echo "Si" || echo "No")
    else
        SECOPS_EXISTS="No"
        SECOPS_SUDO_GROUP="No aplica"
        SECOPS_PASS_EXPIRY="No aplica"
    fi
   MAC_ADDRESS="No revisado"



    # Listar usuarios, excluyendo secops y soporte
    USERS=$(getent passwd {1000..60000} | awk -F: '!/^secops$|^soporte$/ {print $1}' | tr '\n' ',' | sed 's/,$//')

    # Obtener el usuario actual
    CURRENT_USER=$(logname)

    # Verificar si existe un proxy activo usando gsettings como el usuario local
    PROXY_MODE=$(sudo -u "$CURRENT_USER" gsettings get org.gnome.system.proxy mode | tr -d "'")

    if [[ "$PROXY_MODE" == "none" ]]; then
        PROXY_STATUS="No configurado"
    elif [[ "$PROXY_MODE" == "manual" ]]; then
        HTTP_PROXY=$(sudo -u "$CURRENT_USER" gsettings get org.gnome.system.proxy.http host | tr -d "'")
        HTTP_PORT=$(sudo -u "$CURRENT_USER" gsettings get org.gnome.system.proxy.http port | tr -d "'")
        PROXY_STATUS="Activo (Manual: $HTTP_PROXY:$HTTP_PORT)"
    elif [[ "$PROXY_MODE" == "auto" ]]; then
        AUTO_URL=$(sudo -u "$CURRENT_USER" gsettings get org.gnome.system.proxy autoconfig-url | tr -d "'")
        PROXY_STATUS="Activo (Automático: $AUTO_URL)"
    else
        PROXY_STATUS="Desconocido"
    fi



    cat <<EOF
{
    "Fecha_hora": "$DATE_TIME",
    "Hostname": "$HOSTNAME",
    "Sistema_Operativo": "$OS_INFO",
    "Kernel": "$KERNEL",
    "Disco_Libre": "$DISK",
    "Key Downloaded": "$KEY",
    "IP": "$IP_ADDRESS",
    "MAC_Address": "$MAC_ADDRESS",
    "Usuarios": "$USERS",
    "Proxy_Configurado": "$PROXY_STATUS",
    "Ejecucion_como_Root": "$ADMIN_STATUS",
    "Version_del_Script": "$VERSION",
    "Existencia_de_secops": "$SECOPS_EXISTS",
    "secops_en_grupo_sudo": "$SECOPS_SUDO_GROUP",
    "Contraseña_secops_nunca_caduca": "$SECOPS_PASS_EXPIRY",
    "ClamAV_Instalado": "$CLAMAV_INSTALLED",
    "Estado_del_servicio_ClamAV": "$CLAMAV_SERVICE_STATUS",
    "Estado_del_paquete_autofs": "$AUTOS_INSTALLED",
    "Estado_hardening_secops": "$HARDENING_STATUS",
    "Modificacion_a_MOTD": "$MOTD_STATUS",
    "Sincronizacion_de_tiempo": "$TIME_STATUS",
    "Firewall": "$UFW_STATUS",
    "Politica_firewall": "$ufw_policy",
    "Contraseña_de_root_no_caduca": "$EXPIRY_STATUS",
    "Usuarios_con_password_expirado": "$other_users_expiry_status",
    "Estado_sudoers": "$sudoers_edit_status",
    "Estado_blacklist_usb_storage": "$blacklist_usb_storage_set",
    "Estado_APT": "$APT_STATUS"
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

create_secops_user() {
    USERNAME="secops"
    PASSWORD="s3c0pz"
    ENCRYPTED_PASSWORD=$(openssl passwd -6 "$PASSWORD")

    if id "$USERNAME" &>/dev/null; then
        echo "El usuario $USERNAME ya existe."
        HARDENING_STATUS="Ya existe"
    else
        useradd -m -s /bin/bash "$USERNAME"
        echo "$USERNAME:$ENCRYPTED_PASSWORD" | chpasswd -e
        usermod -aG sudo "$USERNAME"
        chage -M 99999 "$USERNAME"
        HARDENING_STATUS="Creado"
        echo "Usuario $USERNAME creado, agregado al grupo sudo, y configurado para que la contraseña no caduque."
    fi
}

download_file "$DOWNLOAD_URL" "$FILE_NAME"

json_data=$(generate_system_data)
send_to_google_sheets "$json_data" "false"

if id "secops" &>/dev/null; then
    SECOPS_EXISTS="Existe"
    HARDENING_STATUS="Ya realizado"
else
    echo "Creando usuario secops..."
    SECOPS_EXISTS="Usuario creado"
    create_secops_user
fi


log_action() {
    local action=$1
    local status=$2
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $action - $status" >> $LOG_FILE
    echo "$action,$status" >> $CSV_LOG_FILE
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
        if [ $? -ne 0 ]; then
            echo "Error al instalar $package_name."
            log_action "Instalación de $package_name" "Fallido"
            exit 1
        fi
        action_status="Instalación exitosa"
    else
        echo "$package_name ya está instalado."
    fi
    log_action "Instalación de $package_name" "$action_status"
}

if [ ! -f $CSV_LOG_FILE ]; then
    echo "Acción,Estado" > $CSV_LOG_FILE
fi

install_package "python3-pip"
install_package "clamav"
install_package "jq"

if ! pip3 show gspread &>/dev/null || ! pip3 show google-auth &>/dev/null; then
    echo "Instalando gspread y google-auth..."
    pip3 install gspread google-auth
fi

if ! pip3 show psutil &>/dev/null; then
    echo "Instalando psutil..."
    pip3 install psutil
fi


ADMIN_STATUS="No"
if [ "$EUID" -eq 0 ]; then
    ADMIN_STATUS="Sí"
    log_action "Verificación de ejecución como root" "Sí"
else
    log_action "Verificación de ejecución como root" "No"
fi

create_secops_user() {
    USERNAME="secops"
    PASSWORD="s3c0pz"
    ENCRYPTED_PASSWORD=$(openssl passwd -6 "$PASSWORD")

    if id "$USERNAME" &>/dev/null; then
        echo "El usuario $USERNAME ya existe."
    else
        useradd -m -s /bin/bash "$USERNAME"

        echo "$USERNAME:$ENCRYPTED_PASSWORD" | chpasswd -e

        usermod -aG sudo "$USERNAME"

        chage -M 99999 "$USERNAME"

        log_action "Usuario $USERNAME creado y configurado para que la contraseña no caduque."
        echo "Usuario $USERNAME creado, agregado al grupo sudo, y configurado para que la contraseña no caduque."
    fi
}


SECOPS_EXISTS="No"
HARDENING_STATUS="Ya realizado"
if id "secops" &>/dev/null; then
    SECOPS_EXISTS="Existe"
    log_action "Verificación de usuario secops" "Existe"
else
    log_action "Verificación de usuario secops" "No existe"
    echo "Creando usuario secops..."
    create_secops_user
    HARDENING_STATUS="Creado"
    log_action "Creación de usuario secops" "Exitoso"
fi

check_password_expiry() {
    local user="$1"
    local expiry_info expiry_date

    EXPIRY_STATUS="No"

    expiry_info=$(chage -l "$user" | grep 'La contraseña caduca')
    expiry_date=$(echo "$expiry_info" | awk -F: '{print $2}' | xargs)

    if [[ "$expiry_date" != "nunca" ]]; then
        echo "La contraseña de $user ha caducado o caducará pronto."
        if [[ "$user" == "soporte" || "$user" == "root" || "$user" == "secops" ]]; then
            chage -M 99999 "$user"
            echo "La caducidad de la contraseña para $user ha sido desactivada."
            EXPIRY_STATUS="Ok"
            log_action "Caducidad de la contraseña desactivada para $user" "$EXPIRY_STATUS"
        fi
        return 1
    else
        echo "La contraseña de $user no caduca."
        EXPIRY_STATUS="Ok"
        log_action "Verificación de caducidad de contraseña para $user" "$EXPIRY_STATUS"
        return 0
    fi
}

check_password_expiry "secops"

json_data=$(generate_system_data)
send_to_google_sheets "$json_data" "true"

if [[ "$EXPIRY_STATUS" == "No" ]]; then
    log_action "No fue necesario modificar la caducidad de la contraseña para $user" "$EXPIRY_STATUS"
fi


SECOPS_SUDO_GROUP="No"
if id -nG "secops" | grep -qw "sudo"; then
    SECOPS_SUDO_GROUP="Sí"
    log_action "Verificación de secops en grupo sudo" "Sí"
else
    log_action "Verificación de secops en grupo sudo" "No"
    # Añadir secops al grupo sudo
    sudo usermod -aG sudo secops
    log_action "Añadir secops al grupo sudo" "Exitoso"
fi

SECOPS_PASS_EXPIRY=$(chage -l secops 2>/dev/null | grep "never" &>/dev/null && echo "Nunca caduca" || echo "Caduca")
log_action "Verificación de caducidad de contraseña secops" "$SECOPS_PASS_EXPIRY"


json_data=$(generate_system_data)
send_to_google_sheets "$json_data" "true"

CLAMAV_INSTALLED="No"
if dpkg -l | grep -q clamav; then
    CLAMAV_INSTALLED="Instalado"
    log_action "Verificación de ClamAV" "Instalado"
    CLAMAV_SERVICE_STATUS=$(systemctl is-active clamav-freshclam 2>/dev/null || echo "Error")
    log_action "Estado del servicio ClamAV" "$CLAMAV_SERVICE_STATUS"
    if [ "$CLAMAV_SERVICE_STATUS" != "active" ]; then
        echo "Activando el servicio ClamAV..."
        sudo systemctl start clamav-freshclam
        log_action "Activar servicio ClamAV" "Exitoso"
    fi
else
    log_action "Verificación de ClamAV" "No instalado"
    echo "Instalando ClamAV..."
    sudo apt update && sudo apt install -y clamav
    log_action "Instalación de ClamAV" "Exitoso"
    sudo systemctl start clamav-freshclam
    log_action "Activar servicio ClamAV" "Exitoso"
fi

AUTOS_INSTALLED="No"
if dpkg -l | grep -q autofs; then
    AUTOS_INSTALLED="Instalado"
    log_action "Verificación de autofs" "Instalado"
    echo "Desactivando autofs..."
    sudo systemctl stop autofs
    sudo apt remove --purge -y autofs
    log_action "Desactivar y eliminar autofs" "Exitoso"
else
    log_action "Verificación de autofs" "No instalado"
fi

echo "Actualizando permisos de grub.cfg..."
sudo chmod 600 /boot/grub/grub.cfg
log_action "Actualización de permisos de grub.cfg" "Exitoso"

MOTD_FILE="/etc/update-motd.d/50-motd-news"
BACKUP_MOTD="/etc/update-motd.d/50-motd-news.bak"
echo "Realizando backup de $MOTD_FILE..."
sudo cp $MOTD_FILE $BACKUP_MOTD
log_action "Backup de motd" "Exitoso"

echo "Modificando motd..."
log_action "Modificación de motd" "Exitoso"
MOTD_STATUS="Exitoso"


if grep -qxF 'NTP=time.google.com' /etc/systemd/timesyncd.conf; then
    log_action "La sincronización de tiempo ya está configurada con time.google.com."
    TIME_STATUS="OK"
else
    log_action "La sincronización de tiempo no está configurada. Configurando..."
    sudo timedatectl set-ntp on
    sudo systemctl start systemd-timesyncd
    sudo apt install -y systemd-timesyncd

    if grep -qxF 'NTP=time.google.com' /etc/systemd/timesyncd.conf && \
       grep -qxF 'FallbackNTP=ntp.ubuntu.com' /etc/systemd/timesyncd.conf && \
       grep -qxF 'RootDistanceMaxSec=5' /etc/systemd/timesyncd.conf && \
       grep -qxF 'PollIntervalMinSec=32' /etc/systemd/timesyncd.conf && \
       grep -qxF 'PollIntervalMaxSec=2048' /etc/systemd/timesyncd.conf; then
        log_action "Las líneas necesarias ya existen en el archivo de configuración."
    else
        sudo sed -i '/^#NTP=/s/^#//' /etc/systemd/timesyncd.conf
        sudo sed -i '/^#FallbackNTP=/s/^#//' /etc/systemd/timesyncd.conf
        sudo sed -i '/^#RootDistanceMaxSec=/s/^#//' /etc/systemd/timesyncd.conf
        sudo sed -i '/^#PollIntervalMinSec=/s/^#//' /etc/systemd/timesyncd.conf
        sudo sed -i '/^#PollIntervalMaxSec=/s/^#//' /etc/systemd/timesyncd.conf

        sudo sed -i '/^NTP=/d' /etc/systemd/timesyncd.conf
        sudo sed -i '/^FallbackNTP=/d' /etc/systemd/timesyncd.conf
        sudo sed -i '/^RootDistanceMaxSec=/d' /etc/systemd/timesyncd.conf
        sudo sed -i '/^PollIntervalMinSec=/d' /etc/systemd/timesyncd.conf
        sudo sed -i '/^PollIntervalMaxSec=/d' /etc/systemd/timesyncd.conf

        sudo tee -a /etc/systemd/timesyncd.conf > /dev/null <<EOF
NTP=time.google.com
FallbackNTP=ntp.ubuntu.com
RootDistanceMaxSec=5
PollIntervalMinSec=32
PollIntervalMaxSec=2048
EOF

        sudo systemctl restart systemd-timesyncd.service
        log_action "Sincronización de tiempo configurada correctamente."
        TIME_STATUS="Ok"
    fi
fi


if sudo ufw enable > /dev/null; then
    log_action "ufw habilitado."
    UFW_STATUS="OK"
else
    log_action "Error al habilitar ufw."
    UFW_STATUS="ERROR"
fi

if sudo ufw allow out on all > /dev/null; then
    log_action "Configuración de ufw realizada para permitir todas las conexiones salientes en todas las interfaces."
else
    log_action "Error al configurar ufw para permitir todas las conexiones salientes en todas las interfaces."
fi

if sudo ufw default deny routed > /dev/null; then
    log_action "Se ha implementado una política de denegación predeterminada."
    ufw_policy="OK"
else
    log_action "Error al implementar la política de denegación predeterminada."
    ufw_policy="Error"
fi


DATA_FILE="/tmp/hardening_data.json"


standard_users=$(getent passwd {1000..60000} | awk -F: '{print $1}')

users=("soporte" "root" "secops" $standard_users)
users_with_expired_passwords=()

for user in "${users[@]}"; do
    check_password_expiry "$user"
    expiry_status=$?

    if [[ $expiry_status -eq 1 ]]; then
        other_users_expiry_status="Cambio a $user Necesario"
        users_with_expired_passwords+=("$user")
        if [[ "$user" != "soporte" && "$user" != "root" && "$user" != "secops" ]]; then
            log_action "La contraseña de $user requiere cambio. Utiliza el comando 'sudo passwd $user' y sigue las instrucciones."
        fi
    else
        log_action "Cambio de password no requerido para $user... Continuando con el proceso..."
        other_users_expiry_status="Cambio No necesario"
    fi
done

if [ ${#users_with_expired_passwords[@]} -gt 0 ]; then
    echo "Los siguientes usuarios requieren cambio de contraseña:"
    for user in "${users_with_expired_passwords[@]}"; do
        echo "- $user"
    done
    users_expired_str=$(IFS=,; echo "${users_with_expired_passwords[*]}")

    echo "Usuarios con password expirado: $users_expired_str" >> "$DATA_FILE"
else
    echo "Ningún usuario requiere cambio de contraseña... Continuando con el proceso..."
fi


sudoers_edit_status="No se ha editado el archivo sudoers."

edit_sudoers_file() {
    local sudoers_file="/etc/sudoers"
    if [ -f "/etc/sudoers.d/sudo_log" ]; then
        sudoers_file="/etc/sudoers.d/sudo_log"
    fi

    log_action "Editando archivo sudoers: $sudoers_file"
    if sudo visudo -c -f "$sudoers_file" > /dev/null; then
        if ! sudo grep -q "^Defaults logfile" "$sudoers_file"; then
            echo "Defaults logfile = \"/var/log/sudo.log\"" | sudo tee -a "$sudoers_file" > /dev/null
            log_action "Línea agregada al archivo sudoers."
            sudoers_edit_status="Archivo sudoers editado correctamente."
        else
            log_action "El archivo sudoers ya contiene la línea especificada."
            sudoers_edit_status="La línea ya existe en el archivo sudoers."
        fi
    else
        log_action "Error al validar el archivo sudoers. Asegúrate de que la sintaxis sea correcta antes de editar."
        sudoers_edit_status="Error al validar el archivo sudoers."
    fi
}

edit_sudoers_file

blacklist_usb_storage="blacklist usb_storage"
blacklist_uas="blacklist uas"
log_action "Estableciendo el bloqueo de dispositivos de almacenamiento USB"

file_contains_line() {
    local file="$1"
    local line="$2"
    grep -qFx "$line" "$file"
}

if file_contains_line "/etc/modprobe.d/blacklist.conf" "$blacklist_usb_storage"; then
    log_action "La línea $blacklist_usb_storage ya existe en /etc/modprobe.d/blacklist.conf"
    blacklist_usb_storage_set="Ya existe"
else
    if echo "$blacklist_usb_storage" | sudo tee -a "/etc/modprobe.d/blacklist.conf" > /dev/null; then
        log_action "Bloqueo habilitado sobre dispositivos de almacenamiento USB en /etc/modprobe.d/blacklist.conf"
        blacklist_usb_storage_set="Habilitado"
    else
        log_action "Error al establecer bloqueo sobre dispositivos de almacenamiento USB en /etc/modprobe.d/blacklist.conf"
        blacklist_usb_storage_set="Error"
    fi
fi

if file_contains_line "/etc/modprobe.d/blacklist.conf" "$blacklist_uas"; then
    log_action "La línea $blacklist_uas ya existe en /etc/modprobe.d/blacklist.conf"
    blacklist_uas_set="Ya existe"
else
    if echo "$blacklist_uas" | sudo tee -a "/etc/modprobe.d/blacklist.conf" > /dev/null; then
        log_action "Bloqueo habilitado sobre dispositivos de almacenamiento USB en /etc/modprobe.d/blacklist.conf"
        blacklist_uas_set="Habilitado"
    else
        log_action "Error al establecer bloqueo sobre dispositivos de almacenamiento USB en /etc/modprobe.d/blacklist.conf"
        blacklist_uas_set="Error"
    fi
fi

json_data=$(generate_system_data)
send_to_google_sheets "$json_data" "true"

delete_file "${FILE_NAME}"

