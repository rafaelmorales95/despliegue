#!/bin/bash

version="Versión 2.0 (08 de Agosto de 2024)"

# Definir la ubicación de los archivos de registro
log_file="script_log.txt"
csv_file="script_log.csv"

# Agregar línea vacía al inicio del archivo de texto
echo >> "$log_file"
echo "Inicio del registro $(date +'%Y-%m-%d %H:%M:%S')" >> "$log_file"
echo "Inicio del script - $version" >> "$log_file"
echo >> "$log_file"

# Función para agregar mensajes al archivo de log
log_message() {
    local message="$1"
    echo "$(date +'%Y-%m-%d %H:%M:%S') $message" >> "$log_file"
}

# Función para agregar mensajes al archivo CSV
log_csv() {
    local hostname="$1"
    local servicio="$2"
    local status="$3"
    local fecha=$(date +'%Y-%m-%d %H:%M:%S')

    # Verificar si el archivo CSV existe y agregar encabezado si es necesario
    if [ ! -f "$csv_file" ]; then
        echo "hostname,servicio,status,fecha" > "$csv_file"
    fi

    echo "$hostname,$servicio,$status,$fecha" >> "$csv_file"
}

# Función para imprimir mensajes de log en rojo
print_error() {
    echo -e "\033[1;31m$1\033[0m"  # Cambia el color del texto a rojo
}

# Verificar si hay discos NVMe
nvme_disks=$(ls /dev/nvme* 2>/dev/null | wc -l)

# Verificar si hay discos HDD
hdd_disks=$(ls /dev/sd* 2>/dev/null | grep -v '[0-9]$' | wc -l)

if [ "$nvme_disks" -gt 0 ]; then 
    echo "Este equipo tiene disco NVMe."
    log_message "Este equipo tiene disco NVMe."
    log_csv "$(hostname)" "NVMe" "OK"
elif [ "$hdd_disks" -gt 0 ]; then   
    echo "Este equipo tiene un disco HDD. El proceso no puede continuar."
    log_message "Este equipo tiene disco HDD."
    log_csv "$(hostname)" "HDD" "ERROR"
    exit 1
else
    echo "No se puede determinar el tipo de disco."
    log_message "No se puede determinar el tipo de disco."
    log_csv "$(hostname)" "Disco" "ERROR"
    exit 1
fi

# Verificar el espacio usado en disco
used_space=$(df --output=used / | tail -n 1)
used_space_gb=$((used_space / 1024 / 1024))

# Verificar el espacio disponible en disco
available_space=$(df --output=avail / | tail -n 1)
available_space_gb=$((available_space / 1024 / 1024))

if [ "$available_space_gb" -lt "$used_space_gb" ]; then
    echo "No hay suficiente espacio en el disco. Se requiere al menos ${used_space_gb}GB de espacio libre."
    log_message "No hay suficiente espacio en el disco. Se requiere al menos ${used_space_gb}GB de espacio libre."
    log_csv "$(hostname)" "Espacio en disco" "ERROR"
    exit 1
else
    echo "Hay suficiente espacio en el disco. Continuando con el proceso..."
    log_message "Hay suficiente espacio en el disco. Continuando con el proceso..."
    log_csv "$(hostname)" "Espacio en disco" "OK"
fi

check_password_expiry() {
    local user="$1"
    expiry_info=$(chage -l "$user" | grep 'La contraseña caduca')
    expiry_date=$(echo "$expiry_info" | awk -F: '{print $2}' | xargs)

    if [[ "$expiry_date" != "nunca" ]]; then
        echo "La contraseña de $user ha caducado o caducará pronto."
        if [[ "$user" == "Soporte" || "$user" == "root" ]]; then
            chage -M 99999 "$user"
            echo "La caducidad de la contraseña para $user ha sido desactivada."
            log_message "Caducidad desactivada para $user."
            log_csv "$(hostname)" "chage -M 99999 $user" "Desactivación de caducidad"
        fi
        return 1
    else
        echo "La contraseña de $user no caduca."
        return 0
    fi
}

# Obtener lista de usuarios estándar (UID entre 1000 y 60000)
standard_users=$(getent passwd {1000..60000} | awk -F: '{print $1}')

# Especificar usuarios a verificar: Soporte, root y todos los usuarios estándar
users=("Soporte" "root" $standard_users)
users_with_expired_passwords=()

for user in "${users[@]}"; do
    check_password_expiry "$user"
    expiry_status=$?

    if [[ $expiry_status -eq 1 ]]; then
        users_with_expired_passwords+=("$user")
        if [[ "$user" != "Soporte" && "$user" != "root" ]]; then
            log_message "La contraseña de $user requiere cambio. Utiliza el comando 'sudo passwd $user' y sigue las instrucciones."
            log_csv "$(hostname)" "passwd $user" "Cambio de passwd necesario"
        fi
    else
        log_message "Cambio de password no requerido para $user... Continuando con el proceso..."
        log_csv "$(hostname)" "passwd $user" "OK"
    fi
done

if [ ${#users_with_expired_passwords[@]} -gt 0 ]; then
    echo "Los siguientes usuarios requieren cambio de contraseña:"
    for user in "${users_with_expired_passwords[@]}"; do
        echo "- $user"
    done
    exit 1
else
    echo "Ningún usuario requiere cambio de contraseña... Continuando con el proceso..."
fi

# Verificar si Timeshift está instalado y, si no lo está, intentar instalarlo
if ! command -v timeshift &> /dev/null; then
    echo "Timeshift no está instalado. Instalando..."
    if sudo apt-get update && sudo apt-get install -y timeshift; then
        echo "Timeshift instalado correctamente."
    else
        echo "Error al instalar Timeshift. Por favor, instálalo manualmente y vuelve a ejecutar el script."
        exit 1
    fi
fi

# Imprimir el número de versión y la fecha de liberación al ejecutar el script
echo "Número de versión: $version"

# Crear un snapshot con timeshift
create_snapshot() {
    log_message "Creando snapshot con timeshift..."
    sudo timeshift --create --comments "Antes de aplicar configuraciones"
    if [ $? -eq 0 ]; then
        log_message "Snapshot creado exitosamente."
        log_csv "$(hostname)" "timeshift" "Snapshot creado"
    else
        log_message "Error al crear snapshot."
        log_csv "$(hostname)" "timeshift" "Error al crear snapshot"
        exit 1
    fi
}

# Crear snapshot antes de aplicar configuraciones
create_snapshot




# Verificar si ClamAV ya está instalado
if command -v clamscan &>/dev/null; then
    message="ClamAV ya está instalado en el sistema."
    echo "$message"
    log_message "$message"
    log_csv "$(hostname)" "ClamAV" "Instalado"
fi

# Verificar si el servicio ClamAV ya está en ejecución
if systemctl is-active --quiet clamav-freshclam; then
    message="El servicio ClamAV ya está en ejecución."
    echo "$message"
    log_message "$message"
    log_csv "$(hostname)" "ClamAV Service" "En ejecución"
else
    # Instalar ClamAV y ClamAV daemon
    message="Instalando ClamAV y ClamAV daemon..."
    echo "$message"
    log_message "$message"
    log_csv "$(hostname)" "ClamAV" "Instalando"
    sudo apt update
    sudo apt install -y clamav clamav-daemon

    # Actualizar las definiciones de virus
    message="Actualizando las definiciones de virus..."
    sudo freshclam
    echo "$message"
    log_message "$message"
    log_csv "$(hostname)" "ClamAV" "Actualizando definiciones"

    # Iniciar y habilitar el servicio ClamAV
    message="Iniciando y habilitando el servicio ClamAV..."
    echo "$message"
    log_message "$message"
    log_csv "$(hostname)" "ClamAV Service" "Iniciando"
    sudo systemctl start clamav-freshclam
    sudo systemctl enable clamav-freshclam
fi

# Verificar la instalación
message="Verificando la instalación de ClamAV..."
echo "$message"
log_message "$message"
log_csv "$(hostname)" "ClamAV" "Verificando instalación"
clamscan --version

message="Instalación de ClamAV completada."
echo "$message"
log_message "$message"
log_csv "$(hostname)" "ClamAV" "Instalación completada"

# Verificar si el paquete autofs está instalado
if dpkg -l | grep -q "autofs"; then
    # Deshabilitar autofs si está instalado
    sudo systemctl --now disable autofs
    if [ $? -eq 0 ]; then
        log_message "autofs ha sido deshabilitado con éxito."
    else
        log_message "Error al deshabilitar autofs."
    fi
else
    log_message "El paquete autofs no está instalado, no se puede deshabilitar."
fi


# Eliminar autofs
sudo apt purge autofs
if [ $? -eq 0 ]; then
    autofs_purge=1
    log_message "autofs ha sido eliminado con éxito."
else
    log_message "Error al eliminar autofs."
    autofs_purge=0
fi


# Definir los repositorios base en inglés y mexicano
base_repo_english=("http://security.ubuntu.com/ubuntu" "http://archive.ubuntu.com/ubuntu")
base_repo_mexican=("http://security.ubuntu.com/ubuntu" "http://mx.archive.ubuntu.com/ubuntu")

# Definir los sufijos de los repositorios de seguridad y actualizaciones
security_suffix="-security"
updates_suffix="-updates"

# Construir los arreglos de repositorios según el idioma
if [ "$system_language" = "es" ]; then
    base_repo=("${base_repo_mexican[@]}")
else
    base_repo=("${base_repo_english[@]}")
fi

# Construir los arreglos de repositorios completos
required_repos_2004=()
required_repos_2204=()

for repo in "${base_repo[@]}"; do
    required_repos_2004+=("$repo focal$security_suffix" "$repo focal$updates_suffix")
    required_repos_2204+=("$repo jammy$security_suffix" "$repo jammy$updates_suffix")
done

# Solicitar el nombre de usuario
echo "Introduce el nombre de usuario para proteger GRUB:"
read requested_user

# Verificar si el usuario existe en el sistema
if ! id "$requested_user" &>/dev/null; then
    message="El usuario '$requested_user' no existe en el sistema."
    echo "$message"
    log_message "$message"
    exit 1
fi

# Agregar el usuario al grupo "lpadmin"
sudo usermod -aG lpadmin "$requested_user"
message="El usuario '$requested_user' ha sido añadido al grupo 'lpadmin'."
echo "$message"
log_message "$message"

# Crear el archivo de configuración para el usuario específico
sudo nano /etc/polkit-1/localauthority/50-local.d/10-network-manager-user.pkla << EOF
[Allow $requested_user to modify network settings without authentication]
Identity=unix-user:$requested_user
Action=org.freedesktop.NetworkManager.settings.modify.system
ResultAny=yes
ResultInactive=yes
ResultActive=yes
EOF

message="Se ha creado un archivo de configuración para el usuario '$requested_user' en '/etc/polkit-1/localauthority/50-local.d/10-network-manager-user.pkla'."
echo "$message"
log_message "$message"

# Solicitar y confirmar la nueva contraseña
echo "Introduce la contraseña para GRUB:"
read -s password
echo "Vuelve a introducir la contraseña:"
read -s password_confirm

if [ "$password" != "$password_confirm" ]; then
    message="Las contraseñas no coinciden. Intenta de nuevo."
    echo "$message"
    log_message "$message"
    exit 1
fi

# Generación del hash de la contraseña
password_hash=$(echo -e "$password\n$password_confirm" | grub-mkpasswd-pbkdf2 | grep -oP 'grub.pbkdf2.*')
if [ -z "$password_hash" ]; then
    message="Error al generar la contraseña encriptada."
    echo "$message"
    log_message "$message"
    exit 1
fi

# Agregar o actualizar usuario en superusers y su contraseña en 40_custom
if grep -q "set superusers=" /etc/grub.d/40_custom; then
    # Extraer los usuarios actuales y agregar el nuevo si no está ya listado
    current_users=$(grep "set superusers=" /etc/grub.d/40_custom | cut -d'"' -f2)
    if [[ ! " $current_users " =~ " $requested_user " ]]; then
        # Añadir el nuevo usuario a la lista existente
        new_users="$current_users $requested_user"
        sudo sed -i "s/set superusers=\".*\"/set superusers=\"$new_users\"/" /etc/grub.d/40_custom
    fi
else
    # Crear la entrada de superusuarios si no existe
    echo "set superusers=\"$requested_user\"" | sudo tee -a /etc/grub.d/40_custom
fi

# Actualizar o agregar la contraseña del usuario
if grep -q "^password_pbkdf2 '$requested_user'" /etc/grub.d/40_custom; then
    sudo sed -i "/^password_pbkdf2 '$requested_user'/c\password_pbkdf2 '$requested_user' $password_hash" /etc/grub.d/40_custom
else
    echo "password_pbkdf2 '$requested_user' $password_hash" | sudo tee -a /etc/grub.d/40_custom
fi

# Actualizar la configuración de GRUB
message="Actualizando la configuración de GRUB..."
echo "$message"
log_message "$message"
sudo update-grub

message="Configuración de GRUB actualizada correctamente para el usuario '$requested_user'."
echo "$message"
log_message "$message"

# Bloquear permisos de configuración para GRUB
sudo chown root:root /boot/grub/grub.cfg > /dev/null
sudo chmod u-wx,go-rwx /boot/grub/grub.cfg > /dev/null
log_message "Permisos en la configuración de GRUB establecidos correctamente."
grub_config=1

# Ruta al archivo a verificar
archivo="/etc/update-motd.d/50-motd-news"

# Ruta al archivo de respaldo
backup_file="/var/tmp/50-motd-news.backup"

# Verificar si el archivo existe
if [ ! -f "$archivo" ]; then
    message="El archivo $archivo no existe."
    echo "$message"
    log_message "$message"
    exit 1
fi

# Realizar una copia de seguridad del archivo original
cp "$archivo" "$backup_file"

# Buscar instancias de \m, \r, \s, \v en el archivo
if grep -q -e '\\m' -e '\\r' -e '\\s' -e '\\v' "$archivo"; then
    message="Se encontraron las siguientes instancias en el archivo $archivo:"
    echo "$message"
    log_message "$message"
    grep -n -e '\\m' -e '\\r' -e '\\s' -e '\\v' "$archivo" >> "$log_file"

    # Eliminar las líneas que contienen instancias encontradas y guardar el archivo modificado
    sed -i -e '/\\m/d' -e '/\\r/d' -e '/\\s/d' -e '/\\v/d' "$archivo"

    message="Las instancias encontradas se han eliminado del archivo $archivo."
    echo "$message"
    log_message "$message"
else
    message="No se encontraron instancias de \\m, \\r, \\s, \\v en el archivo $archivo."
    echo "$message"
    log_message "$message"
fi


log_message "Verificando y configurando la sincronización de tiempo..."

# Verificar si la línea NTP=time.google.com ya existe en timesyncd.conf
if grep -qxF 'NTP=time.google.com' /etc/systemd/timesyncd.conf; then
    log_message "La sincronización de tiempo ya está configurada con time.google.com."
    time_sync=0
else
    log_message "La sincronización de tiempo no está configurada. Configurando..."
    sudo timedatectl set-ntp on
    sudo systemctl start systemd-timesyncd
    sudo apt install -y systemd-timesyncd

    # Verificar si las líneas necesarias ya existen en timesyncd.conf
    if grep -qxF 'NTP=time.google.com' /etc/systemd/timesyncd.conf && \
       grep -qxF 'FallbackNTP=ntp.ubuntu.com' /etc/systemd/timesyncd.conf && \
       grep -qxF 'RootDistanceMaxSec=5' /etc/systemd/timesyncd.conf && \
       grep -qxF 'PollIntervalMinSec=32' /etc/systemd/timesyncd.conf && \
       grep -qxF 'PollIntervalMaxSec=2048' /etc/systemd/timesyncd.conf; then
        log_message "Las líneas necesarias ya existen en el archivo de configuración."
    else
        # Descomentar y configurar las líneas necesarias en timesyncd.conf
        sudo sed -i '/^#NTP=/s/^#//' /etc/systemd/timesyncd.conf
        sudo sed -i '/^#FallbackNTP=/s/^#//' /etc/systemd/timesyncd.conf
        sudo sed -i '/^#RootDistanceMaxSec=/s/^#//' /etc/systemd/timesyncd.conf
        sudo sed -i '/^#PollIntervalMinSec=/s/^#//' /etc/systemd/timesyncd.conf
        sudo sed -i '/^#PollIntervalMaxSec=/s/^#//' /etc/systemd/timesyncd.conf

        # Eliminar duplicados si existen
        sudo sed -i '/^NTP=/d' /etc/systemd/timesyncd.conf
        sudo sed -i '/^FallbackNTP=/d' /etc/systemd/timesyncd.conf
        sudo sed -i '/^RootDistanceMaxSec=/d' /etc/systemd/timesyncd.conf
        sudo sed -i '/^PollIntervalMinSec=/d' /etc/systemd/timesyncd.conf
        sudo sed -i '/^PollIntervalMaxSec=/d' /etc/systemd/timesyncd.conf

        # Agregar las líneas necesarias al archivo timesyncd.conf
        sudo tee -a /etc/systemd/timesyncd.conf > /dev/null <<EOF
NTP=time.google.com
FallbackNTP=ntp.ubuntu.com
RootDistanceMaxSec=5
PollIntervalMinSec=32
PollIntervalMaxSec=2048
EOF

        sudo systemctl restart systemd-timesyncd.service
        log_message "Sincronización de tiempo configurada correctamente."
        time_sync=1
    fi
fi



# Habilitar ufw
if sudo ufw enable > /dev/null; then
    log_message "ufw habilitado."
    ufw_enable=1
else
    log_message "Error al habilitar ufw."
    ufw_enable=0
fi

# Configurar ufw para permitir todas las conexiones salientes en todas las interfaces
if sudo ufw allow out on all > /dev/null; then
    log_message "Configuración de ufw realizada para permitir todas las conexiones salientes en todas las interfaces."
    ufw_config=1
else
    log_message "Error al configurar ufw para permitir todas las conexiones salientes en todas las interfaces."
    ufw_config=0
fi

# Implementar una política de denegación predeterminada
if sudo ufw default deny routed > /dev/null; then
    log_message "Se ha implementado una política de denegación predeterminada."
    ufw_policy=1
else
    log_message "Error al implementar la política de denegación predeterminada."
    ufw_policy=0
fi

# Verificar si auditd ya está instalado
if dpkg -s auditd > /dev/null 2>&1; then
    log_message "auditd ya está instalado."
    auditd_install=1
else
    # Intentar instalar auditd
    if sudo apt install -y auditd audispd-plugins > /dev/null; then
        log_message "auditd instalado correctamente."
        auditd_install=1
    else
        log_message "Error al instalar auditd."
        auditd_install=0
    fi
fi

# Verificar si auditd ya está habilitado
if sudo systemctl is-enabled --quiet auditd; then
    log_message "auditd ya está habilitado."
    auditd_enable=1
else
    # Intentar habilitar auditd
    if sudo systemctl --now enable auditd > /dev/null; then
        log_message "auditd habilitado correctamente."
        auditd_enable=1
    else
        log_message "Error al habilitar auditd."
        auditd_enable=0
    fi
fi


# Verificar si GRUB está instalado
if ! command -v grub-mkconfig >/dev/null; then
    log_message "GRUB no está instalado."
    grub_installed=0
else
    grub_installed=0
fi

if [ $grub_installed -eq 1 ]; then
    # Verificar si los cambios ya están presentes en /etc/default/grub
    if grep -q 'GRUB_CMDLINE_LINUX=.*audit=1.*audit_backlog_limit=8192' /etc/default/grub; then
        log_message "Los cambios ya están presentes en /etc/default/grub."
        grub_edit=0
    else
        # Intentar editar el archivo /etc/default/grub
        if sudo sed -i '/GRUB_CMDLINE_LINUX=/ s/"$/ audit=1"/' /etc/default/grub && \
           sudo sed -i '/GRUB_CMDLINE_LINUX=/ s/"$/ audit_backlog_limit=8192"/' /etc/default/grub && \
           sudo update-grub > /dev/null; then
            log_message "Archivo /etc/default/grub editado correctamente."
            grub_edit=1
        else
            log_message "Error al editar el archivo /etc/default/grub."
            grub_edit=0
        fi
    fi
fi



# Función para verificar y crear archivos de reglas de auditoría si no existen
verify_and_create_audit_rules_files() {
    local file="$1"
    local rules_content="$2"
    if [ ! -f "$file" ]; then
        if sudo touch "$file"; then
            log_message "Archivo $file creado correctamente."
        else
            log_message "Error al crear el archivo $file."
            audit_rules_edit=0
            return
        fi
    fi

    # Verificar si las líneas ya existen en el archivo
    if sudo grep -qe "$rules_content" "$file"; then
        log_message "Las reglas ya existen en el archivo $file."
        audit_rules_edit=0
        return
    fi

    # Agregar las líneas al archivo
    if sudo sh -c "echo '$rules_content' >> $file"; then
        log_message "Reglas agregadas correctamente al archivo $file."
        audit_rules_edit=0
    else
        log_message "Error al agregar reglas al archivo $file."
        audit_rules_edit=1
    fi
}





# Verificar y crear archivos de reglas de auditoría necesarios
verify_and_create_audit_rules_files "/etc/audit/rules.d/50-identity.rules" "-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity"

verify_and_create_audit_rules_files "/etc/audit/rules.d/50-logins.rules" "
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins"

verify_and_create_audit_rules_files "/etc/audit/rules.d/50-session.rules" "
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins"

verify_and_create_audit_rules_files "/etc/audit/rules.d/50-scope.rules" "
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope"

# Ajustando los parámetros en /etc/audit/auditd.conf si no existen
echo "Editando /etc/audit/auditd.conf para ajustar los parámetros si es necesario..."
if ! sudo grep -qE '^max_log_file\s*=\s*6' /etc/audit/auditd.conf; then
    sudo sed -i '/^max_log_file\s*=.*/d' /etc/audit/auditd.conf
    echo "max_log_file = 6" | sudo tee -a /etc/audit/auditd.conf > /dev/null
fi

if ! sudo grep -qE '^max_log_file_action\s*=\s*keep_logs' /etc/audit/auditd.conf; then
    sudo sed -i '/^max_log_file_action\s*=.*/d' /etc/audit/auditd.conf
    echo "max_log_file_action = keep_logs" | sudo tee -a /etc/audit/auditd.conf > /dev/null
fi

log_message "Los parámetros en /etc/audit/auditd.conf han sido ajustados según la política del sitio."



# Añadir reglas de auditoría para los archivos de inicio de sesión
add_comment "Agregar reglas de auditoría para los archivos de inicio de sesión"
rules_content="
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins"
verify_and_create_audit_rules_files "/etc/audit/rules.d/50-logins.rules" "$rules_content"
if [ "$audit_rules_edit" -eq 0 ]; then
    log_message "No se pudo agregar reglas de auditoría para los archivos de inicio de sesión."
fi

# Añadir reglas de auditoría para los archivos de sesión
add_comment "Agregar reglas de auditoría para los archivos de sesión"
rules_content="
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins"
verify_and_create_audit_rules_files "/etc/audit/rules.d/50-session.rules" "$rules_content"
if [ "$audit_rules_edit" -eq 0 ]; then
    log_message "No se pudo agregar reglas de auditoría para los archivos de sesión."
fi

# Editar o crear reglas de auditoría para el alcance
add_comment "Editar o crear reglas de auditoría para el alcance"
rules_content="
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope"
verify_and_create_audit_rules_files "/etc/audit/rules.d/50-scope.rules" "$rules_content"
if [ "$audit_rules_edit" -eq 0 ]; then
    log_message "No se pudo editar o crear reglas de auditoría para el alcance."
fi



# Editar el archivo sudoers
add_comment "Editar archivo sudoers para agregar la línea 'Defaults logfile = /var/log/sudo.log'"

edit_sudoers_file() {
    local sudoers_file="/etc/sudoers"
    if [ -f "/etc/sudoers.d/sudo_log" ]; then
        sudoers_file="/etc/sudoers.d/sudo_log"
    fi

    log_message "Editando archivo sudoers: $sudoers_file"
    if sudo visudo -c -f "$sudoers_file" > /dev/null; then
        if ! sudo grep -q "^Defaults logfile" "$sudoers_file"; then
            echo "Defaults logfile = \"/var/log/sudo.log\"" | sudo tee -a "$sudoers_file" > /dev/null
            log_message "Línea agregada al archivo sudoers."
            sudoers_edit=0
        else
            log_message "El archivo sudoers ya contiene la línea especificada."
            sudoers_edit=0
        fi
    else
        log_message "Error al validar el archivo sudoers. Asegúrate de que la sintaxis sea correcta antes de editar."
        sudoers_edit=1
    fi
}

edit_sudoers_file
if [ "$sudoers_edit" -eq 0 ]; then
    log_message "No se pudo editar correctamente el archivo sudoers."
fi


edit_sudoers_file

# Función para ejecutar el comando y registrar la acción
execute_command() {
    local command="$1"
    log_message "Ejecutando: $command"
    eval $command
}

# Instalar el módulo pam_pwquality
execute_command "sudo apt install -y libpam-pwquality"
if [ $? -eq 0 ]; then
    log_message "Módulo pam_pwquality instalado correctamente."
    pam_pwquality_installed=0
else
    log_message "Error al instalar el módulo pam_pwquality."
    pam_pwquality_installed=1
fi

# Edición de /etc/security/pwquality.conf para ajustar la longitud mínima de la contraseña
echo "Editando /etc/security/pwquality.conf para ajustar la longitud mínima de la contraseña..."
sudo sed -i 's/^# minlen =.*$/minlen = 12/' /etc/security/pwquality.conf
log_message "La longitud mínima de la contraseña ha sido ajustada a 12 caracteres."

# Ajuste de la complejidad de la contraseña
echo "Ajustando la complejidad de la contraseña en /etc/security/pwquality.conf..."
# Opción 1: Establecer el número mínimo de clases de caracteres requeridas
sudo sed -i 's/^# minclass =.*$/minclass = 4/' /etc/security/pwquality.conf
# Opción 2: Utilizar el enfoque de configuración de créditos
sudo sed -i 's/^# dcredit =.*$/dcredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^# ucredit =.*$/ucredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^# ocredit =.*$/ocredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^# lcredit =.*$/lcredit = -1/' /etc/security/pwquality.conf

# Agregar mensaje al archivo de registro
log_message "La complejidad de la contraseña ha sido ajustada."


<<-COMMENT 
edit_common_password() {
    local common_password_file="/etc/pam.d/common-password"
    local pwquality_options="password requisite pam_pwquality.so retry=5"
    local existing_line=$(sudo grep "^[^#]*pam_pwquality\.so retry=" "$common_password_file")
    log_message "Editando archivo common-password: $common_password_file"
    if [ -n "$existing_line" ]; then
        local updated_line=$(echo "$existing_line" | sed 's/retry=[0-9]*/retry=5/')
        sudo sed -i "s|$(sed 's/[]\/$*.^|[]/\\&/g' <<< "$existing_line")|$updated_line|" "$common_password_file"
        log_message "Configuración de pam_pwquality actualizada en $common_password_file."
        common_password_edit=1
    else
        echo "$pwquality_options" | sudo tee -a "$common_password_file" > /dev/null
        log_message "Configuración de pam_pwquality agregada a $common_password_file."
        common_password_edit=0
    fi
}

<<-COMMENT 
edit_common_auth() {
    local common_auth_file="/etc/pam.d/common-auth"
    local auth_content="# here are the per-package modules (the \"\"Primary\"\" block)
auth    required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth    [success=1 default=ignore]      pam_unix.so nullok
# here's the fallback if no module succeeds
# BEGIN ANSIBLE MANAGED BLOCK
auth    [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth    sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
# END ANSIBLE MANAGED BLOCK
auth    requisite                       pam_deny.so
# prime the stack with a positive return value if there isn't one already;
# this avoids us returning an error just because nothing sets a success code
# since the modules above will each just jump around
auth    required                        pam_permit.so
# and here are more per-package modules (the \"\"Additional\"\" block)
auth    optional                        pam_cap.so
# end of pam-auth-update config
auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900"

    log_message "Editando archivo common-auth: $common_auth_file"
    if echo "$auth_content" | sudo tee "$common_auth_file" > /dev/null; then
        log_message "Configuración de common-auth actualizada correctamente."
        common_auth_edit=1
    else
        log_message "Error al editar el archivo common-auth."
        common_auth_edit=0
    fi
} 




edit_common_account() {
    local common_account_file="/etc/pam.d/common-account"
    local account_content="# here are the per-package modules (the \"\"Primary\"\" block)
account [success=1 new_authtok_reqd=done default=ignore]        pam_unix.so
# here's the fallback if no module succeeds
account requisite                       pam_deny.so
# prime the stack with a positive return value if there isn't one already;
# this avoids us returning an error just because nothing sets a success code
# since the modules above will each just jump around
account required                        pam_permit.so
# and here are more per-package modules (the \"\"Additional\"\" block)
# end of pam-auth-update config
account    required pam_faillock.so"

    log_message "Editando archivo common-account: $common_account_file"
    if echo "$account_content" | sudo tee "$common_account_file" > /dev/null; then
        log_message "Configuración de common-account actualizada correctamente."
        common_account_edit=1
    else
        log_message "Error al editar el archivo $common_account_file."
        common_account_edit=0
    fi
}

edit_common_account
if [ "$common_account_edit" -eq 0 ]; then
    log_message "No se pudo editar correctamente el archivo /etc/pam.d/common-account."
fi


# Editar el archivo /etc/pam.d/common-auth para incluir las opciones apropiadas para pam_pwquality.so
edit_common_auth
# Editar el archivo /etc/pam.d/common-account para incluir las opciones apropiadas para pam_pwquality.so
edit_common_account

# Editar el archivo /etc/pam.d/common-password para incluir las opciones apropiadas para pam_pwquality.so
edit_common_password a

# Añadir la configuración de remember al archivo /etc/pam.d/common-password
common_password_file="/etc/pam.d/common-password"
remember_line="password required pam_pwhistory.so remember=5"

log_message "Añadiendo la configuración de 'remember' al archivo $common_password_file"
if file_contains_line "$common_password_file" "$remember_line"; then
    log_message "La configuración de 'remember' ya está presente en $common_password_file."
    remember_config_added=1
else
    if sudo sed -i "/^password.*pam_unix.so.*/a $remember_line" "$common_password_file"; then
        log_message "Se ha añadido correctamente la configuración de 'remember' al archivo $common_password_file."
        remember_config_added=1
    else
        log_message "Error al añadir la configuración de 'remember' al archivo $common_password_file."
        remember_config_added=0
    fi
fi

if [ "$remember_config_added" -eq 0 ]; then
    log_message "No se pudo añadir correctamente la configuración de 'remember' al archivo /etc/pam.d/common-password."
fi

COMMENT

# Establecer PASS_MIN_DAYS en 1 en /etc/login.defs
pass_min_days_line="PASS_MIN_DAYS 1"
log_message "Estableciendo PASS_MIN_DAYS en 1 en /etc/login.defs"
if file_contains_line "/etc/login.defs" "$pass_min_days_line"; then
    log_message "La línea $pass_min_days_line ya existe en /etc/login.defs."
    pass_min_days_set=0
else
    if sudo sed -i "/^PASS_MIN_DAYS/c $pass_min_days_line" "/etc/login.defs"; then
        log_message "Establecido PASS_MIN_DAYS en 1 en /etc/login.defs."
        pass_min_days_set=0
    else
        log_message "Error al establecer PASS_MIN_DAYS en 1 en /etc/login.defs."
        pass_min_days_set=1
    fi
fi

if [ "$pass_min_days_set" -eq 0 ]; then
    log_message "No se pudo establecer correctamente PASS_MIN_DAYS en 1 en /etc/login.defs. " 
fi

# Establecer PASS_MAX_DAYS en 365 en /etc/login.defs
pass_max_days_line="PASS_MAX_DAYS 365"
log_message "Estableciendo PASS_MAX_DAYS en 365 en /etc/login.defs"
if file_contains_line "/etc/login.defs" "$pass_max_days_line"; then
    log_message "La línea $pass_max_days_line ya existe en /etc/login.defs."
    pass_max_days_set=0
else
    if sudo sed -i "/^PASS_MAX_DAYS/c $pass_max_days_line" "/etc/login.defs"; then
        log_message "Establecido PASS_MAX_DAYS en 365 en /etc/login.defs."
        pass_max_days_set=0
    else
        log_message "Error al establecer PASS_MAX_DAYS en 365 en /etc/login.defs."
        pass_max_days_set=1
    fi
fi

if [ "$pass_max_days_set" -eq 0 ]; then
    log_message "No se pudo establecer correctamente PASS_MAX_DAYS en 365 en /etc/login.defs."
fi

# Establecer politica de bloqueo de USB

#Agregar un cron que nos permita desbloquear usb por tiempo predefinido
blacklist_usb_storage="blacklist usb_storage"
blacklist_uas="blacklist uas"
log_message "Estableciendo el bloqueo de Dispositivos de almacenamiento USB"

# Verificar y agregar blacklist usb_storage si no existe
if file_contains_line "/etc/modprobe.d/blacklist.conf" "$blacklist_usb_storage"; then
    log_message "La línea $blacklist_usb_storage ya existe en /etc/modprobe.d/blacklist.conf"
    blacklist_usb_storage_set=1
else
    if echo "$blacklist_usb_storage" | sudo tee -a "/etc/modprobe.d/blacklist.conf" > /dev/null; then
        log_message "Bloqueo habilitado sobre dispositivos de almacenamiento USB en /etc/modprobe.d/blacklist.conf"
        blacklist_usb_storage_set=1
    else
        log_message "Error al establecer bloqueo sobre dispositivos de almacenamiento USB en /etc/modprobe.d/blacklist.conf"
        blacklist_usb_storage_set=0
    fi
fi

# Verificar y agregar blacklist uas si no existe
if file_contains_line "/etc/modprobe.d/blacklist.conf" "$blacklist_uas"; then
    log_message "La línea $blacklist_uas ya existe en /etc/modprobe.d/blacklist.conf"
    blacklist_uas_set=1
else
    if echo "$blacklist_uas" | sudo tee -a "/etc/modprobe.d/blacklist.conf" > /dev/null; then
        log_message "Bloqueo habilitado sobre dispositivos de almacenamiento USB en /etc/modprobe.d/blacklist.conf"
        blacklist_uas_set=1
    else
        log_message "Error al establecer bloqueo sobre dispositivos de almacenamiento USB en /etc/modprobe.d/blacklist.conf"
        blacklist_uas_set=0
    fi
fi

# Comprobación final
if [ "$blacklist_usb_storage_set" -eq 0 ] || [ "$blacklist_uas_set" -eq 0 ]; then
    log_message "No se pudo establecer correctamente bloqueo sobre dispositivos de almacenamiento USB en /etc/modprobe.d/blacklist.conf"
fi



# Modificar los parámetros de usuario para todos los usuarios con una contraseña definida
# para que coincida con los nuevos valores
log_message "Modificando los parámetros de usuario."
modified_users=0
for user in $(awk -F: '($2 != "x" && $2 != "*" && $2 != "") {print $1}' /etc/shadow); do
    if sudo chage --mindays 1 "$user" && sudo chage --maxdays 365 "$user" && sudo chage --inactive 30 "$user"; then
        log_message "Modificados los parámetros de usuario para $user."
        echo "Modificados los parámetros de usuario para $user."
        ((modified_users++))
    else
        log_message "Error al modificar los parámetros de usuario para $user."
    fi
done

if [ "$modified_users" -gt 0 ]; then
    user_parameters_modified=0
else
    user_parameters_modified=1
fi

# Ejecutar el siguiente comando para establecer el período de inactividad de contraseña predeterminado en 30 días
if sudo useradd -D -f 30; then
    log_message "Se ha establecido el período de inactividad de contraseña predeterminado en 30 días."
    echo "Se ha establecido el período de inactividad de contraseña predeterminado en 30 días."
    password_inactivity_set=0
else
    log_message "Error al establecer el período de inactividad de contraseña predeterminado en 30 días."
    password_inactivity_set=1
fi

<<-COMMENT 
# Verificar si el grupo ya existe
if getent group sugroup >/dev/null; then
    log_message "El grupo 'sugroup' ya existe." 
else
    # Verificar si el comando groupadd está disponible
    if ! command -v groupadd >/dev/null; then
        log_message "El comando groupadd no está disponible. Asegúrate de tener el paquete 'passwd' instalado."
    else
        # Intentar crear un grupo vacío
        if sudo groupadd sugroup; then
            log_message "Grupo vacío 'sugroup' creado correctamente."
            empty_group_created=0
        else
            log_message "Error al crear el grupo vacío 'sugroup'."
            empty_group_created=1
        fi
    fi
fi


# Añadir la configuración al archivo /etc/pam.d/su
su_pam_file="/etc/pam.d/su"
auth_line="auth required pam_wheel.so use_uid group=sugroup"
log_message "Añadiendo la configuración al archivo $su_pam_file"
if file_contains_line "$su_pam_file" "$auth_line"; then
    log_message "La configuración de autenticación ya está presente en $su_pam_file."
    su_pam_config_added=0
else
    if sudo sh -c "echo \"$auth_line\" >> $su_pam_file"; then
        log_message "Se ha añadido correctamente la configuración de autenticación al archivo $su_pam_file."
        su_pam_config_added=1
    else
        log_message "Error al añadir la configuración de autenticación al archivo $su_pam_file."
        su_pam_config_added=0
    fi
fi
COMMENT

# Agregar línea vacía al final del archivo
echo >> script_log.txt
echo "Fin del registro $(date +'%Y-%m-%d %H:%M:%S')" >> script_log.txt
echo "Fin del script" >> script_log.txt
echo >> script_log.txt 

# Comprobación de si todas las funciones se ejecutaron correctamente
echo "Informe de ejecución de funciones:"
echo "---------------------------------"

# Función para verificar si la función se ejecutó correctamente
check_function_execution() {
    local function_name="$1"
    local should_run="$2"
    local function_status="$3"

    if [ "$should_run" -eq 0 ]; then
        if [ $function_status -eq 0 ]; then
            echo "[OK] Función $function_name ejecutada correctamente."
        else
            echo "[ERROR] Error al ejecutar la función $function_name."
        fi
    else
        echo "[SKIP] La función $function_name no era necesaria y no se ejecutó."
    fi
}

# Verificar la ejecución de cada función
check_function_execution "Desactivar autofs" $autofs_purge $?
check_function_execution "Eliminar autofs" $autofs_installed $?
check_function_execution "Configurar contraseña cifrada para GRUB" $grub_protected $?
check_function_execution "Establecer permisos en la configuración de GRUB" $grub_config $?
check_function_execution "Configurar sincronización de tiempo" $time_sync $?
check_function_execution "Habilitar ufw" $ufw_enable $?
check_function_execution "Configurar ufw para permitir todas las conexiones salientes" $ufw_config $?
check_function_execution "Implementar política de denegación predeterminada en ufw" $ufw_policy $?
check_function_execution "Instalar auditd" $auditd_install $?
check_function_execution "Habilitar auditd" $auditd_enable $?
check_function_execution "Editar archivo /etc/default/grub" $grub_edit $?
check_function_execution "Editar o crear reglas de auditoría para archivos de inicio de sesión" $audit_rules_edit $?
check_function_execution "Editar o crear reglas de auditoría para archivos de sesión" $audit_rules_edit $?
check_function_execution "Editar o crear reglas de auditoría para el alcance" $audit_rules_edit $?
check_function_execution "Editar archivo sudoers para agregar la línea 'Defaults logfile = /var/log/sudo.log'" $sudoers_edit $?
check_function_execution "Instalar módulo pam_pwquality" $pam_pwquality_installed $?
check_function_execution "Editar archivo /etc/security/pwquality.conf para ajustar la longitud y complejidad de la contraseña" $file_line_edit $?
check_function_execution "Editar archivo /etc/pam.d/common-password para incluir las opciones apropiadas para pam_pwquality.so" $common_password_edit $?
check_function_execution "Editar archivo /etc/pam.d/common-auth para incluir las opciones apropiadas para pam_pwquality.so" $common_auth_edit $?
check_function_execution "Editar archivo /etc/pam.d/common-account para incluir las opciones apropiadas para pam_pwquality.so" $common_account_edit $?
check_function_execution "Añadir configuración de remember al archivo /etc/pam.d/common-password" $remember_config_added $?
check_function_execution "Establecer PASS_MIN_DAYS en 1 en /etc/login.defs" $pass_min_days_set $?
check_function_execution "Establecer PASS_MAX_DAYS en 365 en /etc/login.defs" $pass_max_days_set $?
check_function_execution "Modificar los parámetros de usuario" $user_parameters_modified $?
check_function_execution "Establecer el período de inactividad de contraseña predeterminado en 30 días" $password_inactivity_set $?
check_function_execution "Crear grupo vacío 'sugroup'" $empty_group_created $?
check_function_execution "Añadir configuración al archivo /etc/pam.d/su" $su_pam_config_added $?

echo "---------------------------------"

exit 0

