#!/bin/bash

# Archivo de log
log_file="/var/log/apt_update_fix.log"

# Función para escribir en el log
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$log_file"
}

# Función para crear un backup del archivo sources.list
function backup_sources_list() {
    if [ -f /etc/apt/sources.list ]; then
        log "Creando un backup del archivo /etc/apt/sources.list..."
        cp /etc/apt/sources.list /etc/apt/sources.list.bak_$(date '+%Y%m%d%H%M%S')
        log "Backup creado en /etc/apt/sources.list.bak_$(date '+%Y%m%d%H%M%S')."
    else
        log "El archivo /etc/apt/sources.list no existe, no es necesario hacer un backup."
    fi
}

# Función para desactivar Ubuntu Pro
function disable_ubuntu_pro() {
    log "Desactivando Ubuntu Pro (anteriormente Ubuntu Advantage)..."

    if grep -q "pro" /etc/apt/sources.list; then
        log "Comentando repositorios relacionados con Ubuntu Pro en /etc/apt/sources.list..."
        sed -i '/pro/d' /etc/apt/sources.list
        log "Repositorios de Ubuntu Pro comentados."
    else
        log "No se encontraron repositorios de Ubuntu Pro en /etc/apt/sources.list."
    fi

    if systemctl is-active --quiet ubuntu-advantage-tools; then
        log "Deteniendo y deshabilitando el servicio ubuntu-advantage-tools..."
        systemctl stop ubuntu-advantage-tools
        systemctl disable ubuntu-advantage-tools
        log "Servicio ubuntu-advantage-tools desactivado."
    else
        log "El servicio ubuntu-advantage-tools no está activo."
    fi

    log "Ubuntu Pro desactivado correctamente."
}

function fix_google_chrome_update() {
    log "Corrigiendo el error de actualización de Google Chrome..."

    # Verificar y eliminar el archivo de clave si ya existe
    if [ -f /usr/share/keyrings/google-chrome.gpg ]; then
        sudo rm /usr/share/keyrings/google-chrome.gpg
        log "Archivo de clave antiguo eliminado."
    fi

    # Descargar la clave y crear el archivo keyring (sobrescribiendo sin preguntar)
    wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/google-chrome.gpg
    if [ $? -eq 0 ]; then
        log "Clave de firma de Google Chrome descargada y guardada correctamente."
    else
        log "Error al descargar la clave de firma de Google Chrome."
        exit 1
    fi

    # Crear el archivo de repositorio de Google Chrome
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list > /dev/null
    if [ $? -eq 0 ]; then
        log "Repositorio de Google Chrome configurado correctamente en /etc/apt/sources.list.d/google-chrome.list."
    else
        log "Error al configurar el repositorio de Google Chrome."
        exit 1
    fi
}


# Función para crear un nuevo sources.list basado en la versión de Ubuntu
function create_sources_list() {
    version=$(lsb_release -rs)
    codename=$(lsb_release -cs)

    # Definir el repositorio base
    if (( $(echo "$version < 18.04" | bc -l) )) || [ "$version" == "20.10" ]; then
        base_url="http://old-releases.ubuntu.com/ubuntu"
    elif (( $(echo "$version >= 18.04" | bc -l) && $(echo "$version < 20.04" | bc -l) )); then
        base_url="http://old-releases.ubuntu.com/ubuntu"
    else
        base_url="http://archive.ubuntu.com/ubuntu"
    fi

    cat <<EOF > /etc/apt/sources.list
# Repositorios principales
deb $base_url $codename main restricted universe multiverse
deb $base_url $codename-updates main restricted universe multiverse
deb $base_url $codename-backports main restricted universe multiverse
deb $base_url $codename-security main restricted universe multiverse

# Repositorios de socios (opcional)
deb http://archive.canonical.com/ubuntu $codename partner
EOF
    log "Nuevo archivo sources.list creado para la versión $version ($codename)"
}

# Función para comentar líneas incorrectas en sources.list
function comment_invalid_sources() {
    log "Verificando líneas incorrectas en sources.list..."

    apt_output=$(apt update 2>&1)
    echo "$apt_output" | tee -a "$log_file"

    invalid_sources=$(echo "$apt_output" | grep -Eo '(Err:|W:|Fallo al obtener).*http.*')

    if [ -n "$invalid_sources" ]; then
        log "Se encontraron líneas inválidas o con advertencias en el sources.list. Procediendo a comentarlas..."

        while IFS= read -r line; do
            url=$(echo "$line" | grep -oP '(http|https)://\S+')

            if [ -n "$url" ]; then
                log "Comentando la línea con el repositorio: $url"
                sed -i "s|^deb.*$url|#&|" /etc/apt/sources.list
            fi
        done <<< "$invalid_sources"

        log "Las líneas inválidas o con advertencias han sido comentadas."
    else
        log "No se encontraron errores ni advertencias relacionadas con repositorios en apt update."
    fi
}

# Función para reparar repositorios que ya no tienen un archivo Release
function fix_release_not_found_errors() {
    log "Buscando y reparando errores de repositorios sin archivo Release..."

    apt_output=$(apt update 2>&1)
    echo "$apt_output" | tee -a "$log_file"

    release_errors=$(echo "$apt_output" | grep -E '(E:|N:).*Release')

    if [ -n "$release_errors" ]; then
        log "Se encontraron errores relacionados con repositorios sin archivo Release. Procediendo a eliminarlos..."

        while IFS= read -r line; do
            url=$(echo "$line" | grep -oP '(http|https)://\S+')

            if [ -n "$url" ]; then
                log "Eliminando el repositorio: $url"
                sed -i "/$url/d" /etc/apt/sources.list /etc/apt/sources.list.d/*.list
            fi
        done <<< "$release_errors"

        log "Los repositorios sin archivo Release han sido eliminados."
    else
        log "No se encontraron errores de repositorios sin archivo Release."
    fi
}

# Función para manejar dependencias rotas
function fix_broken_dependencies() {
    log "Verificando dependencias rotas..."
    dpkg_audit_output=$(dpkg --audit 2>&1)

    if [ -n "$dpkg_audit_output" ]; then
        log "Se encontraron problemas de dependencias rotas. Detalles:"
        log "$dpkg_audit_output"
        
        # Intentar corregir las dependencias rotas
        log "Intentando corregir las dependencias rotas..."
        sudo apt --fix-broken install -y
        
        # Verificar nuevamente si el problema persiste
        dpkg_audit_output=$(dpkg --audit 2>&1)
        if [ -n "$dpkg_audit_output" ]; then
            log "Aún existen problemas de dependencias rotas después de la corrección:"
            log "$dpkg_audit_output"
        else
            log "Las dependencias rotas fueron corregidas exitosamente."
        fi
    else
        log "No se encontraron problemas de dependencias rotas."
    fi
}


# Verificar si MySQL está instalado
if dpkg -l | grep -q mysql-server; then
    echo "MySQL está instalado, procediendo con la corrección del repositorio."

    # Verificar si el archivo del repositorio ya existe
    if ! grep -q "dev.mysql.com" /etc/apt/sources.list.d/*; then
        echo "No se encontró el repositorio de MySQL, agregando el repositorio correcto."

        # Descargar el archivo de configuración de MySQL
        wget -q https://dev.mysql.com/get/apt/mysql-apt-config_0.8.17-1_all.deb -O /tmp/mysql-apt-config.deb

        # Instalar el paquete de configuración de MySQL
        sudo dpkg -i /tmp/mysql-apt-config.deb
        rm /tmp/mysql-apt-config.deb

        # Actualizar la lista de paquetes
        sudo apt update

        echo "Repositorio de MySQL agregado y lista de paquetes actualizada."
    else
        echo "El repositorio de MySQL ya está configurado correctamente."
    fi
else
    echo "MySQL no está instalado, no se realizará ninguna acción."
fi



# Iniciar el proceso y registrar en log
log "Iniciando el proceso de actualización y corrección de repositorios."

# Crear un backup del archivo sources.list antes de borrarlo
backup_sources_list

# Borrar el archivo sources.list actual
log "Borrando el archivo sources.list..."
rm /etc/apt/sources.list
log "El archivo sources.list ha sido borrado."

# Crear un nuevo archivo sources.list
create_sources_list

# Desactivar Ubuntu Pro
disable_ubuntu_pro

# Comentar líneas incorrectas en sources.list
#comment_invalid_sources

# Reparar errores de repositorios que ya no tienen archivo Release
fix_release_not_found_errors

# Añadir clave de firma de Google Chrome
fix_google_chrome_update

# Verificar y arreglar dependencias rotas
fix_broken_dependencies


log "Proceso completado."

# Salir con éxito
