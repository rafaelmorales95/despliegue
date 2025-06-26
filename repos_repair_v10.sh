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
        timestamp=$(date '+%Y%m%d%H%M%S')
        log "Creando un backup del archivo /etc/apt/sources.list..."
        cp /etc/apt/sources.list /etc/apt/sources.list.bak_$timestamp
        log "Backup creado en /etc/apt/sources.list.bak_$timestamp."
    else
        log "El archivo /etc/apt/sources.list no existe, no es necesario hacer un backup."
    fi
}

# Función para desactivar Ubuntu Pro
function disable_ubuntu_pro() {
    log "Desactivando Ubuntu Pro (anteriormente Ubuntu Advantage)..."

    if grep -q "pro" /etc/apt/sources.list; then
        log "Eliminando repositorios relacionados con Ubuntu Pro en /etc/apt/sources.list..."
        sed -i '/pro/d' /etc/apt/sources.list
        log "Repositorios de Ubuntu Pro eliminados."
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

# Función para corregir la actualización de Google Chrome
function fix_google_chrome_update() {
    log "Corrigiendo el error de actualización de Google Chrome..."

    if [ -f /usr/share/keyrings/google-chrome.gpg ]; then
        rm /usr/share/keyrings/google-chrome.gpg
        log "Archivo de clave antiguo eliminado."
    fi

    wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg
    if [ $? -eq 0 ]; then
        log "Clave de firma de Google Chrome descargada y guardada correctamente."
    else
        log "Error al descargar la clave de firma de Google Chrome."
        exit 1
    fi

    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list
    log "Repositorio de Google Chrome configurado correctamente."
}

# Crear nuevo sources.list basado en la versión de Ubuntu
function create_sources_list() {
    version=$(lsb_release -rs)
    codename=$(lsb_release -cs)

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

EOF

    log "Nuevo archivo sources.list creado para la versión $version ($codename)."
}

# Comentar líneas inválidas en sources.list y sources.list.d/*.list
function comment_invalid_sources() {
    log "Verificando líneas incorrectas en los repositorios..."

    apt_output=$(apt update 2>&1)
    echo "$apt_output" | tee -a "$log_file"

    invalid_sources=$(echo "$apt_output" | grep -Eo '(Err:|W:|Fallo al obtener).*http.*')

    if [ -n "$invalid_sources" ]; then
        log "Se encontraron líneas inválidas. Procediendo a comentarlas..."

        while IFS= read -r line; do
            url=$(echo "$line" | grep -oP '(http|https)://\S+')
            if [ -n "$url" ]; then
                log "Comentando la línea con el repositorio: $url"

                sed -i "s|^deb .*${url}|#&|" /etc/apt/sources.list

                grep -rl "$url" /etc/apt/sources.list.d/*.list 2>/dev/null | while read -r file; do
                    sed -i "s|^deb .*${url}|#&|" "$file"
                    log "Comentado en $file"
                done
            fi
        done <<< "$invalid_sources"

        log "Las líneas inválidas han sido comentadas."
    else
        log "No se encontraron errores relacionados con los repositorios."
    fi
}

# Eliminar repositorios sin archivo Release
function fix_release_not_found_errors() {
    log "Revisando errores por falta de archivo Release..."

    apt_output=$(apt update 2>&1)
    echo "$apt_output" | tee -a "$log_file"

    release_errors=$(echo "$apt_output" | grep -E '(E:|N:).*Release')

    if [ -n "$release_errors" ]; then
        log "Eliminando repositorios sin archivo Release..."

        while IFS= read -r line; do
            url=$(echo "$line" | grep -oP '(http|https)://\S+')
            if [ -n "$url" ]; then
                log "Eliminando entradas con $url"

                sed -i "/$url/d" /etc/apt/sources.list
                find /etc/apt/sources.list.d/ -type f -name "*.list" -exec sed -i "/$url/d" {} \;
            fi
        done <<< "$release_errors"

        log "Repositorios problemáticos eliminados."
    else
        log "No se encontraron errores de tipo Release."
    fi
}

# Verificar dependencias rotas
function fix_broken_dependencies() {
    log "Verificando dependencias rotas..."
    dpkg_audit_output=$(dpkg --audit 2>&1)

    if [ -n "$dpkg_audit_output" ]; then
        log "Se encontraron dependencias rotas:"
        log "$dpkg_audit_output"
    else
        log "No se encontraron problemas de dependencias."
    fi
}

# ------------------------ EJECUCIÓN PRINCIPAL ------------------------

log "=== Iniciando el proceso de verificación y reparación de repositorios ==="

# Verificar permisos
if [ "$EUID" -ne 0 ]; then
    echo "Este script debe ejecutarse como root." >&2
    exit 1
fi

# Crear backup
backup_sources_list

# Desactivar Ubuntu Pro si es necesario
#disable_ubuntu_pro

# Verificar y comentar líneas inválidas
comment_invalid_sources

# Eliminar entradas sin archivo Release
fix_release_not_found_errors

# Borrar y regenerar sources.list
rm -f /etc/apt/sources.list
log "Archivo /etc/apt/sources.list eliminado."
create_sources_list

# Corregir repositorio y clave de Google Chrome
fix_google_chrome_update

# Verificar dependencias rotas
fix_broken_dependencies

log "=== Proceso completado correctamente ==="
exit 0
