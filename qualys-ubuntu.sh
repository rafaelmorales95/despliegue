#!/bin/bash

# Variables
DOWNLOAD_URL_1="https://data.rafalan.pro/web/client/pubshares/epwySsnqsKnPE9hkn98JXb?compress=false"
DOWNLOAD_URL_2="https://data.rafalan.pro/web/client/pubshares/8kXGiz9xAAre79d44GsLLB?compress=false"
FILE_NAME_1="QualysCloudAgent.deb"
FILE_NAME_2="Cerftificado_Navegacion_Forcepoint.crt"
USER="soporte"
PASSWORD=""

# Función para descargar un archivo desde una URL
download_file() {
    local url=$1
    local file_name=$2
    
    if [ -f "${file_name}" ]; then
        echo "El archivo ${file_name} ya existe en el directorio. No es necesario descargarlo nuevamente."
    else
        echo "Descargando archivo ${file_name} desde la URL ${url}..."
        wget "${url}" -O ${file_name}
        
        if [ $? -ne 0 ]; then
            echo "Error al descargar el archivo ${file_name}."
            exit 1
        fi
        
        echo "Archivo descargado como ${file_name}"
    fi
}

# Función para instalar el paquete .deb
install_deb_package() {
    echo "Verificando si el servicio 'qualys-cloud-agent' está activo..."
    
    # Verificar el estado del servicio
    if systemctl status qualys-cloud-agent.service >/dev/null 2>&1; then
        echo "El servicio 'qualys-cloud-agent' ya está activo."
    else
        echo "Instalando ${FILE_NAME_1}..."
        
        sudo dpkg -i QualysCloudAgent.deb
        
        if [ $? -ne 0 ]; then
            echo "Error al instalar el paquete ${FILE_NAME_1}. Intentando reparar dependencias..."
            sudo apt-get install -f -y
        fi
        
        echo "Instalación de ${FILE_NAME_1} completada."
    fi
}

# Función para activar el agente de Qualys
activate_qualys_agent() {
    echo "Activando el agente de Qualys..."
    
    sudo /usr/local/qualys/cloud-agent/bin/qualys-cloud-agent.sh ActivationId=e1f4f34f-8e56-4f2e-8336-484624b77091 CustomerId=72528eda-c400-5ba6-81d6-a154df946c4b ServerUri=https://qagpublic.qg4.apps.qualys.com/CloudAgent/

    if [ $? -ne 0 ]; then
        echo "Error al activar el agente de Qualys."
        exit 1
    fi
    
    echo "Agente de Qualys activado."
}

# Función para verificar si auditd está activo, deshabilitarlo y desinstalarlo si es necesario
disable_and_uninstall_auditd() {
    echo "Verificando el estado del servicio 'auditd'..."
    
    if systemctl status auditd >/dev/null 2>&1; then
        echo "El servicio 'auditd' está activo. Deshabilitando y desinstalando..."
        
        # Detener y deshabilitar el servicio auditd
        sudo systemctl stop auditd
        sudo systemctl disable auditd
        
        # Desinstalar auditd
        sudo apt-get remove --purge auditd -y
        
        # Verificar si hay alguna referencia a auditd en la configuración de GRUB
        echo "Eliminando configuración relacionada con auditd en GRUB..."
        if grep -q "audit" /etc/grub.d/40_custom; then
            sudo sed -i '/audit/d' /etc/grub.d/40_custom
            sudo update-grub
            echo "Configuración de auditd eliminada de GRUB."
        else
            echo "No se encontró configuración de auditd en GRUB."
        fi

        echo "El servicio 'auditd' ha sido deshabilitado y desinstalado."
    else
        echo "El servicio 'auditd' no está activo."
    fi
}

# Función para verificar si el proceso bdsec está activo
check_bdsec_process() {
    echo "Verificando si el proceso 'bdsec' está activo..."
    
    if systemctl status bdsec >/dev/null 2>&1; then
        echo "El proceso 'bdsec' está activo."
    else
        echo "El proceso 'bdsec' no está activo."
    fi
}

# Función para verificar si hay contraseña configurada en GRUB
check_grub_password() {
    echo "Verificando si hay contraseña configurada en GRUB..."
    
    if grep -q "password" /etc/grub.d/40_custom; then
        echo "Contraseña del GRUB configurada."
    else
        echo "No se encontró una contraseña del GRUB configurada."
    fi
}

list_grub_users_with_password() {
    echo "Enumerando usuarios con contraseña configurada en GRUB..."

    # Buscar líneas que contengan la palabra 'password' en /etc/grub.d/40_custom y extraer los nombres de usuario
    if grep -q "password" /etc/grub.d/40_custom; then
        grep "password" /etc/grub.d/40_custom | awk '{print $2}' | sort | uniq
    else
        echo "No se encontraron usuarios con contraseñas configuradas en GRUB."
    fi
}

# Función principal
main() {
    download_file "${DOWNLOAD_URL_1}" "${FILE_NAME_1}"
    download_file "${DOWNLOAD_URL_2}" "${FILE_NAME_2}"
    
    # Ejecutar las funciones como usuario 'soporte'
    echo "${PASSWORD}" | sudo -S -u ${USER} bash -c "$(declare -f install_deb_package); install_deb_package; $(declare -f activate_qualys_agent); activate_qualys_agent; $(declare -f disable_and_uninstall_auditd); disable_and_uninstall_auditd"
    
    # Verificar si el proceso bdsec está activo
    check_bdsec_process
    
    # Verificar la contraseña del GRUB y listar los usuarios con contraseña
    check_grub_password
    list_grub_users_with_password
    
    hostname
    echo "Script completado."
}

# Ejecutar la función principal
main
