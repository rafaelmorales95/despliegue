#!/bin/bash

# Variables
DOWNLOAD_URL="https://data.rafalan.com/web/client/pubshares/epwySsnqsKnPE9hkn98JXb?compress=false"
FILE_NAME="QualysCloudAgent.deb"
USER="soporte"
PASSWORD=""

# Función para descargar el archivo desde el nuevo enlace
download_file() {
    if [ -f "${FILE_NAME}" ]; then
        echo "El archivo ${FILE_NAME} ya existe en el directorio. No es necesario descargarlo nuevamente."
    else
        echo "Descargando archivo desde el nuevo enlace..."
        wget "${DOWNLOAD_URL}" -O ${FILE_NAME}
        
        if [ $? -ne 0 ]; then
            echo "Error al descargar el archivo."
            exit 1
        fi
        
        echo "Archivo descargado como ${FILE_NAME}"
    fi
}

# Función para instalar el paquete .deb
install_deb_package() {
    echo "Verificando si el servicio 'qualys-cloud-agent' está activo..."
    
    # Verificar el estado del servicio
    if systemctl status qualys-cloud-agent.service >/dev/null 2>&1; then
        echo "El servicio 'qualys-cloud-agent' ya está activo."
    else
        echo "Instalando ${FILE_NAME}..."
        
        sudo dpkg -i QualysCloudAgent.deb
        
        if [ $? -ne 0 ]; then
            echo "Error al instalar el paquete ${FILE_NAME}. Intentando reparar dependencias..."
            sudo apt-get install -f -y
        fi
        
        echo "Instalación de ${FILE_NAME} completada."
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

# Función para verificar si el proceso bdsec está activo
check_bdsec_process() {
    echo "Verificando si el proceso 'bdsec' está activo..."
    
    if systemctl status bdsec >/dev/null 2>&1; then
        echo "El proceso 'bdsec' está activo."
    else
        echo "El proceso 'bdsec' no está activo."
    fi
}

# Función para verificar el estado del servicio auditd
check_auditd_service() {
    echo "Verificando el estado del servicio 'auditd'..."
    
    if systemctl status auditd >/dev/null 2>&1; then
        echo "El servicio 'auditd' está activo."
    else
        echo "El servicio 'auditd' no está activo."
    fi
}

# Función principal
main() {
    download_file
    
    # Ejecutar las funciones como usuario 'soporte'
    echo "${PASSWORD}" | sudo -S -u ${USER} bash -c "$(declare -f install_deb_package); install_deb_package; $(declare -f activate_qualys_agent); activate_qualys_agent; $(declare -f check_bdsec_process); check_bdsec_process; $(declare -f check_auditd_service); check_auditd_service"
    
    hostname
    echo "Script completado."
}

# Ejecutar la función principal
main
