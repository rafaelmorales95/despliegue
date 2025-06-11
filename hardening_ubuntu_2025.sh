#!/bin/bash

# Definir variables
URL_DEB="https://data.rafalan.pro/web/client/pubshares/jU84V2mWDbMeDvz2ecjG3P?compress=false" 
NOMBRE_DEB="hardening-tool_2.6_all.deb"                
COMANDO="hardening-tool"             

# Verificar e instalar curl si no está presente
if ! command -v curl &> /dev/null &&
    echo "[+] Instalando curl..."
    sudo apt-get update
    sudo apt-get install -y curl
fi

# Descargar el archivo .deb usando curl (preferido) o wget
echo "[+] Descargando $NOMBRE_DEB..."
if command -v curl &> /dev/null; then
    curl -L "$URL_DEB" -o "$NOMBRE_DEB"
else
    wget -O "$NOMBRE_DEB" "$URL_DEB"
fi

# Verificar si la descarga fue exitosa
if [ $? -ne 0 ]; then
    echo "[!] Error al descargar el archivo .deb"
    exit 1
fi

# Instalar el paquete
echo "[+] Instalando $NOMBRE_DEB..."
sudo dpkg -i "$NOMBRE_DEB"

# Verificar si hubo errores de dependencias y corregir
if [ $? -ne 0 ]; then
    echo "[!] Corrigiendo dependencias faltantes..."
    sudo apt-get install -f -y
fi

# Ejecutar el comando instalado
echo "[+] Ejecutando comando: $COMANDO"
$COMANDO
