#!/bin/bash

# Definir variables
URL_DEB="https://data.rafalan.pro/web/client/pubshares/jU84V2mWDbMeDvz2ecjG3P?compress=false"  
NOMBRE_DEB="hardening-tool_2.6_all.deb"                   
COMANDO="hardening-tool"              

# Instalar curl y wget si no están presentes (obligatorio)
echo "[+] Instalando curl y wget (requeridos)..."
sudo apt-get update
sudo apt-get install -y curl wget

# Verificar si la instalación fue exitosa
if ! command -v curl &> /dev/null || ! command -v wget &> /dev/null; then
    echo "[!] Error: No se pudo instalar curl o wget"
    exit 1
fi

# Descargar el archivo .deb (usando wget como predeterminado)
echo "[+] Descargando $NOMBRE_DEB..."
wget -O "$NOMBRE_DEB" "$URL_DEB"

# Verificar si la descarga fue exitosa
if [ $? -ne 0 ]; then
    echo "[!] Falló wget, intentando con curl..."
    curl -L "$URL_DEB" -o "$NOMBRE_DEB" || {
        echo "[!] Error al descargar el archivo .deb con ambos métodos"
        exit 1
    }
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
