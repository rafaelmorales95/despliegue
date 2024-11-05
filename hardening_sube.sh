import gspread
from google.oauth2.service_account import Credentials
import platform
import socket
import psutil
import subprocess
import os

# Función para instalar paquetes si no están ya instalados
def install_package(package_name):
    try:
        subprocess.check_call(f"dpkg -l | grep {package_name}", shell=True)
        print(f"{package_name} ya está instalado.")
    except subprocess.CalledProcessError:
        print(f"Instalando {package_name}...")
        subprocess.check_call(f"sudo apt update && sudo apt install -y {package_name}", shell=True)
        print(f"{package_name} instalado correctamente.")

# Instalación de dependencias necesarias
install_package("python3-pip")
install_package("clamav")
install_package("autofs")

# Instalar dependencias de Python si no están presentes
try:
    import gspread
except ImportError:
    subprocess.check_call("pip3 install gspread google-auth", shell=True)
    print("gspread y google-auth instalados.")

try:
    import psutil
except ImportError:
    subprocess.check_call("pip3 install psutil", shell=True)
    print("psutil instalado.")

# Configuración de acceso a Google Sheets
SCOPE = ["https://www.googleapis.com/auth/spreadsheets"]
CREDS = Credentials.from_service_account_file("Key.json", scopes=SCOPE)
CLIENT = gspread.authorize(CREDS)

# ID de la hoja de cálculo de Google Sheets y nombre de la hoja
SPREADSHEET_ID = "1jWAH06G2BKnCPl6UT4vZs2CMMVIPJ9-ZSE3OBQvaeUY"  # Cambia esto por el ID de tu hoja
SHEET_NAME = "ubuntu"  # Cambia esto por el nombre de tu hoja

# Abrir la hoja de cálculo y seleccionar la hoja específica
sheet = CLIENT.open_by_key(SPREADSHEET_ID).worksheet(SHEET_NAME)

# Verificar si ya existe un encabezado
header_exists = len(sheet.row_values(1)) > 0

# Si el encabezado no existe, añadirlo
if not header_exists:
    header = ["Hostname", "Sistema Operativo", "Kernel", "CPU", "RAM", "Disco Libre", "IP",
              "Permisos de Ejecución", "Ejecución como Root", "Versión del Script", "Ubicación de Log",
              "Existencia de secops", "secops en grupo sudo", "Contraseña de secops nunca caduca", 
              "Verificación NVMe", "Caducidad de Contraseña Soporte/Root/secops", 
              "ClamAV Instalado", "Estado del servicio ClamAV", "Actualización de ClamAV", 
              "Autofs Instalado", "Permisos de grub.cfg", "Existencia de MOTD", 
              "Estado de Backup de MOTD", "Secuencias de MOTD"]
    sheet.append_row(header, value_input_option="USER_ENTERED")

# Información del sistema
hostname = socket.gethostname()
os_info = platform.system() + " " + platform.release()
kernel = platform.release()
cpu = platform.processor()
memory = str(round(psutil.virtual_memory().total / (1024 ** 3))) + " GB"
disk = str(round(psutil.disk_usage('/').free / (1024 ** 3))) + " GB"
ip_address = socket.gethostbyname(hostname)

# Funciones de verificación
def check_permissions():
    return os.access(__file__, os.X_OK)

def check_if_running_as_admin():
    return os.geteuid() == 0

def check_version():
    version = "1.0"  # Cambia esto según la versión de tu script
    return version == "1.0"

def check_log_file_location(log_file):
    return os.access(log_file, os.W_OK)

def check_user_exists(username):
    try:
        subprocess.check_output(f"id {username}", shell=True)
        return "Exists"
    except subprocess.CalledProcessError:
        return "Not Exists"

def check_user_in_sudo_group(username):
    try:
        output = subprocess.check_output(f"groups {username}", shell=True).decode()
        return "sudo" in output
    except Exception:
        return "Error"

def check_password_never_expires(username):
    try:
        output = subprocess.check_output(f"chage -l {username}", shell=True).decode()
        return "never" in output
    except Exception:
        return "Error"

def check_nvme():
    try:
        output = subprocess.check_output("lsblk -d -o rota", shell=True)
        return "0" in output.decode().strip()  # 0 indica que es NVMe
    except Exception:
        return "Error"

def check_clamav_installed():
    try:
        subprocess.check_output("dpkg -l | grep clamav", shell=True)
        return "Installed"
    except Exception:
        return "Not Installed"

def check_clamav_service():
    try:
        output = subprocess.check_output("systemctl is-active clamav-freshclam", shell=True).decode().strip()
        return output
    except Exception:
        return "Error"

def update_clamav_definitions():
    try:
        subprocess.check_call("freshclam", shell=True)
        return "Updated"
    except Exception:
        return "Failed"

def check_autofs_installed():
    try:
        subprocess.check_output("dpkg -l | grep autofs", shell=True)
        return "Installed"
    except Exception:
        return "Not Installed"

def check_grub_permissions():
    try:
        output = subprocess.check_output("ls -l /boot/grub/grub.cfg", shell=True).decode()
        return "root root" in output and "rwx" not in output
    except Exception:
        return "Error"

def check_motd_existence():
    return os.path.exists("/etc/update-motd.d/50-motd-news")

def backup_motd():
    try:
        subprocess.check_call("cp /etc/update-motd.d/50-motd-news /etc/update-motd.d/50-motd-news.bak", shell=True)
        return "Backup Created"
    except Exception:
        return "Backup Failed"

def check_motd_sequences():
    try:
        with open("/etc/update-motd.d/50-motd-news", "r") as file:
            content = file.read()
            return all(seq not in content for seq in ['\m', '\r', '\s', '\v'])
    except Exception:
        return "Error"

# Ejecutar verificaciones
permissions_status = check_permissions()
admin_status = check_if_running_as_admin()
version_status = check_version()
log_file = "/var/log/hardening.log"  # Cambia esto a tu ruta de log
log_file_status = check_log_file_location(log_file)

secops_exists = check_user_exists("secops")
secops_in_sudo = check_user_in_sudo_group("secops")
secops_password_expiry = check_password_never_expires("secops")

nvme_status = check_nvme()
password_expiry_users = all(check_password_never_expires(user) for user in ["soporte", "root", "secops"])

clamav_installed = check_clamav_installed()
clamav_service_status = check_clamav_service()
clamav_update_status = update_clamav_definitions()

autofs_installed = check_autofs_installed()
grub_permissions = check_grub_permissions()
motd_existence = check_motd_existence()
motd_backup_status = backup_motd() if motd_existence else "MOTD Not Found"
motd_sequences_status = check_motd_sequences()

# Datos a enviar a Google Sheets
data = [
    [hostname, os_info, kernel, cpu, memory, disk, ip_address,
     permissions_status, admin_status, version_status, log_file_status,
     secops_exists, secops_in_sudo, secops_password_expiry, nvme_status,
     password_expiry_users, clamav_installed, clamav_service_status,
     clamav_update_status, autofs_installed, grub_permissions, motd_existence,
     motd_backup_status, motd_sequences_status]
]

# Añadir datos en la siguiente fila vacía
sheet.append_rows(data, value_input_option="USER_ENTERED")

print("Datos subidos con éxito a Google Sheets")
