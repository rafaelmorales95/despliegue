# Establecer la politica de ejecucion a Unrestricted
$originalExecutionPolicy = Get-ExecutionPolicy
#Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force

# Obtener nombre del equipo
$hostname = $env:COMPUTERNAME

# Lista de servicios a verificar de Bitdefender
$bitdefender_services = @("EPProtectedService", "EPIntegrationService", "EPRedline", "EPSecurityService", "EPUpdateService")

# Lista de servicios de Forcepoint
$forcepoint_services = @("FPDIAG", "FMAPOService")

# Lista de procesos a verificar de Forcepoint
$forcepoint_processes = @("fppsvc", "F1EUI", "Dserui", "wepsvc")

# Lista de servicios de BitLocker
$bitlocker_services = @("BDESVC")

# Archivo CSV de log
$logFile = Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Path) -ChildPath "verification_log.csv"


# Funcion para obtener el formato de fecha y hora
function Get-FormattedDateTime {
    return Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

# Funcion para escribir en el CSV
function Write-LogToCSV {
    param (
        [string]$service,
        [string]$status
    )
    $logEntry = [PSCustomObject]@{
        "Hostname" = $hostname
        "Servicio" = $service
        "Status" = $status
        "Fecha" = Get-FormattedDateTime
    }
    $logEntry | Export-Csv -Path $logFile -Append -NoTypeInformation
}

# Funcion para verificar el estado de los servicios
function Check-Services {
    param (
        [string[]]$services,
        [string]$toolName
    )
    foreach ($service in $services) {
        try {
            $serviceStatus = Get-Service -Name $service -ErrorAction Stop
            if ($serviceStatus.Status -eq 'Running') {
                $message = "El servicio '$service' esta corriendo."
                Write-Output "[OK] [$toolName] $message"
                Write-LogToCSV -service $service -status "OK"
            } else {
                $message = "El servicio '$service' esta detenido."
                Write-Output "[ERROR] [$toolName] $message"
                Write-LogToCSV -service $service -status "ERROR"
            }
        } catch {
            $message = "El servicio '$service' no fue encontrado o ocurrio un error: $_"
            Write-Output "[ERROR] [$toolName] $message"
            Write-LogToCSV -service $service -status "ERROR"
        }
    }
}

# Funcion para verificar el estado de los procesos
function Check-Processes {
    param (
        [string[]]$processes,
        [string]$toolName
    )
    $allProcesses = Get-Process
    foreach ($process in $processes) {
        $processStatus = $allProcesses | Where-Object { $_.Name -eq $process }
        if ($processStatus) {
            $message = "El proceso '$process' esta corriendo."
            Write-Output "[OK] [$toolName] $message"
            Write-LogToCSV -service $process -status "OK"
        } else {
            $message = "El proceso '$process' no fue encontrado."
            Write-Output "[ERROR] [$toolName] $message"
            Write-LogToCSV -service $process -status "ERROR"
        }
    }
}

# Funcion para verificar si la maquina esta añadida  a un dominio
function Check-DomainMembership {
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        if ($computerSystem.PartOfDomain) {
            $message = "Este equipo es miembro del dominio: '$($computerSystem.Domain)'."
            Write-Output "[OK] $message"
            Write-LogToCSV -service "DomainMembership" -status "OK"
        } else {
            $message = "Este equipo no es parte de ningun dominio."
            Write-Output "[ERROR] $message"
            Write-LogToCSV -service "DomainMembership" -status "ERROR"
        }
    } catch {
        $message = "Ocurrio un error al revisar el estado de dominio del equipo: $_"
        Write-Output "[ERROR] $message"
        Write-LogToCSV -service "DomainMembership" -status "ERROR"
    }
}

#Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -noExit -Command `"& { Get-BitLockerVolume -MountPoint 'C:' }`"" -Verb RunAs
#Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -noExit -Command `"& { Get-BitLockerVolume -MountPoint 'C:' | Select-Object -ExpandProperty VolumeStatus }`"" -Verb RunAs
# Funcion para verificar el cifrado del disco
function Check-DiskEncryption {
    # Comando para obtener el estado de BitLocker en la unidad C:
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"& { (Get-BitLockerVolume -MountPoint 'C:' | Select-Object -ExpandProperty VolumeStatus) | Out-File -FilePath `"$env:USERPROFILE\VolumeStatus.txt`" }`"" -Verb RunAs -Wait

    # Esperar 3 segundos para asegurarse de que el archivo se haya creado
    Start-Sleep -Seconds 3

    # Leer el contenido del archivo VolumeStatus.txt
    $bitlockerStatus = Get-Content -Path "$env:USERPROFILE\VolumeStatus.txt"

    # Verificar el estado obtenido y mostrar un mensaje adecuado
    if ($bitlockerStatus -eq 'FullyEncrypted') {
        Write-Output "BitLocker está activado y la unidad está completamente cifrada."
        Write-LogToCSV -service "DiskEncryption" -status "OK"
    } elseif ($bitlockerStatus -eq 'FullyDecrypted') {
        Write-Output "BitLocker está activado pero la unidad no está cifrada en este momento."
        Write-LogToCSV -service "DiskEncryption" -status "OK"
    } elseif ($bitlockerStatus -eq 'EncryptionInProgress') {
        Write-Output "BitLocker está activando actualmente la encriptación en la unidad."
        Write-LogToCSV -service "DiskEncryption" -status "OK"
    } elseif ($bitlockerStatus -eq 'DecryptionInProgress') {
        Write-Output "BitLocker está desactivando actualmente la encriptación en la unidad."
        Write-LogToCSV -service "DiskEncryption" -status "ERROR"
    } else {
        Write-Output "El estado de BitLocker no se pudo determinar correctamente."
        Write-LogToCSV -service "DiskEncryption" -status "ERROR"
    }
}



# Ejecutar todas las verificaciones

Write-Output "`nVerificando servicios de Bitdefender..."
Check-Services -services $bitdefender_services -toolName "Bitdefender"

Write-Output "`nVerificando servicios de BitLocker..."
Check-Services -services $bitlocker_services -toolName "BitLocker"

Write-Output "`nVerificando servicios de Forcepoint..."
Check-Services -services $forcepoint_services -toolName "Forcepoint"

Write-Output "`nVerificando procesos de Forcepoint..."
Check-Processes -processes $forcepoint_processes -toolName "Forcepoint"

Write-Output "`nVerificando membresia de dominio..."
Check-DomainMembership

Write-Output "`nVerificando cifrado de disco..."
Check-DiskEncryption

# Ruta del archivo VolumeStatus.txt en el directorio del perfil del usuario 
$volumeStatusFilePath = Join-Path -Path $env:USERPROFILE -ChildPath "VolumeStatus.txt"

try {
    # Verificar si el archivo existe y es un archivo regular
    if (Test-Path $volumeStatusFilePath -PathType Leaf) {
        # Eliminar el archivo
        Remove-Item -Path $volumeStatusFilePath -Force
        Write-Output "Archivo $volumeStatusFilePath eliminado correctamente."
    } else {
        Write-Output "No se encontró el archivo $volumeStatusFilePath para eliminar."
    }
} catch {
    Write-Output "Error al intentar eliminar el archivo ${volumeStatusFilePath}: $($_.Exception.Message)"
}



# Restablecer la politica de ejecucion a su valor original
#Set-ExecutionPolicy -Scope Process -ExecutionPolicy $originalExecutionPolicy -Force
