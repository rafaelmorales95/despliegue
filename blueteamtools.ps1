# Establecer la política de ejecución a Unrestricted

#Falta añadir la verificacion del hardening, por medio de la entreda de registro de wallpaper
$originalExecutionPolicy = Get-ExecutionPolicy
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force

# Obtener nombre del equipo
$hostname = $env:COMPUTERNAME

# Servicios y procesos de Bitdefender, Forcepoint y Bitlocker
$bitdefender_services = @("EPProtectedService", "EPIntegrationService", "EPRedline", "EPSecurityService", "EPUpdateService")
$forcepoint_services = @("FPDIAG", "FMAPOService")
$forcepoint_processes = @("fppsvc", "F1EUI", "Dserui", "wepsvc")
$bitlocker_services = @("BDESVC")

# Archivo CSV de log
$logFile = Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Path) -ChildPath "verification_log.csv"

# Función para obtener el formato de fecha y hora
function Get-FormattedDateTime {
    return Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

# Inicializar el archivo CSV con encabezados
if (!(Test-Path $logFile)) {
    $header = "Hostname,Bitdefender,Forcepoint,Bitlocker,Dominio,Estado,Fecha"
    Out-File -FilePath $logFile -InputObject $header -Encoding UTF8
}

# Función para verificar servicios y devolver el estado
function Get-ServicesStatus {
    param (
        [string[]]$services
    )
    $status = @()
    foreach ($service in $services) {
        try {
            $serviceStatus = Get-Service -Name $service -ErrorAction Stop
            $status += if ($serviceStatus.Status -eq 'Running') { "OK" } else { "Stopped" }
        } catch {
            $status += "Not Found"
        }
    }
    return $status
}

# Función para verificar procesos y devolver el estado
function Get-ProcessesStatus {
    param (
        [string[]]$processes
    )
    $status = @()
    foreach ($process in $processes) {
        $processStatus = Get-Process -Name $process -ErrorAction SilentlyContinue
        $status += if ($processStatus) { "Running" } else { "Not Found" }
    }
    return $status
}

# Verificar si el equipo es parte de un dominio
function Get-DomainStatus {
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        if ($computerSystem.PartOfDomain) {
            return "OK"
        } else {
            return "No Domain"
        }
    } catch {
        return "Error"
    }
}

# Verificar el estado de cifrado de disco con BitLocker
function Get-BitlockerStatus {
    try {
        $bitlockerStatus = (Get-BitLockerVolume -MountPoint 'C:' | Select-Object -ExpandProperty VolumeStatus)
        return $bitlockerStatus -replace " ", ""  # Retirar espacios si hay
    } catch {
        return "Not Found"
    }
}

# Ejecutar verificaciones y escribir resultados en CSV
$bitdefenderStatusArray = Get-ServicesStatus -services $bitdefender_services
$forcepointServiceStatusArray = Get-ServicesStatus -services $forcepoint_services
$forcepointProcessStatusArray = Get-ProcessesStatus -processes $forcepoint_processes
$domainStatus = Get-DomainStatus
$bitlockerStatus = Get-BitlockerStatus
$date = Get-FormattedDateTime

# Definir estado de Bitdefender y Forcepoint basado en el estado de sus servicios y procesos
$bitdefenderStatus = if ($bitdefenderStatusArray -contains "Stopped" -or $bitdefenderStatusArray -contains "Not Found") { 
    "Parcial" 
} else { 
    "OK" 
}

$forcepointStatus = if ($forcepointServiceStatusArray -contains "Stopped" -or $forcepointServiceStatusArray -contains "Not Found" -or $forcepointProcessStatusArray -contains "Not Found") { 
    "Parcial" 
} else { 
    "OK" 
}

# Preparar el estado detallado para cada verificación
$estadoDetalle = @(
    "Bitdefender: " + ($bitdefenderStatusArray -join "; "),
    "Forcepoint Services: " + ($forcepointServiceStatusArray -join "; "),
    "Forcepoint Processes: " + ($forcepointProcessStatusArray -join "; "),
    "Domain: $domainStatus",
    "BitLocker: $bitlockerStatus"
) -join "; "

# Preparar el registro como un objeto personalizado para el CSV
$logEntry = [PSCustomObject]@{
    "Hostname"    = $hostname
    "Bitdefender" = $bitdefenderStatus
    "Forcepoint"  = $forcepointStatus
    "Bitlocker"   = if ($bitlockerStatus -eq "FullyEncrypted") { "OK" } else { "Check Required" }
    "Dominio"     = $domainStatus
    "Estado"      = $estadoDetalle
    "Fecha"       = $date
}

# Exportar los resultados al CSV
$logEntry | Export-Csv -Path $logFile -Append -NoTypeInformation -Force

# Restablecer la política de ejecución a su valor original
Set-ExecutionPolicy -Scope Process -ExecutionPolicy $originalExecutionPolicy -Force
