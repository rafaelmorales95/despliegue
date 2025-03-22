# Configuración inicial
$logFile = "C:\Logs\update_log.txt"
$nocodbUrl = "http://cc.nocodb.rafalan.pro/api/v2/tables/mqjbstu0hppfnkp/records"
$token = "BF4KTVGn6We-R0gc3zl0gwmMMXDVafoEdsAaGRT3"
$downloadDirectory = "C:\Downloads"
$installerUrl = "https://www.mediafire.com/file/i125zhajsluh2at/FORCEPOINT-ONE-ENDPOINT-x64_Windows11.exe/file"
$installerName = "FORCEPOINT-ONE-ENDPOINT-x64_Windows11.exe"
$installerPath = "$downloadDirectory\$installerName"
$scriptPath = "C:\Scripts\Disable-Proxy.ps1"  # Ruta del script de desbloqueo
$taskName = "DisableProxyAfterReboot"        # Nombre de la tarea programada

# Crear directorios si no existen
if (-not (Test-Path "C:\Logs")) {
    New-Item -Path "C:\Logs" -ItemType Directory
}

if (-not (Test-Path $downloadDirectory)) {
    New-Item -Path $downloadDirectory -ItemType Directory
}

if (-not (Test-Path "C:\Scripts")) {
    New-Item -Path "C:\Scripts" -ItemType Directory
}

# Función para escribir en el log
function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    Add-Content -Path $logFile -Value $logMessage
}

# Función para obtener la versión actual de Forcepoint
function Get-ForcepointVersion {
    try {
        # Ruta donde se encuentra el ejecutable de Forcepoint
        $forcepointPath = "C:\Program Files\Websense\Websense Endpoint\F1EUI.exe"
        if (Test-Path $forcepointPath) {
            $versionInfo = (Get-Item $forcepointPath).VersionInfo
            return $versionInfo.ProductVersion
        } else {
            Write-Log "Forcepoint no está instalado o la ruta es incorrecta."
            return $null
        }
    } catch {
        Write-Log "Error al obtener la versión de Forcepoint: $_"
        return $null
    }
}

# Función para descargar el instalador (si no existe)
function Download-Installer {
    if (Test-Path $installerPath) {
        Write-Log "El instalador ya existe en $installerPath. No es necesario descargarlo."
        return $installerPath
    }

    try {
        Write-Log "Descargando el instalador de Forcepoint..."
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -ErrorAction Stop
        Write-Log "Instalador descargado correctamente en $installerPath."
        return $installerPath
    } catch {
        Write-Log "Error al descargar el instalador: $_"
        return $null
    }
}

# Función para instalar el paquete de Forcepoint en modo silencioso sin reinicio
function Install-Forcepoint {
    param (
        [string]$InstallerPath
    )
    try {
        Write-Log "Instalando el paquete de Forcepoint en modo silencioso sin reinicio..."
        $process = Start-Process -FilePath $InstallerPath -ArgumentList '/v"/qn /norestart"' -Wait -NoNewWindow -PassThru
        if ($process.ExitCode -eq 0) {
            Write-Log "Paquete de Forcepoint instalado correctamente."
            return $true
        } else {
            Write-Log "Error durante la instalación. Código de salida: $($process.ExitCode)"
            return $false
        }
    } catch {
        Write-Log "Error al instalar el paquete de Forcepoint: $_"
        return $false
    }
}

# Función para deshabilitar el proxy y el script de configuración automática (PAC)
function Disable-Proxy {
    try {
        Write-Log "Intentando deshabilitar el proxy..."

        # Ruta de la configuración del proxy en el registro
        $proxySettingsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

        # Verificar si la clave del proxy existe
        if (-not (Test-Path $proxySettingsPath)) {
            Write-Log "La clave del registro para la configuración del proxy no existe."
            return $false
        }

        # Obtener la configuración actual del proxy
        $proxySettings = Get-ItemProperty -Path $proxySettingsPath -Name ProxyEnable, AutoConfigURL -ErrorAction SilentlyContinue

        # Mostrar la configuración actual del proxy
        Write-Log "Configuración actual del proxy:"
        Write-Log "  ProxyEnable: $($proxySettings.ProxyEnable)"
        Write-Log "  AutoConfigURL: $($proxySettings.AutoConfigURL)"

        # Verificar si el proxy está habilitado
        if ($proxySettings.ProxyEnable -eq 1 -or -not [string]::IsNullOrEmpty($proxySettings.AutoConfigURL)) {
            Write-Log "El proxy está habilitado. Deshabilitando..."

            # Deshabilitar el proxy
            Set-ItemProperty -Path $proxySettingsPath -Name ProxyEnable -Value 0

            # Deshabilitar el script de configuración automática (PAC)
            Set-ItemProperty -Path $proxySettingsPath -Name AutoConfigURL -Value ""

            # Verificar explícitamente si el proxy y el PAC se desactivaron correctamente
            $proxySettingsAfter = Get-ItemProperty -Path $proxySettingsPath -Name ProxyEnable, AutoConfigURL -ErrorAction SilentlyContinue
            Write-Log "Configuración del proxy después de la desactivación:"
            Write-Log "  ProxyEnable: $($proxySettingsAfter.ProxyEnable)"
            Write-Log "  AutoConfigURL: $($proxySettingsAfter.AutoConfigURL)"

            if ($proxySettingsAfter.ProxyEnable -eq 0 -and [string]::IsNullOrEmpty($proxySettingsAfter.AutoConfigURL)) {
                Write-Log "Proxy y PAC deshabilitados correctamente."
                return $true
            } else {
                Write-Log "Error: No se pudo deshabilitar el proxy o el PAC."
                return $false
            }
        } else {
            Write-Log "El proxy ya está deshabilitado. No es necesario realizar cambios."
            return $true
        }
    } catch {
        Write-Log "Error al deshabilitar el proxy: $_"
        return $false
    }
}

# Función para crear el script de desbloqueo del proxy
function Create-DisableProxyScript {
    param (
        [string]$ScriptPath,
        [string]$PreviousVersion
    )
    try {
        Write-Log "Creando el script de desbloqueo del proxy en $ScriptPath..."

        # Contenido del script de desbloqueo
        $scriptContent = @"
# Configuración inicial
`$logFile = "C:\Logs\update_log.txt"
`$nocodbUrl = "http://cc.nocodb.rafalan.pro/api/v2/tables/mqjbstu0hppfnkp/records"
`$token = "BF4KTVGn6We-R0gc3zl0gwmMMXDVafoEdsAaGRT3"
`$downloadDirectory = "C:\Downloads"

# Crear directorios si no existen
if (-not (Test-Path "C:\Logs")) {
    New-Item -Path "C:\Logs" -ItemType Directory
}

if (-not (Test-Path `$downloadDirectory)) {
    New-Item -Path `$downloadDirectory -ItemType Directory
}

# Función para escribir en el log
function Write-Log {
    param ([string]`$Message)
    `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    `$logMessage = "`$timestamp - `$Message"
    Add-Content -Path `$logFile -Value `$logMessage
}

# Función para deshabilitar el proxy
function Disable-Proxy {
    try {
        Write-Log "Intentando deshabilitar el proxy..."

        # Ruta de la configuración del proxy en el registro
        `$proxySettingsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

        # Verificar si la clave del proxy existe
        if (-not (Test-Path `$proxySettingsPath)) {
            Write-Log "La clave del registro para la configuración del proxy no existe."
            return `$false
        }

        # Obtener la configuración actual del proxy
        `$proxySettings = Get-ItemProperty -Path `$proxySettingsPath -Name ProxyEnable, AutoConfigURL -ErrorAction SilentlyContinue

        # Mostrar la configuración actual del proxy
        Write-Log "Configuración actual del proxy:"
        Write-Log "  ProxyEnable: `$(`$proxySettings.ProxyEnable)"
        Write-Log "  AutoConfigURL: `$(`$proxySettings.AutoConfigURL)"

        # Deshabilitar el proxy
        Write-Log "Deshabilitando el proxy..."
        Set-ItemProperty -Path `$proxySettingsPath -Name ProxyEnable -Value 0

        # Deshabilitar el script de configuración automática (PAC)
        Write-Log "Deshabilitando el script de configuración automática (PAC)..."
        Set-ItemProperty -Path `$proxySettingsPath -Name AutoConfigURL -Value ""

        # Verificar explícitamente si el proxy y el PAC se desactivaron correctamente
        `$proxySettingsAfter = Get-ItemProperty -Path `$proxySettingsPath -Name ProxyEnable, AutoConfigURL -ErrorAction SilentlyContinue
        Write-Log "Configuración del proxy después de la desactivación:"
        Write-Log "  ProxyEnable: `$(`$proxySettingsAfter.ProxyEnable)"
        Write-Log "  AutoConfigURL: `$(`$proxySettingsAfter.AutoConfigURL)"

        if (`$proxySettingsAfter.ProxyEnable -eq 0 -and [string]::IsNullOrEmpty(`$proxySettingsAfter.AutoConfigURL)) {
            Write-Log "Proxy y PAC deshabilitados correctamente."
            return `$true
        } else {
            Write-Log "Error: No se pudo deshabilitar el proxy o el PAC."
            return `$false
        }
    } catch {
        Write-Log "Error al deshabilitar el proxy: `$_"
        return `$false
    }
}

# Función principal para ejecutar el proceso
function Start-WindowsUpdateProcess {
    Write-Log "Inicio del proceso de actualización"

    # Deshabilitar el proxy
    `$proxyDisabled = Disable-Proxy

    if (-not `$proxyDisabled) {
        Write-Log "No se pudo deshabilitar el proxy. Abortando el proceso."
        exit 1
    }

    Write-Log "Proceso completado. El proxy se ha deshabilitado correctamente."
}

# Llamada a la función principal para iniciar el proceso
Start-WindowsUpdateProcess
"@

        # Crear el archivo del script
        Set-Content -Path $ScriptPath -Value $scriptContent
        Write-Log "Script de desbloqueo del proxy creado correctamente en $ScriptPath."
        return $true
    } catch {
        Write-Log "Error al crear el script de desbloqueo del proxy: $_"
        return $false
    }
}

# Función para crear una tarea programada que se ejecute después del reinicio
function Create-ScheduledTask {
    param (
        [string]$ScriptPath,
        [string]$TaskName
    )
    try {
        Write-Log "Creando tarea programada para desbloquear el proxy después del reinicio..."

        # Crear la tarea programada
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$ScriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest

        Write-Log "Tarea programada creada correctamente."
        return $true
    } catch {
        Write-Log "Error al crear la tarea programada: $_"
        return $false
    }
}

# Función para enviar datos a NocoDB
function Upload-ToNocoDB {
    param (
        [string]$Timestamp,
        [string]$Hostname,
        [string]$Status,
        [string]$Description,
        [string]$ProxyDisabled
    )

    if (-not $token) {
        Write-Log "Error: Token de NocoDB vacío. Verifica la configuración."
        return
    }

    $payload = @{
        Timestamp = $Timestamp
        Hostname = $Hostname
        Status = $Status
        Description = $Description
        ProxyDisabled = $ProxyDisabled
    } | ConvertTo-Json

    Write-Log "Enviando el siguiente payload a NocoDB: $payload"

    try {
        $response = Invoke-RestMethod -Uri $nocodbUrl -Method Post -Headers @{ "xc-token" = $token } -Body $payload -ContentType "application/json"

        if ($response) {
            Write-Log "Datos subidos exitosamente a NocoDB."
        } else {
            Write-Log "Error: No se recibió respuesta de NocoDB."
        }
    } catch {
        Write-Log "Error al intentar enviar los datos a NocoDB: $_"
    }
}

# Función principal para ejecutar el proceso
function Start-UpdateProcess {
    Write-Log "Inicio del proceso de actualización"

    # Obtener información del sistema
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $hostname = $env:COMPUTERNAME

    # Obtener la versión actual de Forcepoint
    $previousVersion = Get-ForcepointVersion
    if ($previousVersion) {
        Write-Log "Versión actual de Forcepoint: $previousVersion"
        
        # Verificar si la versión actual es la 25.03.5710
        if ($previousVersion -eq "25.03.5710") {
            Write-Log "La versión actual de Forcepoint es la 25.03.5710, no es necesario actualizar."
        } else {
            # Descargar el instalador (si no existe)
            $installerPath = Download-Installer
            if (-not $installerPath) {
                Write-Log "No se pudo descargar el instalador. Abortando el proceso."
                exit 1
            }

            # Instalar el paquete de Forcepoint en modo silencioso sin reinicio
            $installationSuccess = Install-Forcepoint -InstallerPath $installerPath
            if (-not $installationSuccess) {
                Write-Log "No se pudo instalar el paquete de Forcepoint. Abortando el proceso."
                exit 1
            }
        }
    } else {
        Write-Log "No se pudo obtener la versión actual de Forcepoint."
    }

    # Deshabilitar el proxy si está habilitado
    $proxyDisabled = Disable-Proxy
    if (-not $proxyDisabled) {
        Write-Log "No se pudo deshabilitar el proxy. Abortando el proceso."
        exit 1
    }

    # Crear el script de desbloqueo del proxy
    $scriptCreated = Create-DisableProxyScript -ScriptPath $scriptPath -PreviousVersion $previousVersion
    if (-not $scriptCreated) {
        Write-Log "No se pudo crear el script de desbloqueo del proxy. Abortando el proceso."
        exit 1
    }

    # Crear una tarea programada para ejecutar el script después del reinicio
    $taskCreated = Create-ScheduledTask -ScriptPath $scriptPath -TaskName $taskName
    if (-not $taskCreated) {
        Write-Log "No se pudo crear la tarea programada. Abortando el proceso."
        exit 1
    }

    # Enviar datos a NocoDB
    $status = if ($proxyDisabled) { "Success" } else { "Error" }
    $proxyDisabledStatus = if ($proxyDisabled) { "Yes" } else { "No" }
    Upload-ToNocoDB -Timestamp $timestamp `
                    -Hostname $hostname `
                    -Status $status `
                    -Description "Proceso de actualización y desactivación del proxy completado." `
                    -ProxyDisabled $proxyDisabledStatus

    Write-Log "Proceso completado. El proxy se ha deshabilitado correctamente."
    exit 0
}

# Llamada a la función principal para iniciar el proceso
Start-UpdateProcess