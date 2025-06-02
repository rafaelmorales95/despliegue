<#
.SYNOPSIS
    Script completo para gestionar la instalación de Forcepoint 24.11 según los requerimientos específicos
.DESCRIPTION
    Este script realiza las siguientes acciones:
    1. Verifica si Forcepoint 24.11 está instalado
    2. Si no está, desinstala cualquier versión existente
    3. Si no puede desinstalar, instala forzosamente la versión 24.11
    4. Prepara el sistema para reinicio si es necesario
    5. Después del reinicio, instala Forcepoint 24.11 desde data.rafalan.pro
    6. Reporta el estado a un servidor NocoDB
.NOTES
    Versión: 2.1
    Autor: Tu Nombre
    Fecha: $(Get-Date -Format "yyyy-MM-dd")
#>

# Configuración inicial
$global:logFile = "C:\Logs\forcepoint_update.log"
$global:nocodbUrl = "http://cc.nocodb.rafalan.pro/api/v2/tables/mqjbstu0hppfnkp/records"
$global:token = "BF4KTVGn6We-R0gc3zl0gwmMMXDVafoEdsAaGRT3"
$global:downloadDirectory = "C:\Downloads"
$global:restartFlagPath = "C:\Scripts\restart_flag.txt"
$global:scriptPath = "C:\Scripts\ForcepointUpdateProcess.ps1"
$global:taskName = "ForcepointUpdateProcess"
$global:forcepointDownloadUrl = "https://github.com/rafaelmorales95/despliegue/releases/download/forcepoint/FORCEPOINT-ONE-ENDPOINT-x64-24-11-Sin-Web-Security.exe"
$global:expectedHash = "26FA78EBC169F103DBA43760721F635956DA43A6100609A3F1A4055B07E4F76F"

#region Funciones de Utilidad

function Initialize-Directories {
    try {
        # Crear directorio de logs si no existe
        if (-not (Test-Path "C:\Logs")) {
            New-Item -Path "C:\Logs" -ItemType Directory -Force | Out-Null
            Write-Log "Directorio C:\Logs creado"
        }

        # Crear directorio de descargas si no existe
        if (-not (Test-Path $global:downloadDirectory)) {
            New-Item -Path $global:downloadDirectory -ItemType Directory -Force | Out-Null
            Write-Log "Directorio $global:downloadDirectory creado"
        }

        # Crear directorio de scripts si no existe
        if (-not (Test-Path (Split-Path $global:scriptPath -Parent))) {
            New-Item -Path (Split-Path $global:scriptPath -Parent) -ItemType Directory -Force | Out-Null
            Write-Log "Directorio $(Split-Path $global:scriptPath -Parent) creado"
        }

        return $true
    } catch {
        Write-Log "ERROR al inicializar directorios: $_"
        return $false
    }
}

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level] - $Message"
    
    try {
        Add-Content -Path $global:logFile -Value $logMessage -ErrorAction Stop
        Write-Host $logMessage -ForegroundColor $(if ($Level -eq "ERROR") { "Red" } elseif ($Level -eq "WARNING") { "Yellow" } else { "White" })
    } catch {
        Write-Host "Fallo al escribir en log: $_" -ForegroundColor Red
    }
}

function Test-AdminPrivileges {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Log "Este script requiere privilegios de administrador" "ERROR"
            return $false
        }
        Write-Log "Privilegios de administrador verificados"
        return $true
    } catch {
        Write-Log "Error al verificar privilegios: $_" "ERROR"
        return $false
    }
}

#endregion

#region Funciones de Forcepoint

function Get-ForcepointProductCode {
    try {
        # Buscar en registros de 64 bits
        $uninstallPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
        if (Test-Path $uninstallPath) {
            $items = Get-ChildItem $uninstallPath | Where-Object {
                $_.GetValue("DisplayName") -match 'Forcepoint|Websense'
            }

            foreach ($item in $items) {
                if ($item.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$') {
                    Write-Log "GUID encontrado en registro: $($item.PSChildName)"
                    return $item.PSChildName
                }
            }
        }

        # Buscar en registros de 32 bits
        $uninstallPath = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        if (Test-Path $uninstallPath) {
            $items = Get-ChildItem $uninstallPath | Where-Object {
                $_.GetValue("DisplayName") -match 'Forcepoint|Websense'
            }

            foreach ($item in $items) {
                if ($item.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$') {
                    Write-Log "GUID encontrado en registro (32 bits): $($item.PSChildName)"
                    return $item.PSChildName
                }
            }
        }

        # Buscar en WMI como último recurso
        $product = Get-CimInstance -ClassName Win32_Product | Where-Object {
            $_.Name -match 'Forcepoint|Websense'
        } | Select-Object -First 1

        if ($product) {
            Write-Log "GUID encontrado via WMI: $($product.IdentifyingNumber)"
            return $product.IdentifyingNumber
        }

        Write-Log "No se encontró GUID del producto" -Level WARNING
        return $null
    } catch {
        Write-Log "Error al buscar GUID: $_" -Level WARNING
        return $null
    }
}

function Remove-Forcepoint {
    try {
        Write-Log "=== INICIANDO DESINSTALACIÓN DE FORCEPOINT ==="
        $success = $false
        $startTime = Get-Date

        # Codificar la contraseña en Base64
        $passwordPlain = 'dHGF4dRCrd|@fp35'
        $passwordBytes = [System.Text.Encoding]::Unicode.GetBytes($passwordPlain)
        $passwordEncoded = [Convert]::ToBase64String($passwordBytes)
        Write-Log "Contraseña codificada en Base64: $passwordEncoded"

        # 1. Método MSI con GUID
        $productCode = Get-ForcepointProductCode
        if ($productCode) {
            Write-Log "Intentando desinstalación MSI..."
            $msiLogFile = "$($global:logFile).msi.log"
            $msiArgs = @(
                "/X$productCode",
                "/qn",
                "XPSWDPXY=$passwordEncoded",
                "/norestart",
                "/l*v",
                "`"$msiLogFile`""
            )

            try {
                $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -NoNewWindow -PassThru
                $successCodes = @(0, 1641, 3010)
                if ($process.ExitCode -in $successCodes) {
                    Write-Log "Desinstalación MSI completada"
                    $success = $true
                } else {
                    Write-Log "Desinstalación MSI falló (Código: $($process.ExitCode))" "WARNING"
                }
            } catch {
                Write-Log "Error en desinstalación MSI: $_" "ERROR"
            }
        }

        # 2. Método nativo
        if (-not $success) {
            $nativeUninstaller = Join-Path -Path $env:ProgramFiles -ChildPath "Websense\Websense Endpoint\uninstall.exe"
            if (Test-Path $nativeUninstaller) {
                try {
                    $process = Start-Process -FilePath $nativeUninstaller -ArgumentList "/S", "/XPSWDPXY=$passwordEncoded" -Wait -NoNewWindow -PassThru
                    if ($process.ExitCode -eq 0) {
                        Write-Log "Desinstalación nativa completada"
                        $success = $true
                    }
                } catch {
                    Write-Log "Error en desinstalación nativa: $_" "ERROR"
                }
            }
        }

        # Verificación final
        if ($success) {
            Start-Sleep -Seconds 10
            if ($null -eq (Get-ForcepointVersion)) {
                Write-Log "Forcepoint desinstalado correctamente"
                return $true
            }
        }
        
        Write-Log "No se pudo desinstalar Forcepoint" "ERROR"
        return $false
        
    } catch {
        Write-Log "Error fatal: $_" "ERROR"
        return $false
    } finally {
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        Write-Log "Tiempo total: $duration segundos"
    }
}

function Get-ForcepointVersion {
    try {
        $uninstallPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $forcepointEntry = Get-ItemProperty $uninstallPath | Where-Object {
            $_.DisplayName -match "Forcepoint|Websense"
        } | Select-Object -First 1

        if ($forcepointEntry) {
            return $forcepointEntry.DisplayVersion
        }
        return $null
    } catch {
        Write-Log "Error al obtener versión de Forcepoint: $_" "ERROR"
        return $null
    }
}

function Get-ForcepointInstaller {
    try {
        $installerPath = "$global:downloadDirectory\FORCEPOINT-ONE-ENDPOINT-24.11.exe"
        
        # Verificar si ya existe un instalador válido
        if (Test-Path $installerPath) {
            Write-Log "Verificando instalador existente..."
            $fileHash = (Get-FileHash -Path $installerPath -Algorithm SHA256).Hash
            if ($fileHash -eq $global:expectedHash) {
                Write-Log "Instalador existente es válido"
                return $installerPath
            } else {
                Write-Log "Instalador existente no es válido (Hash: $fileHash)" "WARNING"
                Remove-Item -Path $installerPath -Force
            }
        }
        
        # Descargar nuevo instalador
        Write-Log "Descargando instalador desde $global:forcepointDownloadUrl..."
        try {
            $progressPreference = 'silentlyContinue'
            Invoke-WebRequest -Uri $global:forcepointDownloadUrl -OutFile $installerPath -ErrorAction Stop
            
            # Verificar hash
            $fileHash = (Get-FileHash -Path $installerPath -Algorithm SHA256).Hash
            if ($fileHash -ne $global:expectedHash) {
                Write-Log "ERROR: Hash no coincide. Esperado: $global:expectedHash, Obtenido: $fileHash" "ERROR"
                Remove-Item -Path $installerPath -Force
                return $null
            }
            
            Write-Log "Instalador descargado y verificado correctamente"
            return $installerPath
        } catch {
            Write-Log "Error al descargar instalador: $_" "ERROR"
            return $null
        }
    } catch {
        Write-Log "Error en Get-ForcepointInstaller: $_" "ERROR"
        return $null
    }
}

function Install-Forcepoint {
    try {
        $installerPath = Get-ForcepointInstaller
        if (-not $installerPath) {
            Write-Log "No se pudo obtener el instalador" "ERROR"
            return $false
        }
        
        Write-Log "Iniciando instalación de Forcepoint 24.11..."
        try {
            # Usa comillas escapadas o simples
            $process = Start-Process -FilePath $installerPath -ArgumentList "/v`"/qn /norestart`"" -Wait -NoNewWindow -PassThru
            
            if ($process.ExitCode -eq 0) {
                Start-Sleep -Seconds 15
                $installedVersion = Get-ForcepointVersion
                if ($installedVersion -like "24.11*") {
                    Write-Log "Forcepoint 24.11 instalado correctamente"
                    return $true
                } else {
                    Write-Log "ERROR: La versión instalada no es 24.11 ($installedVersion)" "ERROR"
                    return $false
                }
            } else {
                Write-Log "ERROR: Instalación falló con código $($process.ExitCode)" "ERROR"
                return $false
            }
        } catch {
            Write-Log "Error durante la instalación: $_" "ERROR"
            return $false
        }
    } catch {
        Write-Log "Error en Install-Forcepoint: $_" "ERROR"
        return $false
    }
}

function Force-Install-Forcepoint {
    try {
        Write-Log "=== INICIANDO INSTALACIÓN FORZOSA DE FORCEPOINT 24.11 ==="
        
        # 1. Detener procesos relacionados con Forcepoint
        try {
            Get-Process -Name "wssc*, wsm*" -ErrorAction SilentlyContinue | Stop-Process -Force
            Write-Log "Procesos de Forcepoint detenidos"
        } catch {
            Write-Log "No se pudieron detener todos los procesos de Forcepoint: $_" "WARNING"
        }
        
        # 2. Instalar la nueva versión
        $installResult = Install-Forcepoint
        
        if ($installResult) {
            Write-Log "Instalación forzosa completada con éxito"
            return $true
        }
        
        Write-Log "Fallo en la instalación forzosa" "ERROR"
        return $false
    } catch {
        Write-Log "Error en Force-Install-Forcepoint: $_" "ERROR"
        return $false
    }
}

#endregion

#region Funciones de Reinicio y Tareas

function Register-UpdateTask {
    try {
        Write-Log "Configurando tarea programada..."
        
        # Eliminar tarea existente si existe
        if (Get-ScheduledTask -TaskName $global:taskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $global:taskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "Tarea existente eliminada"
        }
        
        # Crear acción
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$global:scriptPath`""
        
        # Crear trigger (al inicio con retraso)
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $trigger.Delay = "PT1M"
        
        # Configuración de la tarea
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -RunOnlyIfNetworkAvailable `
            -WakeToRun
        
        # Registrar tarea
        Register-ScheduledTask `
            -TaskName $global:taskName `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -RunLevel "Highest" `
            -Force | Out-Null
        
        Write-Log "Tarea programada creada correctamente"
        return $true
    } catch {
        Write-Log "Error al crear tarea programada: $_" "ERROR"
        return $false
    }
}

function Prepare-Restart {
    try {
        Write-Log "Preparando sistema para reinicio..."
        
        # Crear bandera de reinicio
        Set-Content -Path $global:restartFlagPath -Value "1" -Force
        
        # Clonar script
        try {
            $scriptContent = [System.IO.File]::ReadAllText($PSCommandPath)
            [System.IO.File]::WriteAllText($global:scriptPath, $scriptContent)
            Write-Log "Script clonado en $global:scriptPath"
        } catch {
            Write-Log "Error al clonar el script: $_" "ERROR"
            return $false
        }
        
        # Registrar tarea programada
        if (-not (Register-UpdateTask)) {
            return $false
        }
        
        # Reportar estado antes del reinicio
        $reportResult = Send-Report -Status "PendingReboot" -Message "Preparando reinicio para instalar Forcepoint 24.11"
        if (-not $reportResult) {
            Write-Log "Advertencia: No se pudo enviar reporte" "WARNING"
        }
        
        Write-Log "Reinicio programado en 60 segundos..."
        Start-Sleep -Seconds 60
        
        # Reiniciar sistema
        Write-Log "Iniciando reinicio..."
        Restart-Computer -Force
        return $true
    } catch {
        Write-Log "Error en Prepare-Restart: $_" "ERROR"
        return $false
    }
}

function Complete-Installation {
    try {
        Write-Log "Completando instalación..."
        
        # Eliminar tarea programada
        if (Get-ScheduledTask -TaskName $global:taskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $global:taskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "Tarea programada eliminada"
        }
        
        # Eliminar script clonado
        if (Test-Path $global:scriptPath) {
            Remove-Item -Path $global:scriptPath -Force -ErrorAction SilentlyContinue
            Write-Log "Script clonado eliminado"
        }
        
        # Eliminar bandera de reinicio
        if (Test-Path $global:restartFlagPath) {
            Remove-Item -Path $global:restartFlagPath -Force -ErrorAction SilentlyContinue
            Write-Log "Bandera de reinicio eliminada"
        }
        
        return $true
    } catch {
        Write-Log "Error en Complete-Installation: $_" "WARNING"
        return $false
    }
}

#endregion

#region Funciones de Reporte

function Send-Report {
    param (
        [string]$Status,
        [string]$Message,
        [string]$VersionBefore = "",
        [string]$VersionAfter = ""
    )
    
    try {
        $payload = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Hostname = $env:COMPUTERNAME
            Status = $Status
            Message = $Message
            VersionBefore = $VersionBefore
            VersionAfter = $VersionAfter
            OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
        } | ConvertTo-Json -Depth 3

        Write-Log "Enviando reporte a NocoDB..."
        $headers = @{
            "xc-token" = $global:token
            "Content-Type" = "application/json"
        }
        
        $response = Invoke-RestMethod -Uri $global:nocodbUrl -Method Post -Headers $headers -Body $payload
        Write-Log "Reporte enviado correctamente"
        return $true
    } catch {
        Write-Log "Error al enviar reporte: $_" "WARNING"
        return $false
    }
}

#endregion

#region Función Principal

function Main {
    try {
        # Inicialización
        if (-not (Initialize-Directories)) {
            exit 1
        }
        
        Write-Log "=== INICIO DE EJECUCIÓN ==="
        Write-Log "Script: $($PSCommandPath)"
        Write-Log "Usuario: $($env:USERNAME)"
        Write-Log "Equipo: $($env:COMPUTERNAME)"
        
        # Verificar privilegios
        if (-not (Test-AdminPrivileges)) {
            exit 1
        }
        
        # Verificar si es ejecución post-reinicio
        if (Test-Path $global:restartFlagPath) {
            Handle-PostReboot
        } else {
            Handle-FirstRun
        }
    }
    catch {
        Write-Log "ERROR CRÍTICO: $_" "ERROR"
        exit 1
    }
}

function Handle-PostReboot {
    try {
        Write-Log "=== MODO POST-REINICIO ==="
        Remove-Item -Path $global:restartFlagPath -Force -ErrorAction SilentlyContinue
        
        $currentVersion = Get-ForcepointVersion
        $installResult = Install-Forcepoint
        
        $status = if ($installResult) { "Success" } else { "Failed" }
        $message = if ($installResult) { "Forcepoint 24.11 instalado correctamente" } else { "Fallo en la instalación" }
        
        Send-Report -Status $status -Message $message -VersionBefore "Desinstalado" -VersionAfter $currentVersion
        Complete-Installation
        
        exit $(if ($installResult) { 0 } else { 1 })
    } catch {
        Write-Log "ERROR en Handle-PostReboot: $_" "ERROR"
        exit 1
    }
}

function Handle-FirstRun {
    try {
        Write-Log "=== PRIMERA EJECUCIÓN ==="
        
        # Verificar versión actual
        $currentVersion = Get-ForcepointVersion
        
        if ($currentVersion -like "24.11*") {
            Write-Log "Forcepoint 24.11 ya está instalado. No se requiere acción."
            Send-Report -Status "Success" -Message "Forcepoint 24.11 ya estaba instalado" -VersionBefore $currentVersion -VersionAfter $currentVersion
            return
        }
        
        # Desinstalar versiones existentes
        if ($currentVersion) {
            Write-Log "Desinstalando versión $currentVersion..."
            $uninstallResult = Remove-Forcepoint
            
            if (-not $uninstallResult) {
                Write-Log "No se pudo desinstalar Forcepoint existente, intentando instalación forzosa..." "WARNING"
                
                # Intentar instalación forzosa
                $forceInstallResult = Force-Install-Forcepoint
                
                if ($forceInstallResult) {
                    $newVersion = Get-ForcepointVersion
                    Send-Report -Status "Success" -Message "Instalación forzosa completada" -VersionBefore $currentVersion -VersionAfter $newVersion
                    exit 0
                } else {
                    Send-Report -Status "Failed" -Message "Fallo en desinstalación e instalación forzosa" -VersionBefore $currentVersion
                    exit 1
                }
            }
        }
        
        # Preparar reinicio
        if (-not (Prepare-Restart)) {
            exit 1
        }
    }
    catch {
        Write-Log "ERROR en Handle-FirstRun: $_" "ERROR"
        exit 1
    }
}

#endregion

# Ejecutar función principal
Main
