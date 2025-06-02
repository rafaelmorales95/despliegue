
# Configuración inicial
$global:logFile = "C:\Logs\forcepoint_update.log"
$global:nocodbUrl = "http://cc.nocodb.rafalan.pro/api/v2/tables/mi9zxttkpe831es/records"
$global:token = "BF4KTVGn6We-R0gc3zl0gwmMMXDVafoEdsAaGRT3"
$global:downloadDirectory = "C:\Downloads"
$global:restartFlagPath = "C:\Scripts\restart_flag.txt"
$global:scriptPath = "C:\Scripts\ForcepointUpdateProcess.ps1"
$global:taskName = "ForcepointUpdateProcess"
$global:forcepointDownloadUrl = "https://data.rafalan.pro/web/client/pubshares/5dzvKJJ2NgoeuhYceg3PWG?compress=false"
$global:expectedHash = "26FA78EBC169F103DBA43760721F635956DA43A6100609A3F1A4055B07E4F76F"
$global:PSCommandPath = $MyInvocation.MyCommand.Path

#region Funciones de Utilidad

function Initialize-Directories {
    try {
        # Verificar permisos en cada directorio
        $directories = @("C:\Logs", $global:downloadDirectory, (Split-Path $global:scriptPath -Parent))
        
        foreach ($dir in $directories) {
            if (-not (Test-Path $dir)) {
                try {
                    New-Item -Path $dir -ItemType Directory -Force | Out-Null
                    Write-Log "Directorio $dir creado"
                } catch {
                    Write-Log "ERROR: No se pudo crear el directorio $dir. Verifique permisos." "ERROR"
                    return $false
                }
            }
            
            # Verificar permisos de escritura
            try {
                $testFile = Join-Path $dir "testfile.tmp"
                [System.IO.File]::WriteAllText($testFile, "test")
                Remove-Item $testFile -Force
            } catch {
                Write-Log "ERROR: No hay permisos de escritura en $dir" "ERROR"
                return $false
            }
        }
        return $true
    } catch {
        Write-Log "ERROR al inicializar directorios: $_" "ERROR"
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
        if ($Level -eq "ERROR") { Write-Host $logMessage -ForegroundColor Red }
        elseif ($Level -eq "WARNING") { Write-Host $logMessage -ForegroundColor Yellow }
        else { Write-Host $logMessage -ForegroundColor White }
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

# Función para deshabilitar el proxy del sistema
function Disable-Proxy {
    try {
        Write-Log "Deshabilitando configuración de proxy..."
        
        # Deshabilitar proxy para el usuario actual
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f | Out-Null
        
        # Deshabilitar proxy para el sistema
        reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f | Out-Null
        
        # Configurar conexión directa
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "" /f | Out-Null
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL /t REG_SZ /d "" /f | Out-Null
        
        # También deshabilitar proxy para WinHTTP (afecta a servicios del sistema)
        netsh winhttp reset proxy | Out-Null
        
        Write-Log "Configuración de proxy deshabilitada correctamente"
        return $true
    } catch {
        Write-Log "Error al deshabilitar proxy: $_" "WARNING"
        return $false
    }
}

# Función para instalar el proveedor de NuGet
function Install-NuGetProvider {
    $retryCount = 3
    $retryDelay = 5
    for ($i = 1; $i -le $retryCount; $i++) {
        try {
            Write-Log "Intento $i de ${retryCount}: Configurando TLS 1.2..."
            # Configurar TLS 1.2 para descargas seguras
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            Write-Log "Intento $i de ${retryCount}: Instalando el proveedor de NuGet..."
            # Instalar NuGet sin preguntar al usuario
            Install-PackageProvider -Name NuGet -Force -Scope AllUsers -ErrorAction Stop
            Write-Log "Proveedor de NuGet instalado correctamente."
            return $true
        } catch {
            Write-Log "Error en el intento $i de ${retryCount}: $_"
            if ($i -lt $retryCount) {
                Start-Sleep -Seconds $retryDelay
            } else {
                Write-Log "No se pudo instalar el proveedor de NuGet después de ${retryCount} intentos. Continuando con el proceso..."
                return $false  # Devuelve false pero no detiene el script
            }
        }
    }
}

# Función para instalar el módulo PSWindowsUpdate
function Install-PSWindowsUpdateModule {
    try {
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Log "El módulo PSWindowsUpdate no está instalado. Instalándolo..."
            
            # Configurar TLS 1.2 para descargas seguras
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            
            # Verificar y configurar el repositorio PSGallery si es necesario
            if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
                Write-Log "Configurando el repositorio PSGallery..."
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
            }
            
            # Instalar el módulo
            Install-Module -Name PSWindowsUpdate -Force -Scope AllUsers -AllowClobber -ErrorAction Stop
            Write-Log "Módulo PSWindowsUpdate instalado correctamente."
        } else {
            Write-Log "El módulo PSWindowsUpdate ya está instalado."
        }
        
        # Importar el módulo
        Import-Module PSWindowsUpdate -Force -ErrorAction Stop
        Write-Log "Módulo PSWindowsUpdate importado correctamente."
        return $true
    } catch {
        Write-Log "Error al instalar/importar el módulo PSWindowsUpdate: $_" "WARNING"
        return $false
    }
}

# Función para buscar actualizaciones de Windows
function Get-WindowsUpdates {
    try {
        Write-Log "Buscando actualizaciones disponibles de Windows..."
        
        # Configurar TLS 1.2 para descargas seguras
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        # Verificar si hay actualizaciones disponibles
        $updates = Get-WUList -IsInstalled:$false -ErrorAction Stop
        
        if ($updates -and $updates.Count -gt 0) {
            Write-Log "Se encontraron $($updates.Count) actualizaciones disponibles:"
            $updates | ForEach-Object { Write-Log " - $($_.Title) (KB$($_.KB))" }
            
            # Intentar instalar actualizaciones importantes y críticas
            $importantUpdates = $updates | Where-Object { $_.IsImportant -or $_.IsCritical }
            
            if ($importantUpdates -and $importantUpdates.Count -gt 0) {
                Write-Log "Instalando $($importantUpdates.Count) actualizaciones importantes/críticas..."
                $installResult = Install-WindowsUpdate -KBArticleID $importantUpdates.KB -AcceptAll -AutoReboot:$false -IgnoreUserInput -ErrorAction Stop
                
                if ($installResult.Result -eq "Installed") {
                    Write-Log "Actualizaciones instaladas correctamente"
                    return "UpdatesInstalled"
                } else {
                    Write-Log "No se pudieron instalar todas las actualizaciones" "WARNING"
                    return "PartialUpdates"
                }
            } else {
                Write-Log "No hay actualizaciones importantes/críticas para instalar"
                return "NoCriticalUpdates"
            }
        } else {
            Write-Log "No hay actualizaciones disponibles"
            return "NoUpdates"
        }
    } catch {
        Write-Log "Error al buscar/instalar actualizaciones de Windows: $_" "WARNING"
        return "Error"
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
        $product = Get-WmiObject -Class Win32_Product | Where-Object {
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
    [CmdletBinding()]
    param()

    try {
        Write-Log "=== INICIANDO DESINSTALACIÓN DE FORCEPOINT ==="
        $success = $false
        $startTime = Get-Date
        $error.Clear()

        # 1. Verificar privilegios de administrador
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            throw "Se requieren privilegios de Administrador. Ejecute el script como administrador."
        }

        # 2. Configuración de parámetros
        $passwordPlain = 'dHGF4dRCrd|@fp35'
        Write-Log "Usando contraseña: $passwordPlain"
        
        # 3. Método MSI (Principal)
        $productCode = Get-ForcepointProductCode
        if ($productCode) {
            Write-Log "Product Code encontrado: $productCode"
            $msiLogFile = "C:\Logs\forcepoint_update.log.msi.log"
            
            # Construcción EXACTA del comando MSI como se requiere
            $msiArgs = @(
                "/X{$($productCode.Trim('{}'))}"
                "/qn"
                "XPSWDPXY=`"dHGF4dRCrd|@fp35`""
                "/norestart"
                "/l*v"
                "`"$msiLogFile`""
            )

            # Unir todos los argumentos en una sola cadena
            $fullCommand = $msiArgs -join ' '
            Write-Log "COMANDO MSI COMPLETO: [msiexec.exe $fullCommand]"

            try {
                Write-Log "Iniciando desinstalación MSI..."
                
                # Ejecutar msiexec con el comando completo como un solo argumento
                $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $fullCommand -Wait -NoNewWindow -PassThru
                
                # Códigos de éxito conocidos
                $successCodes = @(0, 1641, 3010)
                if ($successCodes -contains $process.ExitCode) {
                    Write-Log "Desinstalación MSI completada exitosamente (Código: $($process.ExitCode))"
                    $success = $true
                } else {
                    Write-Log "Desinstalación MSI falló (Código: $($process.ExitCode))" -Level Warning
                    # Log adicional para diagnóstico
                    if (Test-Path $msiLogFile) {
                        $logContent = Get-Content $msiLogFile -Tail 30 -ErrorAction SilentlyContinue
                        Write-Log "Últimas 30 líneas del log:`n$($logContent -join "`n")" -Level Debug
                    }
                }
            } catch {
                Write-Log "Error durante desinstalación MSI: $($_.Exception.Message)" -Level Error
                $error.Add($_)
            }
        } else {
            Write-Log "No se encontró el Product Code de Forcepoint" -Level Warning
        }

        # 4. Verificación final
        if ($success) {
            Write-Log "Realizando verificación post-desinstalación..."
            Start-Sleep -Seconds 15 
            
            $installedVersion = Get-ForcepointVersion
            if ($null -eq $installedVersion) {
                Write-Log "VERIFICACIÓN EXITOSA: Forcepoint ha sido desinstalado completamente"
                return $true
            } else {
                Write-Log "VERIFICACIÓN FALLIDA: Forcepoint aún parece estar instalado (Versión detectada: $installedVersion)" -Level Error
                return $false
            }
        }

        # 6. Manejo de fallos generales
        Write-Log "No se pudo completar la desinstalación de Forcepoint" -Level Error
        if ($error.Count -gt 0) {
            Write-Log "Errores encontrados:`n$($error -join "`n`n")" -Level Error
        }
        return $false

    } catch {
        Write-Log "ERROR CRÍTICO: $($_.Exception.Message)`nDetalles:$($_.ScriptStackTrace)" -Level Error
        return $false
    } finally {
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        Write-Log "Tiempo total de ejecución: $duration segundos"
    }
}

function Get-ForcepointVersion {
    try {
        $uninstallPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        $versions = $uninstallPaths | ForEach-Object {
            if (Test-Path $_) {
                Get-ItemProperty $_ | Where-Object {
                    $_.DisplayName -match 'Forcepoint|Websense' -and $_.DisplayVersion
                } | Select-Object DisplayVersion
            }
        } | Sort-Object DisplayVersion -Descending | Select-Object -First 1

        if ($versions) {
            $version = $versions.DisplayVersion
            Write-Log "Versión detectada: $version"
            return $version
        }
        
        Write-Log "No se encontró Forcepoint instalado" "INFO"
        return $null
    } catch {
        Write-Log "Error al verificar versión: $_" "ERROR"
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
            # Argumentos correctamente formateados
            $installArgs = @(
                "/S",  
                "/v`"/qn REBOOT=ReallySuppress`""  # Argumentos MSI
            )
            
            $process = Start-Process -FilePath $installerPath -ArgumentList $installArgs -Wait -NoNewWindow -PassThru
            
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
        $action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$global:scriptPath`""
        
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
            $scriptContent = [System.IO.File]::ReadAllText($global:PSCommandPath)
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
        $reportResult = Send-FinalReport -Status "PendingReboot" -Message "Preparando reinicio para instalar Forcepoint 24.11"
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

function Send-FinalReport {
    param (
        [string]$Status,
        [string]$Message,
        [string]$InitialVersion,
        [string]$FinalVersion,
        [bool]$RebootOccurred
    )
    
    try {
        # Obtener información de actualizaciones de Windows
        $windowsUpdates = Get-WindowsUpdatesStatus
        
        # Validar datos antes de enviar
        $finalMessage = if ($Message.Length -gt 2000) { $Message.Substring(0, 2000) } else { $Message }
        $osInfo = (Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture).Caption

        # Preparar resumen de actualizaciones
        $updatesSummary = @{
            PendingUpdates = $windowsUpdates.Pending
            ImportantUpdates = $windowsUpdates.Important
            LastChecked = $windowsUpdates.LastCheck
            Details = $windowsUpdates.Details | Select-Object Title, KB, IsImportant, IsCritical
        }

        $payload = @{
            FechaHora      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            Hostname       = $env:COMPUTERNAME
            Status         = $Status
            Message        = $finalMessage
            VersionInicial = if ($InitialVersion) { $InitialVersion } else { "N/A" }
            VersionFinal   = if ($FinalVersion) { $FinalVersion } else { "N/A" }
            Reinicio       = if ($RebootOccurred) { "Sí" } else { "No" }
            OSVersion      = $osInfo
            WindowsUpdates = $updatesSummary | ConvertTo-Json -Depth 3
            Ejecucion      = if ($Status -eq "Success") { "Exitosa" } else { "Fallida" }
        }

        Write-Log "Preparando reporte final para NocoDB..."
        
        # Configuración de conexión
        $headers = @{
            "xc-token"     = $global:token
            "Content-Type" = "application/json"
            "Accept"       = "application/json"
        }

        # Envío con timeout de 15 segundos
        $response = Invoke-RestMethod -Uri $global:nocodbUrl -Method Post -Headers $headers -Body ($payload | ConvertTo-Json -Depth 5) -TimeoutSec 15
        
        Write-Log "Reporte enviado correctamente (ID: $($response.Id))"
        return $true
    } catch [System.Net.WebException] {
        Write-Log "ERROR de red al enviar reporte: $($_.Exception.Message)" "ERROR"
        # Intentar guardar localmente para enviar luego
        $backupPath = "C:\Logs\FailedReports\report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        try {
            $payload | ConvertTo-Json -Depth 5 | Out-File -FilePath $backupPath -Force
            Write-Log "Reporte guardado localmente en $backupPath para reintento posterior" "WARNING"
        } catch {
            Write-Log "No se pudo guardar el reporte localmente: $($_.Exception.Message)" "ERROR"
        }
        return $false
    } catch {
        Write-Log "ERROR inesperado al enviar reporte: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Función auxiliar para obtener estado de actualizaciones
function Get-WindowsUpdatesStatus {
    try {
        Write-Log "Verificando estado de actualizaciones de Windows..."
        
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        
        # Buscar actualizaciones pendientes (no instaladas, no ocultas)
        $searchResult = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")
        
        $updates = @()
        foreach ($update in $searchResult.Updates) {
            $updates += @{
                Title = $update.Title
                KB = ($update.KBArticleIDs -join ", ")
                IsImportant = $update.IsMandatory
                IsCritical = $update.AutoSelectOnWebSites
                Categories = ($update.Categories | Select-Object -ExpandProperty Name) -join ", "
            }
        }

        $status = @{
            LastCheck = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Pending = $searchResult.Updates.Count
            Important = ($updates | Where-Object { $_.IsImportant -or $_.IsCritical }).Count
            Details = $updates
        }

        Write-Log "Estado de actualizaciones: $($status.Pending) pendientes ($($status.Important) importantes)"
        return $status
    } catch {
        Write-Log "Error al verificar actualizaciones: $($_.Exception.Message)" "WARNING"
        return @{
            LastCheck = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Error = $_.Exception.Message
            Pending = -1
            Important = -1
        }
    }
}
function Handle-FirstRun {
    # Inicialización de variables
    $initialVersion = Get-ForcepointVersion
    $targetVersion = "24.11"
    $rebootOccurred = $false
    $success = $false
    $errorMessage = $null

    try {
        Write-Log "=== INICIO DE PROCESO ==="
        Write-Log "Versión detectada inicialmente: $($initialVersion ?? 'Ninguna')"

        # Validación clave: Si ya está instalada la versión correcta
        if ($initialVersion -and $initialVersion.StartsWith($targetVersion)) {
            Write-Log "La versión $targetVersion ya está instalada (v$initialVersion). No se requiere acción."
            $success = $true
            $finalVersion = $initialVersion
        }
        else {
            # Paso 1: Desinstalación si es necesario
            if ($initialVersion -and $initialVersion -notlike "$targetVersion*") {
                Write-Log "Desinstalando versión $initialVersion..."
                if (-not (Remove-Forcepoint)) {
                    throw "Fallo en desinstalación"
                }
                
                if (Get-ForcepointVersion) {
                    $rebootOccurred = $true
                    Write-Log "Reinicio requerido para completar desinstalación"
                    Prepare-Restart
                    exit 0
                }
            }

            # Paso 2: Instalación solo si no está ya la versión correcta
            Write-Log "Instalando Forcepoint $targetVersion..."
            if (-not (Install-Forcepoint)) {
                # Si la instalación falla, preparar para reintento en próximo reinicio
                Write-Log "La instalación falló, preparando para reintento en próximo reinicio..."
                $rebootOccurred = $true
                Prepare-Restart
                exit 0
            }

            $finalVersion = Get-ForcepointVersion
            if (-not ($finalVersion -and $finalVersion.StartsWith($targetVersion))) {
                throw "La instalación no resultó en la versión esperada"
            }
            
            $success = $true
            Write-Log "Instalación completada. Versión final: $finalVersion"
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Log "ERROR CRÍTICO: $errorMessage" "ERROR"
        $finalVersion = Get-ForcepointVersion
        
        # Si hay error y no se ha preparado ya un reinicio, prepararlo
        if (-not $rebootOccurred) {
            Write-Log "Preparando reinicio para reintentar instalación..."
            Prepare-Restart
            exit 0
        }
    }
    finally {
        Send-FinalReport -Status $(if ($success) { "Success" } else { "Failed" }) `
                        -Message $(if ($success) { 
                                       if ($initialVersion.StartsWith($targetVersion)) {
                                           "Versión correcta ya instalada (v$initialVersion)"
                                       } else {
                                           "Actualización completada: $initialVersion → $finalVersion" 
                                       }
                                   } else { 
                                       "Error: $errorMessage (Estado: $initialVersion → $finalVersion). Se reintentará en próximo reinicio." 
                                   }) `
                        -InitialVersion $initialVersion `
                        -FinalVersion $finalVersion `
                        -RebootOccurred $rebootOccurred
        
        exit $(if ($success) { 0 } else { 1 })
    }
}
function Handle-PostReboot {
    # Inicialización de variables
    $success = $false
    $errorMessage = $null
    $finalVersion = $null

    try {
        Write-Log "=== EJECUCIÓN POST-REINICIO ==="
        Remove-Item -Path $global:restartFlagPath -Force -ErrorAction SilentlyContinue

        # Paso 1: Verificar si quedan restos de versión anterior
        if ($remainingVersion = Get-ForcepointVersion) {
            Write-Log "Eliminando residuos de versión $remainingVersion..."
            Remove-Forcepoint | Out-Null
        }

        # Paso 2: Instalación definitiva
        Write-Log "Instalando versión 24.11..."
        if (-not (Install-Forcepoint)) {
            throw "Fallo en instalación post-reinicio"
        }

        $finalVersion = Get-ForcepointVersion
        $success = $true
        Write-Log "Instalación post-reinicio completada. Versión: $finalVersion"

    } catch {
        $errorMessage = $_.Exception.Message
        Write-Log "ERROR POST-REINICIO: $errorMessage" "ERROR"
        $finalVersion = Get-ForcepointVersion
    } finally {
        # Reporte final unificado
        Send-FinalReport -Status $(if ($success) { "Success" } else { "Failed" }) `
                        -Message $(if ($success) { 
                                       "Instalación completada post-reinicio (Versión: $finalVersion)" 
                                   } else { 
                                       "Fallo post-reinicio: $errorMessage (Versión final: $($finalVersion ?? 'N/A'))" 
                                   }) `
                        -InitialVersion "Pre-reinicio" `
                        -FinalVersion $finalVersion `
                        -RebootOccurred $true
        
        Complete-Installation
        exit $(if ($success) { 0 } else { 1 })
    }
}
function Main {
    try {
        # Inicialización
        if (-not (Initialize-Directories)) {
            exit 1
        }
        
        Write-Log "=== INICIO DE EJECUCIÓN ==="
        Write-Log "Script: $($global:PSCommandPath)"
        Write-Log "Usuario: $($env:USERNAME)"
        Write-Log "Equipo: $($env:COMPUTERNAME)"
        
        # Verificar privilegios
        if (-not (Test-AdminPrivileges)) {
            exit 1
        }
        
        # Ejecutar funciones comunes en cada ejecución
        Write-Log "=== EJECUTANDO FUNCIONES COMUNES ==="
        
        # 1. Deshabilitar proxy
        $proxyResult = Disable-Proxy
        Write-Log "Resultado de deshabilitar proxy: $(if ($proxyResult) {'Éxito'} else {'Fallo'})"
        
        # 2. Instalar proveedor NuGet
        #$nugetResult = Install-NuGetProvider
        #Write-Log "Resultado de instalar NuGet: $(if ($nugetResult) {'Éxito'} else {'Fallo'})"
        
        # 3. Instalar módulo PSWindowsUpdate
        $moduleResult = Install-PSWindowsUpdateModule
        Write-Log "Resultado de instalar módulo: $(if ($moduleResult) {'Éxito'} else {'Fallo'})"
        
        # 4. Verificar actualizaciones de Windows
        $updateResult = Get-WindowsUpdates
        Write-Log "Resultado de verificación de actualizaciones: $updateResult"
        
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

# Ejecutar función principal
Main

