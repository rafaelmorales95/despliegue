# Configuración inicial
$logFile = "C:\Logs\update_log.txt"
$nocodbUrl = "http://cc.nocodb.rafalan.pro/api/v2/tables/mqjbstu0hppfnkp/records"
$token = "BF4KTVGn6We-R0gc3zl0gwmMMXDVafoEdsAaGRT3"
$downloadDirectory = "C:\Downloads"
$restartFlagPath = "C:\Scripts\restart_flag.txt"
$scriptPath = "C:\Scripts\WindowsUpdateProcess.ps1" 
$taskName = "WindowsUpdateProcess-BT"

# Crear directorios si no existen
if (-not (Test-Path "C:\Logs")) {
    New-Item -Path "C:\Logs" -ItemType Directory -Force
}

if (-not (Test-Path $downloadDirectory)) {
    New-Item -Path $downloadDirectory -ItemType Directory -Force
}

# Función para escribir en el log
function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    Add-Content -Path $logFile -Value $logMessage
}

# Función para descargar archivos
function Download-File {
    param (
        [string]$Url,
        [string]$Destination
    )
    if (Test-Path $Destination) {
        Write-Log "El archivo ya existe en $Destination. No es necesario descargarlo."
        return $true
    }
    Write-Log "Descargando archivo desde $Url a $Destination..."
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -ErrorAction Stop
        Write-Log "Descarga completada: $Destination"
        return $true
    } catch {
        Write-Log "Error al descargar el archivo: $_"
        return $false
    }
}


# Función para escribir en el log
function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    Add-Content -Path $logFile -Value $logMessage
}

# Función para crear una tarea programada
# Función para crear una tarea programada
function Create-ScheduledTask {
    try {
        Write-Log "Creando la tarea programada '$taskName'..."

        # Configurar la acción de la tarea
        $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Unrestricted -File `"$scriptPath`""
        
        # Configurar el desencadenador para ejecutar al inicio con un retraso de 30 segundos
        $taskTrigger = New-ScheduledTaskTrigger -AtStartup
        $taskTrigger.Delay = "PT30S"  # Retraso de 30 segundos

        # Configurar el principal (usuario y privilegios)
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest

        # Configurar las opciones de la tarea
        $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

        # Verificar si la tarea ya existe
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            Write-Log "La tarea programada '$taskName' ya existe. No es necesario crearla."
            return $true
        }

        # Crear la tarea programada
        Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings
        Write-Log "Tarea programada '$taskName' creada correctamente."
        return $true
    } catch {
        Write-Log "Error al crear la tarea programada: $_"
        return $false
    }
}

# Función para clonar el script actual
function Clone-Script {
    try {
        Write-Log "Clonando el script actual en $scriptPath..."

        # Crear el directorio si no existe
        $scriptDirectory = Split-Path -Path $scriptPath -Parent
        if (-not (Test-Path $scriptDirectory)) {
            New-Item -Path $scriptDirectory -ItemType Directory -Force | Out-Null
        }

        # Obtener la ruta del script actual
        $scriptCurrentPath = $PSCommandPath

        # Leer el contenido del script actual como una sola cadena (compatible con todas las versiones de PowerShell)
        $scriptContent = Get-Content -Path $scriptCurrentPath | Out-String
        Set-Content -Path $scriptPath -Value $scriptContent -Force
        Write-Log "Script clonado correctamente en $scriptPath."
        return $true
    } catch {
        Write-Log "Error al clonar el script: $_"
        return $false
    }
}

# Función para esperar 3 minutos antes de reiniciar
function Wait-BeforeRestart {
    $waitTime = 15  # 3 minutos en segundos
    Write-Log "Esperando $($waitTime / 60) minutos antes de reiniciar..."
    Start-Sleep -Seconds $waitTime
}

# Verificar si el script se está ejecutando después de un reinicio
if (Test-Path $restartFlagPath) {
    Write-Log "El script se está ejecutando después de un reinicio."
    Remove-Item -Path $restartFlagPath -Force  # Eliminar la bandera después de usarla
} else {
    Write-Log "El script se está ejecutando por primera vez. Preparando el reinicio..."
    
    # Crear la bandera para indicar que se debe ejecutar después del reinicio
    Set-Content -Path $restartFlagPath -Value "Reinicio pendiente"

    # Clonar el script actual
    $scriptCloned = Clone-Script

    if ($scriptCloned) {
        # Crear la tarea programada
        $taskCreated = Create-ScheduledTask

        if ($taskCreated) {
            Write-Log "La tarea programada se creó correctamente. Preparando el reinicio..."
            Wait-BeforeRestart
            Write-Log "Reiniciando el sistema..."
            #Restart-Computer -Force
        } else {
            Write-Log "No se pudo crear la tarea programada. Abortando el proceso."
            exit 1
        }
    } else {
        Write-Log "No se pudo clonar el script. Abortando el proceso."
        exit 1
    }
}
# Función para verificar privilegios de administrador
function Check-AdminPrivileges {
    $adminCheck = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $adminCheck.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "Este script debe ejecutarse como administrador."
        exit 1
    } else {
        Write-Log "El script se ejecutó como administrador."
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
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-Log "El módulo PSWindowsUpdate no está instalado. Instalándolo..."
        try {
            if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
                Write-Log "Registrando el repositorio PSGallery..."
                Register-PSRepository -Default
            }
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
            Write-Log "Módulo PSWindowsUpdate instalado correctamente."
        } catch {
            Write-Log "Error al instalar el módulo PSWindowsUpdate: $_"
            return $false
        }
    } else {
        Write-Log "El módulo PSWindowsUpdate ya está instalado."
    }
    Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
    return $true
}

# Función para buscar actualizaciones de Windows
function Get-WindowsUpdates {
    Write-Log "Buscando actualizaciones disponibles..."
    try {
        $updates = Get-WindowsUpdate -ErrorAction Stop
        if ($updates) {
            Write-Log "Se encontraron actualizaciones disponibles:"
            $updates | ForEach-Object { Write-Log " - $($_.Title)" }
            return "UpdatesInstalled"
        } else {
            Write-Log "No hay actualizaciones disponibles."
            return "NoUpdates"
        }
    } catch {
        Write-Log "Error al buscar actualizaciones: $_"
        return "Error"
    }
}

# Configuración de URLs de descarga para JRE y JDK
$javaJreUrl = "https://javadl.oracle.com/webapps/download/AutoDL?BundleId=251656_7ed26d28139143f38c58992680c214a5"
$javaJdkUrl = "https://download.oracle.com/java/24/latest/jdk-24_windows-x64_bin.msi"

# Función mejorada para verificar Java instalado
function Check-JavaInstalled {
    $javaPaths = @(
        "${env:ProgramFiles}\Java\*",
        "${env:ProgramFiles(x86)}\Java\*"
    )
    
    $result = @{
        JRE = @{
            Version = $null
            Path = $null
            IsInstalled = $false
            Executable = $null
        }
        JDK = @{
            Version = $null
            Path = $null
            IsInstalled = $false
            Executable = $null
        }
    }

    foreach ($path in $javaPaths) {
        if (Test-Path $path) {
            try {
                # Obtener todas las carpetas de Java, excluyendo enlaces simbólicos
                $javaFolders = Get-ChildItem -Path $path -Directory | Where-Object { 
                    $_.LinkType -ne "SymbolicLink" -and $_.Name -match "jre|jdk"
                }

                foreach ($folder in $javaFolders) {
                    # Detectar JRE (java.exe en la raíz de la carpeta JRE)
                    if ($folder.Name -match "jre" -and -not $result.JRE.IsInstalled) {
                        $javaExePath = Join-Path -Path $folder.FullName -ChildPath "bin\java.exe"
                        if (Test-Path $javaExePath) {
                            $javaVersion = & "$javaExePath" -version 2>&1 | 
                                          Select-String -Pattern "version" | 
                                          ForEach-Object { $_.ToString().Split()[2].Trim('"') }
                            
                            $result.JRE.Version = $javaVersion
                            $result.JRE.Path = $folder.FullName
                            $result.JRE.IsInstalled = $true
                            $result.JRE.Executable = $javaExePath
                            Write-Log "JRE detectado. Versión: $javaVersion en $($folder.FullName)"
                        }
                    }

                    # Detectar JDK (javac.exe en la carpeta bin del JDK)
                    if ($folder.Name -match "jdk" -and -not $result.JDK.IsInstalled) {
                        $javacExePath = Join-Path -Path $folder.FullName -ChildPath "bin\javac.exe"
                        if (Test-Path $javacExePath) {
                            $jdkVersion = & "$javacExePath" -version 2>&1 | 
                                         Select-String -Pattern "javac" | 
                                         ForEach-Object { $_.ToString().Split()[1].Trim('"') }
                            
                            $result.JDK.Version = $jdkVersion
                            $result.JDK.Path = $folder.FullName
                            $result.JDK.IsInstalled = $true
                            $result.JDK.Executable = $javacExePath
                            Write-Log "JDK detectado. Versión: $jdkVersion en $($folder.FullName)"
                        }
                    }
                }
            } catch {
                Write-Log "Error al verificar Java: $_"
            }
        }
    }

    return $result
}

# Función para actualizar JRE
function Update-JRE {
    param (
        [string]$CurrentVersion
    )
    
    $installerPath = "$env:TEMP\JavaJRE_Installer.exe"
    $requiredJREVersion = "1.8.0_441"  # Versión específica requerida
    $javaInstallPath = "${env:ProgramFiles}\Java"
    
    Write-Log "Versión actual de JRE: $CurrentVersion"
    Write-Log "Buscando versiones instaladas en $javaInstallPath..."

    # Buscar todas las versiones de JRE instaladas
    $installedVersions = @()
    if (Test-Path $javaInstallPath) {
        $jreFolders = Get-ChildItem -Path $javaInstallPath -Directory -Filter "jre*" | 
                      Where-Object { $_.Name -match 'jre1\.8\.0_(\d+)' }
        
        foreach ($folder in $jreFolders) {
            $version = $folder.Name.Replace('jre', '')
            $installedVersions += $version
            Write-Log "Encontrado JRE versión: $version en $($folder.FullName)"
        }
    }

    # Verificar si ya existe la versión requerida
    $hasRequiredVersion = $installedVersions -contains $requiredJREVersion

    if ($hasRequiredVersion) {
        Write-Log "Ya existe la versión requerida (JRE $requiredJREVersion) instalada. No es necesario actualizar."
        return "AlreadyUpdated"
    }

    # Verificar si la versión actual es la requerida
    if ($CurrentVersion -eq $requiredJREVersion) {
        Write-Log "La versión actual de JRE ($CurrentVersion) es la requerida. No es necesario actualizar."
        return "AlreadyUpdated"
    }
    
    Write-Log "Descargando instalador de JRE..."
    if (-not (Download-File -Url $javaJreUrl -Destination $installerPath)) {
        return "DownloadFailed"
    }

    Write-Log "Actualizando JRE..."
    try {
        # Comando para instalar JRE silenciosamente
        Start-Process -FilePath $installerPath -ArgumentList "/s" -Wait -ErrorAction Stop
        
        # Verificar nueva versión
        $javaInfo = Check-JavaInstalled
        $newVersion = $javaInfo.JRE.Version
        
        if ($newVersion -eq $requiredJREVersion) {
            Write-Log "JRE actualizado correctamente a la versión requerida $requiredJREVersion"
            return $newVersion
        } elseif ($newVersion -and $newVersion -ne $CurrentVersion) {
            Write-Log "JRE se actualizó pero no a la versión requerida. Versión instalada: $newVersion"
            return "PartialUpdate"
        } else {
            Write-Log "JRE no se actualizó o la versión no cambió."
            return "NoChange"
        }
    } catch {
        Write-Log "Error al actualizar JRE: $_"
        return "InstallFailed"
    }
}

function Update-JDK {
    param (
        [string]$CurrentVersion,
        [string]$JavaJdkUrl,
        [int]$LatestJDKVersion = 24
    )
    
    $installerPath = "$env:TEMP\JavaJDK_Installer.msi"
    $javaInstallPath = "${env:ProgramFiles}\Java"
    $logFile = "$env:TEMP\JDK_Install_$(Get-Date -Format 'yyyyMMddHHmmss').log"
    
    Write-Log "Inicio del proceso de actualización de JDK"
    Write-Log "Versión actual: $CurrentVersion | Versión objetivo: $LatestJDKVersion"

    # Validación de parámetros
    if ([string]::IsNullOrEmpty($JavaJdkUrl)) {
        Write-Log "Error: No se ha proporcionado la URL de descarga del JDK"
        return "InvalidParameters"
    }

    # Detección de versiones instaladas
    Write-Log "Buscando versiones instaladas en $javaInstallPath..."
    $installedVersions = @()
    
    if (Test-Path $javaInstallPath) {
        $jdkFolders = Get-ChildItem -Path $javaInstallPath -Directory -Filter "jdk*" | 
                      Where-Object { $_.Name -match 'jdk-?(\d+)' }
        
        foreach ($folder in $jdkFolders) {
            $version = if ($folder.Name -match 'jdk-?(\d+)') { [int]$matches[1] } else { 0 }
            $installedVersions += $version
            Write-Log "Encontrado JDK versión $version en $($folder.FullName)"
        }
    }

    # Verificar si ya existe una versión adecuada
    $hasNewerVersion = $installedVersions | Where-Object { $_ -ge $LatestJDKVersion } | Select-Object -First 1

    if ($hasNewerVersion) {
        Write-Log "Versión adecuada ya instalada (JDK $hasNewerVersion). No se requiere actualización."
        return "AlreadyUpdated"
    }

    # Extraer versión mayor actual
    $currentMajorVersion = if ($CurrentVersion -match '^(\d+)') { [int]$matches[1] } else { 0 }
    
    if ($currentMajorVersion -ge $LatestJDKVersion) {
        Write-Log "La versión actual ($CurrentVersion) cumple con los requisitos"
        return "AlreadyUpdated"
    }

    # Descarga del instalador
    Write-Log "Descargando instalador desde $JavaJdkUrl..."
    try {
        $downloadResult = Download-File -Url $JavaJdkUrl -Destination $installerPath
        if (-not $downloadResult) {
            Write-Log "Error en la descarga del instalador"
            return "DownloadFailed"
        }
        Write-Log "Instalador descargado correctamente en $installerPath"
    } catch {
        Write-Log "Error durante la descarga: $_"
        return "DownloadFailed"
    }

    # Instalación MSI
    Write-Log "Iniciando instalación silenciosa del JDK..."
    try {
        $msiArguments = @(
            "/i", "`"$installerPath`"",
            "/quiet",
            "/norestart",
            "/log", "`"$logFile`""
        )

        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArguments -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -ne 0) {
            Write-Log "Instalación fallida. Código de salida: $($process.ExitCode)"
            Write-Log "Consulte el archivo de log: $logFile"
            return "InstallFailed"
        }

        # Verificación post-instalación
        $javaInfo = Check-JavaInstalled
        $newVersion = $javaInfo.JDK.Version
        
        if (-not $newVersion) {
            Write-Log "No se pudo verificar la versión instalada después de la actualización"
            return "InstallFailed"
        }

        $newMajorVersion = if ($newVersion -match '^(\d+)') { [int]$matches[1] } else { 0 }
        
        if ($newMajorVersion -ge $LatestJDKVersion) {
            Write-Log "JDK actualizado correctamente a la versión $newVersion"
            return $newVersion
        } else {
            Write-Log "JDK actualizado a versión $newVersion (no alcanza la versión objetivo $LatestJDKVersion)"
            return "PartialUpdate"
        }
    } catch {
        Write-Log "Error durante la instalación: $_"
        return "InstallFailed"
    } finally {
        # Limpieza del instalador
        if (Test-Path $installerPath) {
            Remove-Item -Path $installerPath -Force -ErrorAction SilentlyContinue
            Write-Log "Instalador temporal eliminado"
        }
    }
}

# Función principal para manejar Java
function Update-Java {
    Write-Log "Iniciando proceso de actualización de Java..."
    $javaInfo = Check-JavaInstalled
    $result = @{
        JRE = @{
            Before = $javaInfo.JRE.Version
            After = $null
            Status = "NotInstalled"
        }
        JDK = @{
            Before = $javaInfo.JDK.Version
            After = $null
            Status = "NotInstalled"
        }
    }

    # Actualizar JRE si está instalado
    if ($javaInfo.JRE.IsInstalled) {
        Write-Log "JRE instalado detectado. Versión actual: $($javaInfo.JRE.Version)"
        $jreUpdateResult = Update-JRE -CurrentVersion $javaInfo.JRE.Version
        
        if ($jreUpdateResult -notin "DownloadFailed", "InstallFailed", "NoChange") {
            $result.JRE.After = $jreUpdateResult
            $result.JRE.Status = "Updated"
        } elseif ($jreUpdateResult -eq "NoChange") {
            $result.JRE.After = $javaInfo.JRE.Version
            $result.JRE.Status = "AlreadyUpdated"
        } else {
            $result.JRE.After = $javaInfo.JRE.Version
            $result.JRE.Status = $jreUpdateResult
        }
    }

    # Actualizar JDK si está instalado
    if ($javaInfo.JDK.IsInstalled) {
        Write-Log "JDK instalado detectado. Versión actual: $($javaInfo.JDK.Version)"
        $jdkUpdateResult = Update-JDK -CurrentVersion $javaInfo.JDK.Version
        
        if ($jdkUpdateResult -notin "DownloadFailed", "InstallFailed", "NoChange") {
            $result.JDK.After = $jdkUpdateResult
            $result.JDK.Status = "Updated"
        } elseif ($jdkUpdateResult -eq "NoChange") {
            $result.JDK.After = $javaInfo.JDK.Version
            $result.JDK.Status = "AlreadyUpdated"
        } else {
            $result.JDK.After = $javaInfo.JDK.Version
            $result.JDK.Status = $jdkUpdateResult
        }
    }

    # Si no hay nada instalado
    if (-not $javaInfo.JRE.IsInstalled -and -not $javaInfo.JDK.IsInstalled) {
        Write-Log "No se encontró JRE ni JDK instalado."
    }

    return $result
}

# Función para verificar si Firefox está instalado
function Check-FirefoxInstalled {
    $firefoxPaths = @(
        "${env:ProgramFiles}\Mozilla Firefox\firefox.exe",
        "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
    )
    foreach ($path in $firefoxPaths) {
        if (Test-Path $path) {
            try {
                $versionInfo = (Get-Item $path).VersionInfo
                $firefoxVersion = $versionInfo.ProductVersion
                Write-Log "Firefox está instalado. Versión: $firefoxVersion"
                return $firefoxVersion
            } catch {
                Write-Log "No se pudo obtener la versión de Firefox: $_"
                return $null
            }
        }
    }
    Write-Log "Firefox no está instalado."
    return $null
}

# Función para actualizar Firefox
function Update-Firefox {
    Write-Log "Iniciando la verificación de Firefox..."
    $firefoxVersionBefore = Check-FirefoxInstalled
    if (-not $firefoxVersionBefore) {
        Write-Log "Firefox no está instalado. No se realizará ninguna acción."
        return "NotInstalled"
    } else {
        Write-Log "Firefox está instalado. Versión actual: $firefoxVersionBefore"
    }

    $firefoxDownloadUrl = "https://download.mozilla.org/?product=firefox-latest&os=win64&lang=es-ES"
    $installerPath = "$downloadDirectory\Firefox_Installer.exe"
    if (-not (Download-File -Url $firefoxDownloadUrl -Destination $installerPath)) {
        return "DownloadFailed"
    }

    if (Test-Path $installerPath) {
        Write-Log "Actualizando Firefox..."
        try {
            Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait -ErrorAction Stop
            $firefoxVersionAfter = Check-FirefoxInstalled
            Write-Log "Firefox ha sido actualizado correctamente. Nueva versión: $firefoxVersionAfter"
            return $firefoxVersionAfter
        } catch {
            Write-Log "Error al actualizar Firefox: $_"
            return "InstallFailed"
        }
    } else {
        Write-Log "Error: No se pudo descargar el instalador de Firefox."
        return "DownloadFailed"
    }
}

# Función para verificar si FileZilla está instalado
function Check-FileZillaInstalled {
    $filezillaPaths = @(
        "${env:ProgramFiles}\FileZilla FTP Client\filezilla.exe",
        "${env:ProgramFiles(x86)}\FileZilla FTP Client\filezilla.exe"
    )
    foreach ($path in $filezillaPaths) {
        if (Test-Path $path) {
            try {
                $versionInfo = (Get-Item $path).VersionInfo
                $filezillaVersion = $versionInfo.ProductVersion
                Write-Log "FileZilla está instalado. Versión: $filezillaVersion"
                return $filezillaVersion
            } catch {
                Write-Log "No se pudo obtener la versión de FileZilla: $_"
                return $null
            }
        }
    }
    Write-Log "FileZilla no está instalado."
    return $null
}

# Función para actualizar FileZilla
function Update-FileZilla {
    Write-Log "Iniciando la verificación de FileZilla..."
    $filezillaVersionBefore = Check-FileZillaInstalled
    if (-not $filezillaVersionBefore) {
        Write-Log "FileZilla no está instalado. No se realizará ninguna acción."
        return "NotInstalled"
    } else {
        Write-Log "FileZilla está instalado. Versión actual: $filezillaVersionBefore"
    }

    $filezillaDownloadUrl = "https://data.rafalan.pro/web/client/pubshares/4REX3w52FfgGLmh5USRR5M?compress=false"
    $installerPath = "$downloadDirectory\FileZilla_Installer.exe"
    if (-not (Download-File -Url $filezillaDownloadUrl -Destination $installerPath)) {
        return "DownloadFailed"
    }

    if (Test-Path $installerPath) {
        Write-Log "Actualizando FileZilla..."
        try {
            Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait -ErrorAction Stop
            $filezillaVersionAfter = Check-FileZillaInstalled
            Write-Log "FileZilla ha sido actualizado correctamente. Nueva versión: $filezillaVersionAfter"
            return $filezillaVersionAfter
        } catch {
            Write-Log "Error al actualizar FileZilla: $_"
            return "InstallFailed"
        }
    } else {
        Write-Log "Error: No se pudo descargar el instalador de FileZilla."
        return "DownloadFailed"
    }
}

# Función para verificar si LibreOffice está instalado
function Check-LibreOfficeInstalled {
    $libreofficePaths = @(
        "${env:ProgramFiles}\LibreOffice\program\soffice.exe",
        "${env:ProgramFiles(x86)}\LibreOffice\program\soffice.exe"
    )
    foreach ($path in $libreofficePaths) {
        if (Test-Path $path) {
            try {
                $versionInfo = (Get-Item $path).VersionInfo
                $libreofficeVersion = $versionInfo.ProductVersion
                Write-Log "LibreOffice está instalado. Versión: $libreofficeVersion"
                return $libreofficeVersion
            } catch {
                Write-Log "No se pudo obtener la versión de LibreOffice: $_"
                return $null
            }
        }
    }
    Write-Log "LibreOffice no está instalado."
    return $null
}

# Función para actualizar LibreOffice
function Update-LibreOffice {
    Write-Log "Iniciando la verificación de LibreOffice..."
    $libreofficeVersionBefore = Check-LibreOfficeInstalled
    if (-not $libreofficeVersionBefore) {
        Write-Log "LibreOffice no está instalado. No se realizará ninguna acción."
        return "NotInstalled"
    } else {
        Write-Log "LibreOffice está instalado. Versión actual: $libreofficeVersionBefore"
    }

    $libreofficeDownloadUrl = "https://download.documentfoundation.org/libreoffice/stable/25.2.1/win/x86_64/LibreOffice_25.2.1_Win_x86-64.msi"
    $installerPath = "$downloadDirectory\LibreOffice_Installer.msi"
    if (-not (Download-File -Url $libreofficeDownloadUrl -Destination $installerPath)) {
        return "DownloadFailed"
    }

    if (Test-Path $installerPath) {
        Write-Log "Actualizando LibreOffice..."
        try {
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$installerPath`" /quiet /norestart" -Wait -NoNewWindow
            $libreofficeVersionAfter = Check-LibreOfficeInstalled
            Write-Log "LibreOffice ha sido actualizado correctamente. Nueva versión: $libreofficeVersionAfter"
            return $libreofficeVersionAfter
        } catch {
            Write-Log "Error al actualizar LibreOffice: $_"
            return "InstallFailed"
        }
    } else {
        Write-Log "Error: No se pudo descargar el instalador de LibreOffice."
        return "DownloadFailed"
    }
}

# Función para verificar si WinRAR está instalado
function Check-WinRARInstalled {
    $winrarPaths = @(
        "${env:ProgramFiles}\WinRAR\WinRAR.exe",
        "${env:ProgramFiles(x86)}\WinRAR\WinRAR.exe"
    )
    foreach ($path in $winrarPaths) {
        if (Test-Path $path) {
            try {
                $versionInfo = (Get-Item $path).VersionInfo
                $winrarVersion = $versionInfo.ProductVersion
                Write-Log "WinRAR está instalado. Versión: $winrarVersion"
                return $winrarVersion
            } catch {
                Write-Log "No se pudo obtener la versión de WinRAR: $_"
                return $null
            }
        }
    }
    Write-Log "WinRAR no está instalado."
    return $null
}

function Update-WinRAR {
    Write-Log "Iniciando la verificación de WinRAR..."
    $winrarVersionBefore = Check-WinRARInstalled
    if (-not $winrarVersionBefore) {
        Write-Log "WinRAR no está instalado. No se realizará ninguna acción."
        return "NotInstalled"
    } else {
        Write-Log "WinRAR está instalado. Versión actual: $winrarVersionBefore"
    }

    $winrarDownloadUrl = "https://data.rafalan.pro/web/client/pubshares/movSNycYZ7pK72rgxfLa2b?compress=false"
    $installerPath = "$downloadDirectory\WinRAR_Installer.exe"
    $expectedHash = "9A266E4FCC51599D067973E962A077972339CD5CDF97BA2B6B8F8DA93697905C"  # Reemplaza con el hash correcto

    if (-not (Download-File -Url $winrarDownloadUrl -Destination $installerPath)) {
        return "DownloadFailed"
    }

    if (Test-Path $installerPath) {
        Write-Log "Verificando la integridad del archivo descargado..."
        $fileHash = (Get-FileHash -Path $installerPath -Algorithm SHA256).Hash
        
        if ($fileHash -ne $expectedHash) {
            Write-Log "Error: El hash del instalador no coincide. Abortando instalación."
            Remove-Item -Path $installerPath -Force
            return "HashMismatch"
        }

        Write-Log "El hash es válido. Procediendo con la actualización de WinRAR..."
        try {
            Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait -ErrorAction Stop
            $winrarVersionAfter = Check-WinRARInstalled
            Write-Log "WinRAR ha sido actualizado correctamente. Nueva versión: $winrarVersionAfter"
            return $winrarVersionAfter
        } catch {
            Write-Log "Error al actualizar WinRAR: $_"
            return "InstallFailed"
        }
    } else {
        Write-Log "Error: No se pudo descargar el instalador de WinRAR."
        return "DownloadFailed"
    }
}
# Función para verificar si Forcepoint está instalado
function Check-ForcepointInstalled {
    $forcepointPath = "C:\Program Files\Websense\Websense Endpoint\F1EUI.exe"
    if (Test-Path $forcepointPath) {
        try {
            $versionInfo = (Get-Item $forcepointPath).VersionInfo
            $forcepointVersion = $versionInfo.ProductVersion
            Write-Log "Forcepoint está instalado. Versión: $forcepointVersion"
            return $forcepointVersion
        } catch {
            Write-Log "No se pudo obtener la versión de Forcepoint: $_"
            return $null
        }
    } else {
        Write-Log "Forcepoint no está instalado."
        return $null
    }
}

function Update-Forcepoint {
    Write-Log "Iniciando la verificación de Forcepoint..."
    $forcepointVersionBefore = Check-ForcepointInstalled
    if (-not $forcepointVersionBefore) {
        Write-Log "Forcepoint no está instalado. No se realizará ninguna acción."
        return "NotInstalled"
    } else {
        Write-Log "Forcepoint está instalado. Versión actual: $forcepointVersionBefore"
    }

    # Verificar si ya está en la versión más reciente (25.03.5710)
    if ($forcepointVersionBefore -eq "25.03.5710") {
        Write-Log "Forcepoint ya está en la versión más reciente (25.03.5710). No es necesario actualizar."
        return "AlreadyUpdated"
    }

    $forcepointDownloadUrl = "https://data.rafalan.pro/web/client/pubshares/pLyTPKDEYEGEadV7wRzzui?compress=false"
    $installerPath = "$downloadDirectory\FORCEPOINT-ONE-ENDPOINT-x64_Windows11.exe"

    # Hash SHA256 conocido del archivo (debes obtener este valor del archivo original)
    $expectedHash = "05E661F86AF1DE781315360CCB99CEF444D8946CA4C00F7D73522315D8FC7911"

    # Verificar si el archivo ya existe en la carpeta de descargas
    if (Test-Path $installerPath) {
        Write-Log "El instalador de Forcepoint ya existe en $installerPath. Verificando integridad del archivo..."
        
        # Calcular el hash del archivo existente
        $fileHash = Get-FileHash -Path $installerPath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
        Write-Log "Hash del archivo descargado: $fileHash"

        # Comparar el hash del archivo con el hash conocido
        if ($fileHash -eq $expectedHash) {
            Write-Log "El archivo está íntegro. No es necesario descargarlo nuevamente."
        } else {
            Write-Log "El archivo está corrupto. Eliminando y descargando nuevamente..."
            Remove-Item -Path $installerPath -Force
        }
    }

    # Si el archivo no existe o fue eliminado por estar corrupto, descargarlo nuevamente
    if (-not (Test-Path $installerPath)) {
        Write-Log "El instalador de Forcepoint no existe. Descargando..."
        try {
            Invoke-WebRequest -Uri $forcepointDownloadUrl -OutFile $installerPath
            Write-Log "Instalador descargado correctamente en: $installerPath"

            # Verificar el hash del archivo descargado
            $fileHash = Get-FileHash -Path $installerPath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
            Write-Log "Hash del archivo descargado: $fileHash"

            if ($fileHash -eq $expectedHash) {
                Write-Log "El archivo está íntegro. Procediendo con la instalación."
            } else {
                Write-Log "Error: El archivo descargado está corrupto (hash no coincide)."
                return "DownloadCorrupted"
            }
        } catch {
            Write-Log "Error al descargar el instalador de Forcepoint: $_"
            return "DownloadFailed"
        }
    }

    # Verificar nuevamente si el archivo existe antes de proceder con la instalación
    if (Test-Path $installerPath) {
        Write-Log "Actualizando Forcepoint..."
        try {
            # Ejecutar la instalación silenciosa sin reiniciar
            Start-Process -FilePath $installerPath -ArgumentList '/v"/qn /norestart"' -Wait -NoNewWindow
            Write-Log "Instalación silenciosa de Forcepoint completada."
            
            # Verificar la versión después de la instalación
            $forcepointVersionAfter = Check-ForcepointInstalled
            Write-Log "Forcepoint ha sido actualizado correctamente. Nueva versión: $forcepointVersionAfter"
            return $forcepointVersionAfter
        } catch {
            Write-Log "Error al actualizar Forcepoint: $_"
            return "InstallFailed"
        }
    } else {
        Write-Log "Error: No se pudo descargar o verificar el instalador de Forcepoint."
        return "DownloadFailed"
    }
}

# Función para subir datos a NocoDB (actualizada para JRE/JDK)
function Upload-ToNocoDB {
    param (
        [string]$Timestamp,
        [string]$Hostname,
        [string]$Status,
        [string]$Description,
        [string]$WindowsUpdateStatus,
        [string]$JREVersionBefore,
        [string]$JREVersionAfter,
        [string]$JREStatus,
        [string]$JDKVersionBefore,
        [string]$JDKVersionAfter,
        [string]$JDKStatus,
        [string]$FirefoxVersionBefore,
        [string]$FirefoxVersionAfter,
        [string]$LibreOfficeVersionBefore,
        [string]$LibreOfficeVersionAfter,
        [string]$LibreOfficeStatus,
        [string]$FileZillaVersionBefore,
        [string]$FileZillaVersionAfter,
        [string]$FileZillaStatus,
        [string]$WinRARVersionBefore,
        [string]$WinRARVersionAfter,
        [string]$WinRARStatus,
        [string]$ForcepointVersionBefore,
        [string]$ForcepointVersionAfter,
        [string]$ForcepointStatus,
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
        WindowsUpdateStatus = $WindowsUpdateStatus
        JREVersionBefore = if ($JREVersionBefore) { $JREVersionBefore } else { "NotInstalled" }
        JREVersionAfter = if ($JREVersionAfter) { $JREVersionAfter } else { "NotInstalled" }
        JREStatus = $JREStatus
        JDKVersionBefore = if ($JDKVersionBefore) { $JDKVersionBefore } else { "NotInstalled" }
        JDKVersionAfter = if ($JDKVersionAfter) { $JDKVersionAfter } else { "NotInstalled" }
        JDKStatus = $JDKStatus
        FirefoxVersionBefore = $FirefoxVersionBefore
        FirefoxVersionAfter = $FirefoxVersionAfter
        LibreOfficeVersionBefore = $LibreOfficeVersionBefore
        LibreOfficeVersionAfter = $LibreOfficeVersionAfter
        LibreOfficeStatus = $LibreOfficeStatus
        FileZillaVersionBefore = $FileZillaVersionBefore
        FileZillaVersionAfter = $FileZillaVersionAfter
        FileZillaStatus = $FileZillaStatus
        WinRARVersionBefore = $WinRARVersionBefore
        WinRARVersionAfter = $WinRARVersionAfter
        WinRARStatus = $WinRARStatus
        ForcepointVersionBefore = $ForcepointVersionBefore
        ForcepointVersionAfter = $ForcepointVersionAfter
        ForcepointStatus = $ForcepointStatus
        ProxyDisabled = $ProxyDisabled
    } | ConvertTo-Json

    Write-Log "Enviando datos a NocoDB..."
    try {
        $response = Invoke-RestMethod -Uri $nocodbUrl -Method Post -Headers @{ "xc-token" = $token } -Body $payload -ContentType "application/json"
        Write-Log "Datos subidos exitosamente a NocoDB."
    } catch {
        Write-Log "Error al enviar datos a NocoDB: $_"
    }
}

# Función para eliminar la tarea programada
function Remove-ScheduledTask {
    try {
        Write-Log "Eliminando la tarea programada '$taskName'..."
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
        Write-Log "Tarea programada '$taskName' eliminada correctamente."
        return $true
    } catch {
        Write-Log "Error al eliminar la tarea programada '$taskName': $_"
        return $false
    }
}

# Función para eliminar el archivo del script
function Remove-ScriptFile {
    try {
        Write-Log "Eliminando el archivo del script en '$scriptPath'..."
        if (Test-Path $scriptPath) {
            Remove-Item -Path $scriptPath -Force -ErrorAction Stop
            Write-Log "Archivo del script en '$scriptPath' eliminado correctamente."
            return $true
        } else {
            Write-Log "El archivo del script en '$scriptPath' no existe."
            return $false
        }
    } catch {
        Write-Log "Error al eliminar el archivo del script en '$scriptPath': $_"
        return $false
    }
}

# Función principal del proceso de actualización (actualizada)
function Start-WindowsUpdateProcess {
    Write-Log "Inicio del proceso de actualización"

    # Verificar privilegios de administrador
    Check-AdminPrivileges

    # Actualizar Forcepoint
    $forcepointVersionBefore = Check-ForcepointInstalled
    if ($forcepointVersionBefore) {
        $forcepointResult = Update-Forcepoint
        $forcepointVersionAfter = if ($forcepointResult -eq "AlreadyUpdated") { $forcepointVersionBefore } else { Check-ForcepointInstalled }
        $forcepointStatus = $forcepointResult
    } else {
        $forcepointVersionAfter = "NotInstalled"
        $forcepointStatus = "NotInstalled"
    }

    # Deshabilitar el proxy
    $proxyDisabled = Disable-Proxy

    # Instalar el proveedor de NuGet y el módulo PSWindowsUpdate
    Install-NuGetProvider
    Install-PSWindowsUpdateModule

    # Buscar e instalar actualizaciones de Windows
    $windowsUpdateStatus = Get-WindowsUpdates

    # Actualizar Java
    $javaUpdateResult = Update-Java

    # Actualizar Firefox
    $firefoxVersionBefore = Check-FirefoxInstalled
    if ($firefoxVersionBefore) {
        $firefoxVersionAfter = Update-Firefox
        $firefoxStatus = if ($firefoxVersionAfter -eq $firefoxVersionBefore) { "AlreadyUpdated" } else { $firefoxVersionAfter }
    } else {
        $firefoxVersionAfter = "NotInstalled"
        $firefoxStatus = "NotInstalled"
    }

    # Actualizar LibreOffice
    $libreofficeVersionBefore = Check-LibreOfficeInstalled
    if ($libreofficeVersionBefore) {
        $libreofficeVersionAfter = Update-LibreOffice
        $libreofficeStatus = if ($libreofficeVersionAfter -eq $libreofficeVersionBefore) { "AlreadyUpdated" } else { $libreofficeVersionAfter }
    } else {
        $libreofficeVersionAfter = "NotInstalled"
        $libreofficeStatus = "NotInstalled"
    }

    # Actualizar FileZilla
    $filezillaVersionBefore = Check-FileZillaInstalled
    if ($filezillaVersionBefore) {
        $filezillaVersionAfter = Update-FileZilla
        $filezillaStatus = if ($filezillaVersionAfter -eq $filezillaVersionBefore) { "AlreadyUpdated" } else { $filezillaVersionAfter }
    } else {
        $filezillaVersionAfter = "NotInstalled"
        $filezillaStatus = "NotInstalled"
    }

    # Actualizar WinRAR
    $winrarVersionBefore = Check-WinRARInstalled
    if ($winrarVersionBefore) {
        $winrarVersionAfter = Update-WinRAR
        $winrarStatus = if ($winrarVersionAfter -eq $winrarVersionBefore) { "AlreadyUpdated" } else { $winrarVersionAfter }
    } else {
        $winrarVersionAfter = "NotInstalled"
        $winrarStatus = "NotInstalled"
    }

# Enviar datos a NocoDB con la información separada de JRE/JDK
Upload-ToNocoDB -Timestamp (Get-Date -Format "yyyy-MM-dd HH:mm:ss") `
                -Hostname $env:COMPUTERNAME `
                -Status "Success" `
                -Description "Proceso de actualización completado." `
                -WindowsUpdateStatus $windowsUpdateStatus `
                -JREVersionBefore $javaUpdateResult.JRE.Before `
                -JREVersionAfter $javaUpdateResult.JRE.After `
                -JREStatus $javaUpdateResult.JRE.Status `
                -JDKVersionBefore $javaUpdateResult.JDK.Before `
                -JDKVersionAfter $javaUpdateResult.JDK.After `
                -JDKStatus $javaUpdateResult.JDK.Status `
                -FirefoxVersionBefore $firefoxVersionBefore `
                -FirefoxVersionAfter $firefoxVersionAfter `
                -LibreOfficeVersionBefore $libreofficeVersionBefore `
                -LibreOfficeVersionAfter $libreofficeVersionAfter `
                -LibreOfficeStatus $libreofficeStatus `
                -FileZillaVersionBefore $filezillaVersionBefore `
                -FileZillaVersionAfter $filezillaVersionAfter `
                -FileZillaStatus $filezillaStatus `
                -WinRARVersionBefore $winrarVersionBefore `
                -WinRARVersionAfter $winrarVersionAfter `
                -WinRARStatus $winrarStatus `
                -ForcepointVersionBefore $forcepointVersionBefore `
                -ForcepointVersionAfter $forcepointVersionAfter `
                -ForcepointStatus $forcepointStatus `
                -ProxyDisabled $(if ($proxyDisabled) { "Yes" } else { "No" })
    Write-Log "Proceso completado."

    # Eliminar la tarea programada
    $taskRemoved = Remove-ScheduledTask
    if (-not $taskRemoved) {
        Write-Log "Advertencia: No se pudo eliminar la tarea programada."
    }

    # Eliminar el archivo del script
    $scriptRemoved = Remove-ScriptFile
    if (-not $scriptRemoved) {
        Write-Log "Advertencia: No se pudo eliminar el archivo del script."
    }
}

# Llamada a la función principal
Start-WindowsUpdateProcess
