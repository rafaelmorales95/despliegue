# Cambiar la política de ejecución temporalmente
Set-ExecutionPolicy Bypass -Scope Process -Force

# Definir la ruta del archivo de log y el CSV
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$logFile = Join-Path $scriptDir "log.txt"
$csvFile = Join-Path $scriptDir "resultado.csv"

# Encabezados esperados
$expectedHeaders = "Fecha y Hora,Hostname,SO,IP,Parámetro,Estado"

# Función para asegurar que el encabezado esté presente
function Ensure-CSVHeader {
    if (-not (Test-Path -Path $csvFile)) {
        # Si el archivo no existe, crearlo con el encabezado
        Add-Content -Path $csvFile -Value $expectedHeaders -Encoding UTF8
    } else {
        # Si el archivo existe, verificar el encabezado
        $firstLine = Get-Content -Path $csvFile -TotalCount 1
        if ($firstLine -ne $expectedHeaders) {
            # Si el encabezado no coincide, añadirlo al inicio del archivo
            $content = Get-Content -Path $csvFile
            Set-Content -Path $csvFile -Value $expectedHeaders -Encoding UTF8
            Add-Content -Path $csvFile -Value $content
        }
    }
}

# Redirigir la salida estándar y de error al archivo de log
Start-Transcript -Path $logFile -Append

# Función para mostrar el menú
function Show-Menu {
    Clear-Host
    Write-Host "====================================" -ForegroundColor Cyan
    Write-Host "        MENU DE DIRECTIVAS" -ForegroundColor Cyan
    Write-Host "====================================" -ForegroundColor Cyan
    Write-Host "1. Descarga dependencias" -ForegroundColor Yellow
    Write-Host "2. Aplicar directivas" -ForegroundColor Yellow
    Write-Host "3. Backup directivas" -ForegroundColor Yellow
    Write-Host "4. Ejecutar todo (Backup + Aplicar)" -ForegroundColor Yellow
    Write-Host "5. Salir" -ForegroundColor Yellow
}

function Get-SecurityPolicy {
    param (
        [string]$Policy
    )
    $currentPolicy = secedit /export /cfg $env:windir\security\export.cfg
    $value = (Get-Content $env:windir\security\export.cfg | Select-String $Policy) -replace "${Policy} = "
    return $value
}

function Get-CurrentAuditPolicy {
    param (
        [string]$Subcategory
    )
    $result = auditpol /get /category:* | Select-String -Pattern "^\s+$Subcategory\s+" | ForEach-Object { $_.ToString().Trim() -split '\s+', 2 | Select-Object -Last 1 }
    return $result
}

function Get-RegistryPolicy {
    param (
        [string]$Path,
        [string]$Name
    )
    try {
        $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $value.$Name
    }
    catch {
        return $null
    }
}

function Verify-Status {
    Clear-Host
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "   VERIFICACION DEL ESTADO DE LAS DIRECTIVAS" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "Verificando el estado de las directivas..." -ForegroundColor Green
    Write-Host ""

    # Políticas de seguridad
    $securityPolicies = @{
        "PasswordHistorySize" = "24"
        "MaximumPasswordAge" = "365"
        "MinimumPasswordAge" = "0"
        "MinimumPasswordLength" = "12"
        "PasswordComplexity" = "1"
        "ClearTextPassword" = "0"
        "LockoutDuration" = "15"
        "LockoutBadCount" = "5"
        "EnableAdminAccount" = "0"
        "EnableGuestAccount" = "0"
        "RestrictAnonymousSAM" = "1"
        "RestrictAnonymous" = "1"
        "DisableDomainCreds" = "1"
        "EveryoneIncludesAnonymous" = "0"
        "ForceLogoffWhenHourExpire" = "1"
        "EnableSecuritySignature" = "1"
        "RequireSecuritySignature" = "1"
        "DisableMachineAccountPasswordChange" = "0"
        "MaximumMachineAccountPasswordAge" = "30"
        "RequireStrongKey" = "1"
        "LsaAnonymousNameLookup" = "0"
        "AllowNullSessionFallback" = "0"
        "AllowAdministratorLockout" = "1"
        "EnableUIADesktopToggle" = "0"
        "FormatAndEject" = "1"
        "PreventPrinterDrivers" = "1"
        "DigitallySignChannelData" = "1"
        "EncryptChannelData" = "1"
        "RemotelyAccessibleRegistryPaths" = "System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion"
        "RemotelyAccessibleRegistryPathsAndSubPaths" = "System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog"
        "AnonymousAccessToShares" = ""
        "EnableAdminApprovalMode" = "1"
        "ConsentPromptBehaviorUser" = "0"
        "DetectApplicationInstallations" = "1"
    }

    foreach ($policy in $securityPolicies.Keys) {
        $currentValue = Get-SecurityPolicy $policy
        $expectedValue = $securityPolicies[$policy]
        if ($currentValue -eq $expectedValue) {
            Write-Host "Política ${policy}: Correcta (${currentValue})" -ForegroundColor Green
        } else {
            Write-Host "Política ${policy}: Incorrecta (Actual: ${currentValue}, Esperado: ${expectedValue})" -ForegroundColor Red
        }
    }

    # Políticas de auditoría
    $auditPolicies = @{
        "Validación de credenciales" = "Aciertos y errores"
        "Administración de grupos de aplicaciones" = "Aciertos y errores"
        "Administración de grupos de seguridad" = "Aciertos"
        "Administración de cuentas de usuario" = "Aciertos"
        "Actividad DPAPI" = "Sin auditoría"
        "Creación del proceso" = "Sin auditoría"
        "Bloqueo de cuenta" = "Aciertos"
        "Cerrar sesión" = "Aciertos"
        "Inicio de sesión" = "Aciertos y errores"
        "Otros eventos de inicio y cierre de sesión" = "Sin auditoría"
        "Inicio de sesión especial" = "Aciertos"
        "Recurso compartido de archivos detallado" = "Sin auditoría"
        "Recurso compartido de archivos" = "Sin auditoría"
        "Otros eventos de acceso a objetos" = "Sin auditoría"
        "Almacenamiento extraíble" = "Sin auditoría"
        "Uso de privilegio confidencial" = "Sin auditoría"
        "Controlador IPsec" = "Sin auditoría"
        "Otros eventos de sistema" = "Aciertos y errores"
        "Cambio de estado de seguridad" = "Aciertos"
        "Extensión del sistema de seguridad" = "Sin auditoría"
        "Integridad del sistema" = "Aciertos y errores"
        "Actividad PNP" = "Aciertos"
    }

    foreach ($policy in $auditPolicies.Keys) {
        $currentValue = Get-CurrentAuditPolicy $policy
        $expectedValue = $auditPolicies[$policy]
        if ($currentValue -eq $expectedValue) {
            Write-Host "Política de auditoría ${policy}: Correcta (${currentValue})" -ForegroundColor Green
        } else {
            Write-Host "Política de auditoría ${policy}: Incorrecta (Actual: ${currentValue}, Esperado: ${expectedValue})" -ForegroundColor Red
        }
    }

    # Otras políticas
    $otherPolicies = @{
        "ScreenSaverActive" = @{Path="HKCU:\Control Panel\Desktop"; Name="ScreenSaveActive"; ExpectedValue="1"}
        "AlwaysInstallElevated" = @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="AlwaysInstallElevated"; ExpectedValue="0"}
    }

    foreach ($policy in $otherPolicies.Keys) {
        $currentValue = Get-RegistryPolicy -Path $otherPolicies[$policy].Path -Name $otherPolicies[$policy].Name
        $expectedValue = $otherPolicies[$policy].ExpectedValue
        if ($currentValue -eq $expectedValue) {
            Write-Host "Política ${policy}: Correcta (${currentValue})" -ForegroundColor Green
        } else {
            Write-Host "Política ${policy}: Incorrecta (Actual: ${currentValue}, Esperado: ${expectedValue})" -ForegroundColor Red
        }
    }
}

# Función para agregar entradas al archivo CSV
function Add-ToCsv {
    param (
        [string]$Parameter,
        [string]$Status
    )
    Ensure-CSVHeader
    $systemInfo = @{
        FechaHora        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Hostname         = $env:COMPUTERNAME
        SistemaOperativo = (Get-CimInstance Win32_OperatingSystem).Caption
        IP               = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet | Select-Object -First 1).IPAddress
    }
    $data = "{0},{1},{2},{3},{4},{5}" -f $systemInfo.FechaHora, $systemInfo.Hostname, $systemInfo.SistemaOperativo, $systemInfo.IP, $Parameter, $Status
    try {
        Add-Content -Path $csvFile -Value $data
    } catch {
        Write-Host "No se pudo escribir en el archivo CSV." -ForegroundColor Red
    }
}




# Función para descargar y descomprimir
function Download-And-Unzip {
    Clear-Host
    Write-Host "====================================" -ForegroundColor Cyan
    Write-Host "    DESCARGAR Y DESCOMPRIMIR ZIP" -ForegroundColor Cyan
    Write-Host "====================================" -ForegroundColor Cyan

    $url = "https://data.rafalan.pro/web/client/pubshares/2VLLBDM6jrUbnn3teVvVJW?compress=false"
    $zipPath = "C:\lgpo\archivo.zip"
    $extractPath = "C:\lgpo"
    $backupFolder = "C:\lgpo\Respaldos"

    if (Test-Path -Path $backupFolder) {
        Write-Host "La carpeta Respaldos ya existe en $backupFolder, por lo que el hardening ya está aplicado" -ForegroundColor Yellow
        Add-ToCsv -Parameter "Hardening" -Status "OK"
        return
    }

    if (-not (Test-Path -Path $extractPath)) {
        New-Item -ItemType Directory -Path $extractPath
    }

    try {
        Invoke-WebRequest -Uri $url -OutFile $zipPath
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
        Remove-Item -Path $zipPath -Force
        Add-ToCsv -Parameter "Descarga y descompresión" -Status "OK"
    }
    catch {
        Add-ToCsv -Parameter "Descarga y descompresión" -Status "Error"
    }
}

# Función para descargar y descomprimir
function Download-And-Unzip {
    Clear-Host
    Write-Host "====================================" -ForegroundColor Cyan
    Write-Host "    DESCARGAR Y DESCOMPRIMIR ZIP" -ForegroundColor Cyan
    Write-Host "====================================" -ForegroundColor Cyan

    $url = "https://data.rafalan.pro/web/client/pubshares/2VLLBDM6jrUbnn3teVvVJW?compress=false"
    $zipPath = "C:\lgpo\archivo.zip"
    $extractPath = "C:\lgpo"
    $backupFolder = "C:\lgpo\Respaldos"

    if (Test-Path -Path $backupFolder) {
        Write-Host "La carpeta Respaldos ya existe en $backupFolder, por lo que el hardening ya está aplicado" -ForegroundColor Yellow
        Add-ToCsv -Parameter "Hardening" -Status "OK"
        return
    }

    if (-not (Test-Path -Path $extractPath)) {
        New-Item -ItemType Directory -Path $extractPath
    }

    try {
        Invoke-WebRequest -Uri $url -OutFile $zipPath
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
        Remove-Item -Path $zipPath -Force
        Add-ToCsv -Parameter "Descarga y descompresión" -Status "OK"
    }
    catch {
        Add-ToCsv -Parameter "Descarga y descompresión" -Status "Error"
    }
}

# Función para aplicar directivas
function Apply-Policies {
    Clear-Host
    Write-Host "====================================" -ForegroundColor Cyan
    Write-Host "    APLICACION DE DIRECTIVAS" -ForegroundColor Cyan
    Write-Host "====================================" -ForegroundColor Cyan
    Write-Host "Aplicando directivas de grupo desde C:\lgpo\Respaldos\Directivas..." -ForegroundColor Green

    $lgpoPath = "C:\lgpo\LGPO.exe"
    $policyPath = "C:\lgpo\Respaldos\Directivas"
    & $lgpoPath /g $policyPath

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Las directivas se aplicaron correctamente desde $policyPath" -ForegroundColor Green
        Add-ToCsv -Parameter "Aplicación de directivas" -Status "OK"
    } else {
        Write-Host "Hubo un error al aplicar las directivas desde $policyPath" -ForegroundColor Red
        Add-ToCsv -Parameter "Aplicación de directivas" -Status "Error"
    }
}

# Función para respaldar directivas
function Backup-Policies {
    Clear-Host
    Write-Host "====================================" -ForegroundColor Cyan
    Write-Host "    RESPALDO DE DIRECTIVAS" -ForegroundColor Cyan
    Write-Host "====================================" -ForegroundColor Cyan

    $lgpoPath = "C:\lgpo\LGPO.exe"
    $backupPath = "C:\lgpo\Respaldos\Directivas"

    if (-not (Test-Path -Path $backupPath)) {
        New-Item -ItemType Directory -Path $backupPath
    }

    & $lgpoPath /b $backupPath
    if ($LASTEXITCODE -eq 0) {
        Add-ToCsv -Parameter "Backup de directivas" -Status "OK"
    } else {
        Add-ToCsv -Parameter "Backup de directivas" -Status "Error"
    }
}

# Función para ejecutar todo
function Run-All {
    Clear-Host
    Write-Host "====================================" -ForegroundColor Cyan
    Write-Host "    EJECUTANDO TODO EL SCRIPT" -ForegroundColor Cyan
    Write-Host "====================================" -ForegroundColor Cyan

    Download-And-Unzip
    Backup-Policies
    #Apply-Policies
}

# Menú principal
while ($true) {
    Show-Menu
    $selection = Read-Host "Selecciona una opción"
    switch ($selection) {
        1 { Download-And-Unzip }
        2 { Apply-Policies }
        3 { Backup-Policies }
        4 { Run-All }
        5 {
            Write-Host "Saliendo..." -ForegroundColor Red
            Stop-Transcript
            exit
        }
        default {
            Write-Host "Opción no válida." -ForegroundColor Red
        }
    }
}
