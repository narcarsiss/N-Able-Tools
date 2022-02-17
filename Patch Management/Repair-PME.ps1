$Version = '0.2.1.3'
$VersionDate = '(24/05/2021)'

# Settings
# **********************************************************************************************************************************
# Change this variable to number of days (must be a number!) to allow repair after new version of PME is released. 
# This is used for the update pending check. Default is 2.
$RepairAfterUpdateDays = "2"

# Change this variable to number of days (must be a number!) within a recent install to allow a force repair. 
# This will bypass the update pending check. Default is 2. Ensure this is equal to $RepairAfterUpdateDays.
$ForceRepairRecentInstallDays = "2"

# Change this variable to turn off/on update check of the Repair-PME script. Default is Yes. To turn this off set it to No.
$UpdateCheck = "off"

# Change this variable to turn off/on random delay of the Repair-PME script to help prevent network congestion if running this
# Script on large number of machines at the same time. Default is No. To turn this on set it to Yes.
$PreventNetworkCongestion = "No"
# **********************************************************************************************************************************

Write-Host "Repair-PME $Version $VersionDate" -ForegroundColor Yellow
Write-Host "-------------------------------" -ForegroundColor Yellow

$WriteEventLogInformationParams = @{
    LogName   = "Application"
    Source    = "Repair-PME"
    EntryType = "Information"
    EventID   = 100
}
$WriteEventLogErrorParams = @{
    LogName   = "Application"
    Source    = "Repair-PME"
    EntryType = "Error"
    EventID   = 100
}
$WriteEventLogWarningParams = @{
    LogName   = "Application"
    Source    = "Repair-PME"
    EntryType = "Warning"
    EventID   = 100
}

Function Confirm-Elevation {
    # Confirms script is running as an administrator
    Write-Host "Checking for elevated permissions..." -ForegroundColor Cyan
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Throw "Insufficient permissions to run this script. Run PowerShell as an administrator and run this script again."
    }
    Else {
        Write-Host "OK: Script is running as administrator" -ForegroundColor Green
    }
}

Function Set-Start {
    New-EventLog -LogName Application -Source "Repair-PME" -ErrorAction SilentlyContinue
    Write-EventLog @WriteEventLogInformationParams -Message "Repair-PME has started, running version $Version.`nScript: Repair-PME.ps1"
}

function Get-LegacyHash {
    Param($Path)
    # Performs hashing functionality with compatibility for older OS
    Try {
        Add-Type -AssemblyName System.Security
        $csp = New-Object -TypeName System.Security.Cryptography.SHA256CryptoServiceProvider
        $ComputedHash = @()
        $ComputedHash = $csp.ComputeHash([System.IO.File]::ReadAllBytes($Path))
        $ComputedHash = [System.BitConverter]::ToString($ComputedHash).Replace("-", "").ToLower()
        Return $ComputedHash
    }
    Catch {
        Write-EventLog @WriteEventLogErrorParams -Message "Unable to performing hashing, aborting. Error: $($_.Exception.Message).`nScript: Repair-PME.ps1"
        Throw "Unable to performing hashing, aborting. Error: $($_.Exception.Message)"
    }
}
Function Get-OSVersion {
    # Get OS version
    $OSVersion = (Get-WmiObject Win32_OperatingSystem).Caption
    # Workaround for WMI timeout or WMI returning no data
    If (($null -eq $OSVersion) -or ($OSVersion -like "*OS - Alias not found*")) {
        $OSVersion = (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('ProductName')
    }
    Write-Output "OS: $OSVersion"
}
Function Get-OSArch {
    $OSArch = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
    Write-Output "OS Architecture: $OSArch"
    If ($OSArch -like '*64*') {
        # 32-bit program files on 64-bit
        $ProgramFiles = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
    } ElseIf ($OSArch -like '*32*') {
        # 32-bit program files on 32-bit
        $ProgramFiles = [Environment]::GetEnvironmentVariable("ProgramFiles")
    }
    Else {
        Write-EventLog @WriteEventLogErrorParams -Message "Unable to detect processor architecture, aborting. Error: $($_.Exception.Message).`nScript: Repair-PME.ps1"
        Throw "Unable to detect processor architecture, aborting. Error: $($_.Exception.Message)"
    }
}

Function Get-PMELocations {
    $NCentralLog = "$ProgramFiles\N-able Technologies\Windows Agent\log"
    # > PME Version 2.0
    If (Test-Path -Path "$ProgramFiles\MspPlatform\PME\unins000.exe") {
        $PMEAgentUninstall = "$ProgramFiles\MspPlatform\PME\unins000.exe"
        If (Test-Path -Path "$env:ProgramData\MspPlatform\PME\archives") {
            $PMEArchives = "$env:ProgramData\MspPlatform\PME\archives"
        }
        If (Test-Path -Path "$env:ProgramData\MspPlatform") {
            $PMEProgramDataPath = "$env:ProgramData\MspPlatform"
        }
    }
    If (Test-Path -Path "$ProgramFiles\MspPlatform\RequestHandlerAgent\unins000.exe") {
        $PMERPCUninstall = "$ProgramFiles\MspPlatform\RequestHandlerAgent\unins000.exe"
    }
    If (Test-Path -Path "$ProgramFiles\MspPlatform\FileCacheServiceAgent\unins000.exe") {
        $PMECacheUninstall = "$ProgramFiles\MspPlatform\FileCacheServiceAgent\unins000.exe"
        If (Test-Path -Path "$PMEProgramDataPath\FileCacheServiceAgent") {
            $CacheServiceConfigFile = "$PMEProgramDataPath\FileCacheServiceAgent\config\FileCacheServiceAgent.xml"
        }
    }

    # < PME Version 2.0
    If (Test-Path -Path "$ProgramFiles\SolarWinds MSP\PME\unins000.exe") {
        $PMEAgentUninstall = "$ProgramFiles\SolarWinds MSP\PME\unins000.exe"
        If (Test-Path -Path "$env:ProgramData\SolarWinds MSP\PME\archives") {
            $PMEArchives = "$env:ProgramData\SolarWinds MSP\PME\archives"
        }
        If (Test-Path -Path "$env:ProgramData\SolarWinds MSP") {
            $PMEProgramDataPath = "$env:ProgramData\SolarWinds MSP"
        }
    }
    If (Test-Path -Path "$ProgramFiles\SolarWinds MSP\RpcServer\unins000.exe") {
        $PMERPCUninstall = "$ProgramFiles\SolarWinds MSP\RpcServer\unins000.exe"
    }
    If (Test-Path -Path "$ProgramFiles\SolarWinds MSP\CacheService\unins000.exe") {
        $PMECacheUninstall = "$ProgramFiles\SolarWinds MSP\CacheService\unins000.exe"
        If (Test-Path -Path "$PMEProgramDataPath\SolarWinds.MSP.CacheService") {
            $CacheServiceConfigFile = "$PMEProgramDataPath\SolarWinds.MSP.CacheService\config\CacheService.xml"
        }
    }

    # Fallback to new directory if not installed (required)
    If ($null -eq $PMEProgramDataPath) {
        $PMEProgramDataPath = "$env:ProgramData\MspPlatform"
    }
    If ($null -eq $PMEArchives) {
        $PMEArchives = "$env:ProgramData\MspPlatform\PME\archives"
    }
    If ($null -eq $CacheServiceConfigFile) {
        $CacheServiceConfigFile = "$PMEProgramDataPath\FileCacheServiceAgent\config\FileCacheServiceAgent.xml"
    }
}

Function Get-PSVersion {
    $PSVersion = $($PSVersionTable.PSVersion)
    Write-Output "PowerShell: $($PSVersionTable.PSVersion)"
}

Function Test-Port ($server, $port) {
    $client = New-Object Net.Sockets.TcpClient
    Try {
        $client.Connect($server, $port)
        $true
    }
    Catch {
        $false
    }
}

Function Set-CryptoProtocol {
    # Enable TLS 1.2 - this should work on Windows 7 with PowerShell 2.0 and above.
    $tls12 = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    [Net.ServicePointManager]::SecurityProtocol = $tls12
}

Function Invoke-Delay {
    If ($PreventNetworkCongestion -eq "Yes") {
        $Delay = Get-Random -Minimum 1 -Maximum 60
        Write-Output "Execution will be delayed for $Delay seconds to avoid network congestion..."
        Start-Sleep -Seconds $Delay
    }
}

Function Get-RepairPMEUpdate {
    If ($UpdateCheck -eq "Yes") {
        Write-Host "Checking if update is available for Repair-PME script..." -ForegroundColor Cyan    
        $RepairPMEVersionURI = "http://raw.githubusercontent.com/N-able/ScriptsAndAutomationPolicies/master/Repair-PME/LatestVersion.xml"
        $EventLogMessage = $null
        $CatchError = $null
        [int]$DownloadAttempts = 0
        [int]$MaxDownloadAttempts = 10
        Do {
            Try {
                $DownloadAttempts +=1
                $Request = $null; $LatestPMEVersion = $null
                [xml]$request = ((New-Object System.Net.WebClient).DownloadString("$RepairPMEVersionURI") -split '<\?xml.*\?>')
                $LatestPMEVersion  = $request.LatestVersion.Version
                Write-Output "Current Repair-PME Version: $Version `nLatest Repair-PME Version: $LatestPMEVersion"
                Break
            }
            Catch {
                $EventLogMessage = "ERROR: Unable to fetch version file to check if Repair-PME is up to date, possibly due to limited or no connectivity to https://raw.githubusercontent.com`nScript: Repair-PME.ps1"
                $CatchError = "Unable to fetch version file to check if Repair-PME is up to date, possibly due to limited or no connectivity to https://raw.githubusercontent.com"
            }
            Write-Output "Download failed on attempt $DownloadAttempts of $MaxDownloadAttempts, retrying in 3 seconds..."
            Start-Sleep -Seconds 3
        }
        While ($DownloadAttempts -lt 10)
        If (($DownloadAttempts -eq 10) -and ($null -ne $CatchError)) {
            Write-EventLog @WriteEventLogErrorParams -Message $EventLogMessage
            Throw $CatchError
        }

        If ([version]$Version -ge [version]$LatestPMEVersion) {
            Write-Host "OK: Repair-PME is up to date" -ForegroundColor Green
        }
        ElseIf ([version]$Version -lt [version]$LatestPMEVersion) {
            Write-EventLog @WriteEventLogWarningParams -Message "WARNING: Repair-PME is not up to date! please download the latest version from https://github.com/N-able/ScriptsAndAutomationPolicies/blob/master/Repair-PME/Repair-PME.ps1`nScript: Repair-PME.ps1"
            Write-Error "Repair-PME is not up to date! please download the latest version from https://github.com/N-able/ScriptsAndAutomationPolicies/blob/master/Repair-PME/Repair-PME.ps1"
        }
        Else {
            Write-EventLog @WriteEventLogWarningParams -Message "ERROR: Unable to detect if Repair-PME is up to date!`nScript: Repair-PME.ps1"
            Write-Error "Unable to detect if Repair-PME is up to date!"
        }
    }
}

Function Test-Connectivity {
    # Performs connectivity tests to destinations required for PME
    If (($PSVersionTable.PSVersion -ge "4.0") -and (!($OSVersion -match 'Windows 7')) -and (!($OSVersion -match '2008 R2'))) {
        Write-Host "Performing HTTPS connectivity tests for PME required destinations..." -ForegroundColor Cyan
        $List1 = @("sis.n-able.com")
        $HTTPSError = @()
        $List1 | ForEach-Object {
            $Test1 = Test-NetConnection $_ -Port 443
            If ($Test1.tcptestsucceeded -eq $True) {
                Write-Host "OK: Connectivity to https://$_ ($(($Test1).RemoteAddress.IpAddressToString)) established" -ForegroundColor Green
                $HTTPSError += "No"
            }
            Else {
                Write-Host "ERROR: Unable to establish connectivity to https://$_ ($(($Test1).RemoteAddress.IpAddressToString))" -ForegroundColor Red
                $HTTPSError += "Yes"
            }
        }

        Write-Host "Performing HTTP connectivity tests for PME required destinations..." -ForegroundColor Cyan
        $HTTPError = @()
        $List2 = @("sis.n-able.com", "download.windowsupdate.com", "fg.ds.b1.download.windowsupdate.com")
        $List2 | ForEach-Object {
            $Test1 = Test-NetConnection $_ -Port 80
            If ($Test1.tcptestsucceeded -eq $True) {
                Write-Host "OK: Connectivity to http://$_ ($(($Test1).RemoteAddress.IpAddressToString)) established" -ForegroundColor Green
                $HTTPError += "No"
            }
            Else {
                Write-Host "ERROR: Unable to establish connectivity to http://$_ ($(($Test1).RemoteAddress.IpAddressToString))" -ForegroundColor Red
                $HTTPError += "Yes"
            }
        }

        If (($HTTPError[0] -like "*Yes*") -and ($HTTPSError[0] -like "*Yes*")) {
            Write-EventLog @WriteEventLogErrorParams -Message "ERROR: No connectivity to $($List2[0]) can be established, aborting.`nScript: Repair-PME.ps1"
            Throw "ERROR: No connectivity to $($List2[0]) can be established, aborting."
        } ElseIf (($HTTPError[0] -like "*Yes*") -or ($HTTPSError[0] -like "*Yes*")) {
            Write-EventLog @WriteEventLogWarningParams -Message "WARNING: Partial connectivity to $($List2[0]) established, falling back to HTTP.`nScript: Repair-PME.ps1"
            Write-Warning "Partial connectivity to $($List2[0]) established, falling back to HTTP"
            $Fallback = "Yes"
        }

        If ($HTTPError[1] -like "*Yes*") {
            Write-EventLog @WriteEventLogWarningParams -Message "WARNING: No connectivity to $($List2[1]) can be established, you will be unable to download Microsoft Updates!`nScript: Repair-PME.ps1"
            Write-Warning "No connectivity to $($List2[1]) can be established, you will be unable to download Microsoft Updates!"
        }

        If ($HTTPError[2] -like "*Yes*") {
            Write-EventLog @WriteEventLogWarningParams -Message "WARNING: No connectivity to $($List2[2]) can be established, you will be unable to download Windows Feature Updates!`nScript: Repair-PME.ps1"
            Write-Warning "No connectivity to $($List2[2]) can be established, you will be unable to download Windows Feature Updates!"
        }
    }
    Else {
        Write-Host "Performing HTTPS connectivity tests for PME required destinations using legacy method..." -ForegroundColor Cyan
        $List1 = @("sis.n-able.com")
        $HTTPSError = @()
        $List1 | ForEach-Object {
            $Test1 = Test-Port $_ 443
            If ($Test1 -eq $True) {
                Write-Host "OK: Connectivity to https://$_ established" -ForegroundColor Green
                $HTTPSError += "No"
            }
            Else {
                Write-Host "ERROR: Unable to establish connectivity to https://$_ established" -ForegroundColor Red
                $HTTPSError += "Yes"
            }
        }

        Write-Host "Performing HTTP connectivity tests for PME required destinations using legacy method..." -ForegroundColor Cyan
        $HTTPError = @()
        $List2 = @("sis.n-able.com", "download.windowsupdate.com", "fg.ds.b1.download.windowsupdate.com")
        $List2 | ForEach-Object {
            $Test1 = Test-Port $_ 80
            If ($Test1 -eq $True) {
                Write-Host "OK: Connectivity to http://$_ established" -ForegroundColor Green
                $HTTPError += "No"
            }
            Else {
                Write-Host "ERROR: Unable to establish connectivity to http://$_ established" -ForegroundColor Red
                $HTTPError += "Yes"
            }
        }

        If (($HTTPError[0] -like "*Yes*") -and ($HTTPSError[0] -like "*Yes*")) {
            Write-EventLog @WriteEventLogErrorParams -Message "ERROR: No connectivity to $($List2[0]) can be established, aborting.`nScript: Repair-PME.ps1"
            Throw "ERROR: No connectivity to $($List2[0]) can be established, aborting."
        } ElseIf (($HTTPError[0] -like "*Yes*") -or ($HTTPSError[0] -like "*Yes*")) {
            Write-EventLog @WriteEventLogWarningParams -Message "WARNING: Partial connectivity to $($List2[0]) established, falling back to HTTP.`nScript: Repair-PME.ps1"
            Write-Warning "Partial connectivity to $($List2[0]) established, falling back to HTTP"
            $Fallback = "Yes"
        }

        If ($HTTPError[1] -like "*Yes*") {
            Write-EventLog @WriteEventLogWarningParams -Message "WARNING: No connectivity to $($List2[1]) can be established, you will be unable to download Microsoft Updates!`nScript: Repair-PME.ps1"
            Write-Warning "No connectivity to $($List2[1]) can be established, you will be unable to download Microsoft Updates!"
        }

        If ($HTTPError[2] -like "*Yes*") {
            Write-EventLog @WriteEventLogWarningParams -Message "WARNING: No connectivity to $($List2[2]) can be established, you will be unable to download Windows Feature Updates!`nScript: Repair-PME.ps1"
            Write-Warning "No connectivity to $($List2[2]) can be established, you will be unable to download Windows Feature Updates!"
        }
    }
}

Function Get-NableCertificate ($url) {
    $EventLogMessage = $null
    $CatchError = $null
    [int]$DownloadAttempts = 0
    [int]$MaxDownloadAttempts = 10
    Do {
        Try {
            # Request website
            $DownloadAttempts +=1
            $WebRequest = $null
            [net.httpWebRequest] $WebRequest = [Net.WebRequest]::Create($url)
            $WebRequest.AllowAutoRedirect = $true
            $WebRequest.KeepAlive = $false
            $WebRequest.Timeout = 10000
            $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
            [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            $Response = $WebRequest.GetResponse()
            $Response.close()
            Break
        }
        Catch {
            $EventLogMessage = "Unable to obtain certificate chain, PME may have trouble downloading from https://sis.n-able.com, aborting. Error: $($_.Exception.Message).`nScript: Repair-PME.ps1"
            $CatchError = "Unable to obtain certificate chain, PME may have trouble downloading from https://sis.n-able.com, aborting. Error: $($_.Exception.Message)"
        }
        Write-Output "Download failed on attempt $DownloadAttempts of $MaxDownloadAttempts, retrying in 3 seconds..."
        Start-Sleep -Seconds 3
    }
    While ($DownloadAttempts -lt 10)
    If (($DownloadAttempts -eq 10) -and ($null -ne $CatchError)) {
        Write-EventLog @WriteEventLogErrorParams -Message $EventLogMessage
        Throw $CatchError
    }

    # Creates Certificate
    $Certificate = $WebRequest.ServicePoint.Certificate.Handle
    $Issuer = $WebRequest.ServicePoint.Certificate.Issuer
    $Subject = $WebRequest.ServicePoint.Certificate.Subject

    # Build chain
    [Void]($chain.Build($Certificate))
    # write-host $chain.ChainElements.Count #This returns "1" meaning none of the CA certs are included.
    # write-host $chain.ChainElements[0].Certificate.IssuerName.Name
    [Net.ServicePointManager]::ServerCertificateValidationCallback = $null

    $CertificateChain = $chain.ChainElements.Certificate | Select-Object -Property DnsNameList, NotAfter
    $CertificateChain = $chain.ChainElements | Select-Object -ExpandProperty Certificate | Select-Object Subject, NotAfter
}

Function Test-NableCertificate {
    If ($null -eq $Fallback) {
        Write-Host "Downloading and checking certificate chain for sis.n-able.com..." -ForegroundColor Cyan
        . Get-NableCertificate https://sis.n-able.com
        $Date = Get-Date
        $CertificateChain | ForEach-Object {
            If ($null -eq $($_.NotAfter)) {
                Write-EventLog @WriteEventLogErrorParams -Message "Unable to obtain certificate chain, PME may have trouble downloading from https://sis.n-able.com, aborting.`nScript: Repair-PME.ps1"
                Throw "Unable to obtain certificate chain, PME may have trouble downloading from https://sis.n-able.com, aborting."
            } ElseIf ($($_.NotAfter) -le $Date) {
                Write-Host "$($_.NotAfter)"
                Write-EventLog @WriteEventLogErrorParams -Message "Certificate for ($($_.Subject)) expired on $($_.NotAfter) PME may have trouble downloading from https://sis.n-able.com, aborting.`nScript: Repair-PME.ps1"
                Throw "Certificate for ($($_Subject)) expired on $($_.NotAfter) PME may have trouble downloading from https://sis.n-able.com, aborting."
            } 
            Else {
                Write-Host "OK: Certificate for ($($_.Subject)) is valid"  -ForegroundColor Green
            }
        }
    }
}

Function Restore-Date {
    If ($InstallDate.Length -eq 6) {
        $M = $InstallDate.Substring(4, 1)
        $d = $InstallDate.Substring(5, 1)
        $Year = $InstallDate.Substring(0, 4)
        $InstallDate = $($Year + "0" + $M +"0" + $d )
    }
    If ($InstallDate.Length -eq 7) {
        $MMdd = $InstallDate.Substring(4, 3)
        $Year = $InstallDate.Substring(0, 4)
        $InstallDate = $($Year + "0" + $MMdd)
    }
}

Function Get-NCAgentVersion {
    # Check if N-Central Agent is currently installed
    Write-Host "Checking if N-Central Agent is already installed..." -ForegroundColor Cyan
    $IsNCAgentInstalled = ""
    $PATHS = @("HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    $SOFTWARE = "Windows Agent"
    ForEach ($path in $PATHS) {
        $installed = Get-ChildItem -Path $path |
        ForEach-Object { Get-ItemProperty $_.PSPath } |
        Where-Object { $_.DisplayName -match $SOFTWARE } |
        Select-Object -Property DisplayName, DisplayVersion, Publisher, InstallDate

        If ($null -ne $installed) {
            ForEach ($app in $installed) {
                If ($($app.DisplayName) -eq "Windows Agent" -and $($app.Publisher) -eq "N-able Technologies") {
                    $InstallDate = $($app.InstallDate)
                    If ($null -ne $InstallDate -and $InstallDate -ne "") {
                        . Restore-Date
                        $ConvertDateTime = [DateTime]::ParseExact($InstallDate, "yyyyMMdd", $null)
                        $InstallDateFormatted = $ConvertDateTime | Get-Date -Format "yyyy.MM.dd"
                    }
                    $IsNCAgentInstalled = "Yes"
                    Write-Host "N-Central Agent Installed: Yes" -ForegroundColor Green
                    Write-Output "N-Central Agent Version: $($app.DisplayVersion)"
                    Write-Output "N-Central Agent Install Date: $InstallDateFormatted"
                    If ($($app.DisplayVersion) -ge "12.2.0.274") {
                        Write-Host "N-Central Agent PME Compatible: Yes" -ForegroundColor Green
                    } 
                    Else {
                        Write-Host "N-Central Agent PME Compatible: No" -ForegroundColor Red
                        Write-EventLog @WriteEventLogErrorParams -Message "Installed N-Central Agent ($($app.DisplayVersion)) is not compatible with PME, aborting.`nScript: Repair-PME.ps1"
                        Throw "Installed N-Central Agent ($($app.DisplayVersion)) is not compatible with PME, aborting."
                    }
                }
                Else {
                    $IsNCAgentInstalled = "No"
                    Write-Host "N-Central Agent Installed: No" -ForegroundColor Red
                    Write-EventLog @WriteEventLogErrorParams -Message "N-Central Agent is not installed, PME requires an agent, aborting.`nScript: Repair-PME.ps1"
                    Throw "N-Central Agent is not installed, PME requires an agent, aborting."
                }
            }
        }
    }
}

Function Confirm-PMEInstalled {
    Write-Host "Checking if PME Components are already installed..." -ForegroundColor Cyan

    # Check if PME Agent / Patch Management Service Controller is currently installed
    $IsPMEAgentInstalled = ""
    $PATHS = @("HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    $SOFTWARES = "SolarWinds MSP Patch Management Engine", "Patch Management Service Controller"
    ForEach ($SOFTWARE in $SOFTWARES) {
        ForEach ($path in $PATHS) {
            $installed = Get-ChildItem -Path $path |
            ForEach-Object { Get-ItemProperty $_.PSPath } |
            Where-Object { $_.DisplayName -match $SOFTWARE } |
            Select-Object -Property DisplayName, DisplayVersion, InstallDate

            If ($null -ne $installed) {
                ForEach ($app in $installed) {
                    If ($($app.DisplayName) -eq "SolarWinds MSP Patch Management Engine") {
                        $PMEAgentAppDisplayVersion = $($app.DisplayVersion)
                        $InstallDate = $($app.InstallDate)
                        If ($null -ne $InstallDate -and $InstallDate -ne "") {
                            . Restore-Date
                            $ConvertDateTime = [DateTime]::ParseExact($InstallDate, "yyyyMMdd", $null)
                            $InstallDateFormatted = $ConvertDateTime | Get-Date -Format "yyyy.MM.dd"
                        }
                        $IsPMEAgentInstalled = "Yes"
                        Write-Host "PME Agent Already Installed: Yes" -ForegroundColor Green
                        Write-Output "Installed PME Agent Version: $PMEAgentAppDisplayVersion"
                        Write-Output "Installed PME Agent Date: $InstallDateFormatted"
                    }
                    If ($($app.DisplayName) -eq "Patch Management Service Controller") {
                        $PMEAgentAppDisplayVersion = $($app.DisplayVersion)
                        $InstallDate = $($app.InstallDate)
                        If ($null -ne $InstallDate -and $InstallDate -ne "") {
                            . Restore-Date
                            $ConvertDateTime = [DateTime]::ParseExact($InstallDate, "yyyyMMdd", $null)
                            $InstallDateFormatted = $ConvertDateTime | Get-Date -Format "yyyy.MM.dd"
                        }
                        $IsPMEAgentInstalled = "Yes"
                        Write-Host "PME Patch Management Service Controller Already Installed: Yes" -ForegroundColor Green
                        Write-Output "Installed PME Patch Management Service Controller Version: $PMEAgentAppDisplayVersion"
                        Write-Output "Installed PME Patch Management Service Controller Date: $InstallDateFormatted"
                    }
                }
            } 
        }
    }
    If ($IsPMEAgentInstalled -ne "Yes") {
        Write-Host "PME Agent / Patch Management Service Controller Already Installed: No" -ForegroundColor Yellow
    }

    # Check if PME RPC Service / Request Handler Agent is currently installed
    $IsPMERPCServerServiceInstalled = ""
    $PATHS = @("HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    $SOFTWARES = "SolarWinds MSP RPC Server", "Request Handler Agent"
    ForEach ($SOFTWARE in $SOFTWARES) {
        ForEach ($PATH in $PATHS) {
            $installed = Get-ChildItem -Path $PATH |
            ForEach-Object { Get-ItemProperty $_.PSPath } |
            Where-Object { $_.DisplayName -match $SOFTWARE } |
            Select-Object -Property DisplayName, DisplayVersion, InstallDate

            If ($null -ne $installed) {
                ForEach ($app in $installed) {
                    If ($($app.DisplayName) -eq "Solarwinds MSP RPC Server") {
                        $PMERPCServerAppDisplayVersion = $($app.DisplayVersion) 
                        $InstallDate = $($app.InstallDate)
                        If ($null -ne $InstallDate -and $InstallDate -ne "") {
                            . Restore-Date
                            $ConvertDateTime = [DateTime]::ParseExact($InstallDate, "yyyyMMdd", $null)
                            $InstallDateFormatted = $ConvertDateTime | Get-Date -Format "yyyy.MM.dd"
                        }
                        $IsPMERPCServerServiceInstalled = "Yes"
                        Write-Host "PME RPC Server Service Already Installed: Yes" -ForegroundColor Green
                        Write-Output "Installed PME RPC Server Service Version: $PMERPCServerAppDisplayVersion"
                        Write-Output "Installed PME RPC Server Service Date: $InstallDateFormatted"
                    }
                    If ($($app.DisplayName) -eq "Request Handler Agent") {
                        $PMERPCServerAppDisplayVersion = $($app.DisplayVersion)
                        $InstallDate = $($app.InstallDate)
                        If ($null -ne $InstallDate -and $InstallDate -ne "") {
                            . Restore-Date
                            $ConvertDateTime = [DateTime]::ParseExact($InstallDate, "yyyyMMdd", $null)
                            $InstallDateFormatted = $ConvertDateTime | Get-Date -Format "yyyy.MM.dd"
                        }
                        $IsPMERPCServerServiceInstalled = "Yes"
                        Write-Host "PME Request Handler Agent Already Installed: Yes" -ForegroundColor Green
                        Write-Output "Installed PME Request Handler Agent Version: $PMERPCServerAppDisplayVersion"
                        Write-Output "Installed PME Request Handler Agent Date: $InstallDateFormatted"
                    }
                }
            }
        }
    }
    If ($IsPMERPCServerServiceInstalled -ne "Yes") {
        Write-Host "PME RPC Server Service / Request Handler Agent Already Installed: No" -ForegroundColor Yellow
    }

    # Check if PME Cache Service / File Cache Service Agent is currently installed
    $IsPMECacheServiceInstalled = ""
    $PATHS = @("HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    $SOFTWARES = "SolarWinds MSP Cache Service", "File Cache Service Agent"
    ForEach ($SOFTWARE in $SOFTWARES) {
        ForEach ($path in $PATHS) {
            $installed = Get-ChildItem -Path $path |
            ForEach-Object { Get-ItemProperty $_.PSPath } |
            Where-Object { $_.DisplayName -match $SOFTWARE } |
            Select-Object -Property DisplayName, DisplayVersion, InstallDate

            If ($null -ne $installed) {
                ForEach ($app in $installed) {
                    If ($($app.DisplayName) -eq "SolarWinds MSP Cache Service") {
                        $PMECacheServiceAppDisplayVersion = $($app.DisplayVersion) 
                        $InstallDate = $($app.InstallDate)
                        If ($null -ne $InstallDate -and $InstallDate -ne "") {
                            . Restore-Date
                            $ConvertDateTime = [DateTime]::ParseExact($InstallDate, "yyyyMMdd", $null)
                            $InstallDateFormatted = $ConvertDateTime | Get-Date -Format "yyyy.MM.dd"
                        }
                        $IsPMECacheServiceInstalled = "Yes"
                        Write-Host "PME Cache Service Already Installed: Yes" -ForegroundColor Green
                        Write-Output "Installed PME Cache Service Version: $PMECacheServiceAppDisplayVersion"
                        Write-Output "Installed PME Cache Service Date: $InstallDateFormatted"
                    }
                    If ($($app.DisplayName) -eq "File Cache Service Agent") {
                        $PMECacheServiceAppDisplayVersion = $($app.DisplayVersion)
                        $InstallDate = $($app.InstallDate)
                        If ($null -ne $InstallDate -and $InstallDate -ne "") {
                            . Restore-Date
                            $ConvertDateTime = [DateTime]::ParseExact($InstallDate, "yyyyMMdd", $null)
                            $InstallDateFormatted = $ConvertDateTime | Get-Date -Format "yyyy.MM.dd"
                        }
                        $IsPMECacheServiceInstalled = "Yes"
                        Write-Host "PME File Cache Service Agent Already Installed: Yes" -ForegroundColor Green
                        Write-Output "Installed PME File Cache Service Agent Version: $PMECacheServiceAppDisplayVersion"
                        Write-Output "Installed PME File Cache Service Agent Date: $InstallDateFormatted"
                    }
                }
            }
        }
    }
    If ($IsPMECacheServiceInstalled -ne "Yes") {
        Write-Host "PME Cache Service / File Cache Service Agent Already Installed: No" -ForegroundColor Yellow
    }
}

Function Get-PMESetupDetails {
    # Declare static URI of PMESetup_details.xml
    If ($Fallback -eq "Yes") {
        $PMESetup_detailsURI = "http://sis.n-able.com/Components/MSP-PME/latest/PMESetup_details.xml"
    }
    Else {
        $PMESetup_detailsURI = "https://sis.n-able.com/Components/MSP-PME/latest/PMESetup_details.xml"
    }

    $EventLogMessage = $null
    $CatchError = $null
    [int]$DownloadAttempts = 0
    [int]$MaxDownloadAttempts = 10
    Do {
        Try {
            $DownloadAttempts +=1
            $request = $null
            [xml]$request = ((New-Object System.Net.WebClient).DownloadString("$PMESetup_detailsURI") -split '<\?xml.*\?>')[-1]
            $PMEDetails = $request.ComponentDetails
            $LatestVersion = $request.ComponentDetails.Version
            Break
        }
        Catch [System.Management.Automation.MetadataException] {
            $EventLogMessage = "Error casting to XML, could not parse PMESetup_details.xml from $PMESetup_detailsURI, aborting. Error: $($_.Exception.Message).`nScript: Repair-PME.ps1"
            $CatchError = "Error casting to XML, could not parse PMESetup_details.xml from $PMESetup_detailsURI, aborting. Error: $($_.Exception.Message)"
            Break
        }
        Catch {
            $EventLogMessage = "Error occurred attempting to obtain PMESetup_details.xml from $PMESetup_detailsURI, aborting. Error: $($_.Exception.Message).`nScript: Repair-PME.ps1"
            $CatchError = "Error occurred attempting to obtain PMESetup_details.xml from $PMESetup_detailsURI, aborting. Error: $($_.Exception.Message)"
        }
        Write-Output "Download failed on attempt $DownloadAttempts of $MaxDownloadAttempts, retrying in 3 seconds..."
        Start-Sleep -Seconds 3
    }
    While ($DownloadAttempts -lt 10)
    If (($DownloadAttempts -eq 10) -and ($null -ne $CatchError)) {
        Write-EventLog @WriteEventLogErrorParams -Message $EventLogMessage
        Throw $CatchError
    }

    $EventLogMessage = $null
    $CatchError = $null
    [int]$DownloadAttempts = 0
    [int]$MaxDownloadAttempts = 10
    Do {
        Try {
            $DownloadAttempts +=1
            $webRequest = $null; $webResponse = $null
            $webRequest = [System.Net.WebRequest]::Create($PMESetup_detailsURI)
            $webRequest.Method = "HEAD"
            $WebRequest.AllowAutoRedirect = $true
            $WebRequest.KeepAlive = $false
            $WebRequest.Timeout = 10000
            $webResponse = $webRequest.GetResponse()
            $remoteLastModified = ($webResponse.LastModified) -as [DateTime]
            $PMEReleaseDate = $remoteLastModified | Get-Date -Format "yyyy.MM.dd"
            $webResponse.Close()
            Break
        }
        Catch {
            $EventLogMessage = "Error fetching header for PMESetup_Details.xml from $($PMESetup_detailsURI), aborting. Error: $($_.Exception.Message).`nScript: Repair-PME.ps1"
            $CatchError = "Error fetching header for PMESetup_Details.xml from $($PMESetup_detailsURI), aborting. Error: $($_.Exception.Message)"
        }
        Write-Output "Download failed on attempt $DownloadAttempts of $MaxDownloadAttempts, retrying in 3 seconds..."
        Start-Sleep -Seconds 3
    }
    While ($DownloadAttempts -lt 10)
        If (($DownloadAttempts -eq 10) -and ($null -ne $CatchError)) {
        Write-EventLog @WriteEventLogErrorParams -Message $EventLogMessage
        Throw $CatchError
    }

    Write-Host "Checking Latest PME version..." -ForegroundColor Cyan
    Write-Output "Latest PME Version: $LatestVersion"
    Write-Output "Latest PME Release Date: $PMEReleaseDate"
}

Function Confirm-PMERecentInstall {
    If (($IsPMEAgentInstalled -eq "Yes") -or ($IsPMERPCServerServiceInstalled -eq "Yes") -or ($IsPMECacheServiceInstalled -eq "Yes")) {
        $Date = Get-Date -Format 'yyyy.MM.dd'
        If ($null -ne $PMEAgentUninstall) {
            $InstallDatePMEAgent = (Get-Item $PMEAgentUninstall).LastWriteTime
        }
        If ($null -ne $PMERPCUninstall) {
            $InstallDatePMERPC = (Get-Item $PMERPCUninstall).LastWriteTime
        }
        If ($null -ne $PMECacheUninstall) {
            $InstallDatePMECache = (Get-Item $PMECacheUninstall).LastWriteTime
        }
        
        If ($null -ne $InstallDatePMEAgent) {
            $DaysInstalledPMEAgent = (New-TimeSpan -Start $InstallDatePMEAgent -End $Date).Days
        }
        If ($null -ne $InstallDatePMERPC) {
            $DaysInstalledPMERPC = (New-TimeSpan -Start $InstallDatePMERPC -End $Date).Days
        }
        If ($null -ne $InstallDatePMECache) {
            $DaysInstalledPMECache  = (New-TimeSpan -Start $InstallDatePMECache -End $Date).Days
        }

        Write-Host "INFO: Repair-PME will force repair without update pending check if PME was installed in the last ($ForceRepairRecentInstallDays) days" -ForegroundColor Yellow -BackgroundColor Black
        If (($DaysInstalledPMEAgent -le $ForceRepairRecentInstallDays) -or ($DaysInstalledPMERPC -le $ForceRepairRecentInstallDays) -or ($DaysInstalledPMECache -le $ForceRepairRecentInstallDays)) {
            Write-Output "Less than ($ForceRepairRecentInstallDays) days has elapsed since PME has been installed. No update pending check required."
            $BypassUpdatePendingCheck = "Yes"
        }
        Else {
            Write-Output "More than ($ForceRepairRecentInstallDays) days has elapsed since PME has been installed. Update pending check required."
            $BypassUpdatePendingCheck = "No"
        }
    }
}

Function Confirm-PMEUpdatePending {
    # Check if PME is awaiting update for new release but has not updated yet (normally within 48 hours)
    If (($IsPMEAgentInstalled -eq "Yes") -and ($BypassUpdatePendingCheck -eq "No")) {
        $Date = Get-Date -Format 'yyyy.MM.dd'
        $ConvertPMEReleaseDate = Get-Date "$PMEReleaseDate"
        $SelfHealingDate = $ConvertPMEReleaseDate.AddDays($RepairAfterUpdateDays).ToString('yyyy.MM.dd')
        Write-Host "Checking if PME update pending..." -ForegroundColor Cyan
        Write-Host "INFO: Script will proceed ($RepairAfterUpdateDays) days after a new version of PME has been released" -ForegroundColor Yellow -BackgroundColor Black
        $DaysElapsed = (New-TimeSpan -Start $SelfHealingDate -End $Date).Days
        $DaysElapsedReversed = (New-TimeSpan -Start $ConvertPMEReleaseDate -End $Date).Days

        # Only run if current $Date is greater than or equal to $SelfHealingDate and $LatestVersion is greater than or equal to $app.DisplayVersion
        If (($Date -ge $SelfHealingDate) -and ([version]$LatestVersion -ge [version]$PMEAgentAppDisplayVersion)) {
            Write-Output "($DaysElapsed) days has elapsed since a new version of PME has been released and is allowed to be installed, script will proceed."
        }
        Else {
            Write-EventLog @WriteEventLogWarningParams -Message "($DaysElapsedReversed) days has elapsed since a new version of PME has been released, PME will only install after ($RepairAfterUpdateDays) days, aborting.`nScript: Repair-PME.ps1"
            Throw "($DaysElapsedReversed) days has elapsed since a new version of PME has been released, PME will only install after ($RepairAfterUpdateDays) days, aborting."
            Break
        }
    } ElseIf ($BypassUpdatePendingCheck -eq "Yes") {
        Write-Warning "Skipping update pending check as PME has recently been installed"
    }
    Else {
        Write-Warning "Skipping update pending check as PME is not currently installed"
    }
}

Function Clear-RepairPME {
    # Cleanup Repair-PME Log files older than 30 days
    Write-Host "Repair-PME Log Cleanup..." -ForegroundColor Cyan
    $RepairPMEPaths = "C:\ProgramData\SolarWinds MSP\Repair-PME", "C:\ProgramData\MspPlatform\Repair-PME"
    ForEach ($RepairPMEPath in $RepairPMEPaths) {
        If (Test-Path -Path "$RepairPMEPath") {
            Try {
                Write-Output "Performing cleanup of '$RepairPMEPath' folder"
                [Void](Get-ChildItem -Path $RepairPMEPath -Recurse | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-30) -and ! $_.PSIsContainer } | Remove-Item -Recurse -Confirm:$false)
            }
            Catch {
                Write-EventLog @WriteEventLogErrorParams -Message "Unable to cleanup '$RepairPMEPath' aborting. Error: $($_.Exception.Message).`nScript: Repair-PME.ps1"
                Throw "Unable to cleanup '$RepairPMEPath' aborting. Error: $($_.Exception.Message)"
            }
        }
    }
}

Function Invoke-PMEDiagnostics {
    # Invokes official PME Diagnostics tool to capture logs for support
    If (Test-Path -Path "$ProgramFiles\MspPlatform\PME\Diagnostics") {
        $PMEDiagnosticsFolderPath = "$ProgramFiles\MspPlatform\PME\Diagnostics"
        $PMEDiagnosticsExePath = "$PMEDiagnosticsFolderPath\PME.Diagnostics.exe"
        $RepairPMEDiagnosticsLogsPath = "$env:ProgramData\MspPlatform\Repair-PME\Diagnostic Logs"
        $ZipPath = "/`"ProgramData/MspPlatform/Repair-PME/Diagnostic Logs/PMEDiagnostics$(Get-Date -Format 'yyyyMMdd-hhmmss').zip`""
    }
    ElseIf (Test-Path -Path "$ProgramFiles\SolarWinds MSP\PME\Diagnostics") {
        $PMEDiagnosticsFolderPath = "$ProgramFiles\SolarWinds MSP\PME\Diagnostics"
        $PMEDiagnosticsExePath = "$PMEDiagnosticsFolderPath\SolarwindsDiagnostics.exe"
        $RepairPMEDiagnosticsLogsPath = "$env:ProgramData\SolarWinds MSP\Repair-PME\Diagnostic Logs"
        $ZipPath = "/`"ProgramData/SolarWinds MSP/Repair-PME/Diagnostic Logs/PMEDiagnostics$(Get-Date -Format 'yyyyMMdd-hhmmss').zip`""
    }
    Else  {
        $PMEDiagnosticsExePath = $False
    }

    Write-Host "Checking Diagnostics..." -ForegroundColor Cyan
    If (Test-Path -Path "$PMEDiagnosticsExePath") {
        Write-Output "PME Diagnostics located at '$PMEDiagnosticsExePath'"
        If (Test-Path -Path  "$RepairPMEDiagnosticsLogsPath") {
            Write-Output "Directory '$RepairPMEDiagnosticsLogsPath' already exists, no need to create directory"
        }
        Else {
            Try {
                Write-Output "Directory '$RepairPMEDiagnosticsLogsPath' does not exist, creating directory"
                [Void](New-Item -ItemType Directory -Path "$RepairPMEDiagnosticsLogsPath" -Force)
            }
            Catch {
                Write-EventLog @WriteEventLogErrorParams -Message "Unable to create directory '$RepairPMEDiagnosticsLogsPath' required for saving log capture. Error: $($_.Exception.Message).`nScript: Repair-PME.ps1"
                Throw "Unable to create directory '$RepairPMEDiagnosticsLogsPath' required for saving log capture. Error: $($_.Exception.Message)"
            }
        }
        Write-Output "Starting PME Diagnostics"
        # Write-Output "DEBUG: PME Diagnostics started with:- Start-Process -FilePath "$PMEDiagnosticsExePath" -ArgumentList "$ZipPath" -WorkingDirectory "$PMEDiagnosticsFolderPath" -Verb RunAs -Wait"
        Start-Process -FilePath "$PMEDiagnosticsExePath" -ArgumentList "$ZipPath" -WorkingDirectory "$RepairPMEDiagnosticsLogsPath" -Verb RunAs -Wait
        Write-Output "PME Diagnostics completed, file saved to '$RepairPMEDiagnosticsLogsPath'"
    }
    Else {
        Write-Warning "Unable to detect PME Diagnostics, skipping log capture"
    }
}

Function Stop-PMESetup {
    # Stop any running instances of PME install/uninstall to ensure that we can download & install successfully
    Write-Host "Stopping any running instances of PME install/uninstall..." -ForegroundColor Cyan
    $Processes = "PMESetup*", "CacheServiceSetup*", "FileCacheServiceAgentSetup*", "RPCServerServiceSetup*", "RequestHandlerAgentSetup*", "_iu14D2N*", "unins000*"
    ForEach ($Process in $Processes) {
        Write-Host "Checking if $Process is currently running..."
        $PMESetupRunning = Get-Process $Process -ErrorAction SilentlyContinue
        If ($PMESetupRunning) {
            Write-Warning "$Process is currently running, terminating..."
            $PMESetupRunning | Stop-Process -Force
        } 
        Else {
            Write-Host "OK: $Process is not currently running" -ForegroundColor Green
        }
    }
}

Function Stop-PMEServices {
    Write-Host "Stopping PME Services..." -ForegroundColor Cyan
    $Services = "SolarWinds.MSP.PME.Agent.PmeService", "PME.Agent.PmeService", "SolarWinds.MSP.RpcServerService", "SolarWinds.MSP.CacheService"
    ForEach ($Service in $Services) {
        $ServiceStatus = (Get-Service $Service -ErrorAction SilentlyContinue).Status
        If (($ServiceStatus -eq "Running") -or ($ServiceStatus -eq "Stopping") -or ($ServiceStatus -eq "Suspended")) {
            Write-Output "$Service is $ServiceStatus, attempting to stop..."
            Stop-Service -Name $Service -Force
            $ServiceStatus = (Get-Service $Service -ErrorAction SilentlyContinue).Status
            If ($ServiceStatus -eq "Stopped") {
                Write-Host "OK: $Service service successfully stopped" -ForegroundColor Green
            }
            Else {
                Write-Warning "$Service still running, temporarily disabling recovery and terminating"
                # Set-Service -Name $Service -StartupType Disabled
                sc.exe failure "$Service" reset= 0 actions= // >null
                $ServicePID = (Get-WMIObject Win32_Service | Where-Object { $_.name -eq $Service}).processID
                Stop-Process -Id $ServicePID -Force
                sc.exe failure "$Service" actions= restart/0/restart/0//0 reset= 0 >null
            }
        }
        Else {
            Write-Host "OK: $Service is not running" -ForegroundColor Green
        }
    }
}

Function Clear-PME {
    # Cleanup PME Cache folders
    Write-Host "PME Cache Cleanup..." -ForegroundColor Cyan
    $CacheFolderPaths = "$env:ProgramData\SolarWinds MSP\SolarWinds.MSP.CacheService", "$env:ProgramData\SolarWinds MSP\SolarWinds.MSP.CacheService\cache", "$env:ProgramData\MspPlatform\FileCacheServiceAgent", "$env:ProgramData\MspPlatform\FileCacheServiceAgent\cache"
    ForEach ($CacheFolderPath in $CacheFolderPaths) {
        If (Test-Path -Path "$CacheFolderPath") {
            Try {
                Write-Output "Performing cleanup of '$CacheFolderPath' folder"
                [Void](Remove-Item -Path "$CacheFolderPath\*.*" -Force -Confirm:$false)
            }
            Catch {
                Write-EventLog @WriteEventLogErrorParams -Message "Unable to cleanup '$CacheFolderPath\*.*' aborting. Error: $($_.Exception.Message).`nScript: Repair-PME.ps1"
                Throw "Unable to cleanup '$CacheFolderPath\*.*' aborting. Error: $($_.Exception.Message)"
            }
        }
    }
}

Function Get-PMESetup {
    # Download Setup
    If ($Fallback -eq "Yes") {
        $FallbackDownloadURL = ($PMEDetails.DownloadURL).Replace('https', 'http')
        Write-Output "Begin download of current $($PMEDetails.FileName) version $($PMEDetails.Version) from sis.n-able.com"
        $EventLogMessage = $null
        $CatchError = $null
        [int]$DownloadAttempts = 0
        [int]$MaxDownloadAttempts = 10
        Do {
            Try {
                $DownloadAttempts +=1
                (New-Object System.Net.WebClient).DownloadFile("$($FallbackDownloadURL)", "$PMEArchives\PMESetup_$($PMEDetails.Version).exe")
                Break
            }
            Catch {
                $EventLogMessage = "Unable to download $($PMEDetails.FileName) from sis.n-able.com, aborting. Error: $($_.Exception.Message).`nScript: Repair-PME.ps1"
                $CatchError = "Unable to download $($PMEDetails.FileName) from sis.n-able.com, aborting. Error: $($_.Exception.Message)"
            }
            Write-Output "Download failed on attempt $DownloadAttempts of $MaxDownloadAttempts, retrying in 3 seconds..."
            Start-Sleep -Seconds 3
        }
        While ($DownloadAttempts -lt 10)
        If (($DownloadAttempts -eq 10) -and ($null -ne $CatchError)) {
            Write-EventLog @WriteEventLogErrorParams -Message $EventLogMessage
            Throw $CatchError
        }
    }
    Else {
        Write-Output "Begin download of current $($PMEDetails.FileName) version $($PMEDetails.Version) from sis.n-able.com"
        $EventLogMessage = $null
        $CatchError = $null
        [int]$DownloadAttempts = 0
        [int]$MaxDownloadAttempts = 10
        Do {
            Try {
                $DownloadAttempts +=1
                (New-Object System.Net.WebClient).DownloadFile("$($PMEDetails.DownloadURL)", "$PMEArchives\PMESetup_$($PMEDetails.Version).exe")
                Break
            }
            Catch {
                $EventLogMessage = "Unable to download $($PMEDetails.FileName) from sis.n-able.com, aborting. Error: $($_.Exception.Message).`nScript: Repair-PME.ps1"
                $CatchError = "Unable to download $($PMEDetails.FileName) from sis.n-able.com, aborting. Error: $($_.Exception.Message)"
            }
            Write-Output "Download failed on attempt $DownloadAttempts of $MaxDownloadAttempts, retrying in 3 seconds..."
            Start-Sleep -Seconds 3
        }
        While ($DownloadAttempts -lt 10)
        If (($DownloadAttempts -eq 10) -and ($null -ne $CatchError)) {
            Write-EventLog @WriteEventLogErrorParams -Message $EventLogMessage
            Throw $CatchError
        }
    }
}

Function Get-PMEConfigMisconfigurations {
    # Check PME Config and inform of possible misconfigurations
    Write-Host "Checking PME Configuration..." -ForegroundColor Cyan
    Try {
        If (Test-Path -Path "$CacheServiceConfigFile") {
            $xml = New-Object XML
            $xml.Load($CacheServiceConfigFile)
            $CacheServiceConfig = $xml.Configuration
                If ($null -ne $CacheServiceConfig) {
                    If ($CacheServiceConfig.CanBypassProxyCacheService -eq "False") {
                        Write-Warning "Patch profile doesn't allow PME to fallback to external sources, if probe is not reachable PME may not work!"
                    }
                    ElseIf ($CacheServiceConfig.CanBypassProxyCacheService -eq "True") {
                        Write-Host "INFO: Patch profile allows PME to fallback to external sources" -ForegroundColor Yellow -BackgroundColor Black
                    }
                    Else {
                        Write-Warning "Unable to determine if patch profile allows PME to fallback to external sources"
                    }

                    If ($CacheServiceConfig.CacheSizeInMB -eq 10240) {
                        Write-Host "INFO: Cache Service is set to default cache size of 10240 MB" -ForegroundColor Yellow -BackgroundColor Black
                    }
                    Else {
                        $CacheSize = $CacheServiceConfig.CacheSizeInMB
                        Write-Warning "Cache Service is not set to default cache size of 10240 MB (currently $CacheSize MB), PME may not work at expected!"
                    }
                }
                Else {
                    Write-Warning "Cache Service config file is empty, skipping checks"
                }
        }
        Else {
            Write-Warning "Cache Service config file does not exist, skipping checks"
        }
    }
    Catch {
        Write-Warning "Unable to read Cache Service config file as a valid xml file, default cache size can't be checked"
    }
}

Function Set-PMEConfig {
    # Reserved for future use
    Write-Host "Setting PME Configuration..." -ForegroundColor Cyan
}

Function Install-PME {
    Write-Host "Install PME..." -ForegroundColor Cyan
    # Check Setup Exists in PME Archive Directory
    If (Test-Path -Path "$PMEArchives\PMESetup_$($PMEDetails.Version).exe") {
        # Check Hash
        Write-Output "Checking hash of local file at '$PMEArchives\PMESetup_$($PMEDetails.Version).exe'"
        $Download = Get-LegacyHash -Path "$PMEArchives\PMESetup_$($PMEDetails.Version).exe"
        If ($Download -eq $($PMEDetails.SHA256Checksum)) {
            # Install
            Write-Output "Local copy of $($PMEDetails.FileName) is current and hash is correct"
            If (Test-Path -Path "$PMEProgramDataPath\Repair-PME") {
                Write-Output "Directory '$PMEProgramDataPath\Repair-PME' already exists, no need to create directory"
            }
            Else {
                Try {
                    Write-Output "Directory '$PMEProgramDataPath\Repair-PME' does not exist, creating directory"
                    [Void](New-Item -ItemType Directory -Path "$PMEProgramDataPath\Repair-PME" -Force)
                }
                Catch {
                    Write-EventLog @WriteEventLogErrorParams -Message "Unable to create directory '$PMEProgramDataPath\Repair-PME' required for saving log capture. Error: $($_.Exception.Message).`nScript: Repair-PME.ps1"
                    Throw "Unable to create directory '$PMEProgramDataPath\Repair-PME' required for saving log capture. Error: $($_.Exception.Message)"
                }
            }
            Write-Output "Installing $($PMEDetails.FileName) - logs will be saved to '$PMEProgramDataPath\Repair-PME'"
            $DateTime = Get-Date -Format 'yyyy-MM-dd HH-mm-ss'
            $StartProcessParams = @{
                FilePath     = "$PMEArchives\PMESetup_$($PMEDetails.Version).exe"
                ArgumentList = "/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS /LOG=`"$PMEProgramDataPath\Repair-PME\Setup-Log-$DateTime.txt`""
                Wait         = $true
                PassThru     = $true
            }
            $Install = Start-Process @StartProcessParams
            If ($Install.ExitCode -eq 0) {
                Write-Host "OK: $($PMEDetails.Name) version $($PMEDetails.Version) successfully installed" -ForegroundColor Green
            } ElseIf ($Install.ExitCode -eq 5) {
                Write-EventLog @WriteEventLogErrorParams -Message "$($PMEDetails.Name) version $($PMEDetails.Version) was unable to be successfully installed because access is denied, exit code $($Install.ExitCode).`nScript: Repair-PME.ps1"
                Throw "$($PMEDetails.Name) version $($PMEDetails.Version) was unable to be successfully installed because access is denied, exit code $($Install.ExitCode)"
            }
            Else {
                Write-EventLog @WriteEventLogErrorParams -Message "$($PMEDetails.Name) version $($PMEDetails.Version) was unable to be successfully installed, exit code $($Install.ExitCode) see 'https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-'.`nScript: Repair-PME.ps1"
                Throw "$($PMEDetails.Name) version $($PMEDetails.Version) was unable to be successfully installed, exit code $($Install.ExitCode) see 'https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-'"
            }
        }
        Else {
            # Download
            Write-Output "Hash of local file ($($Download.SHA256Checksum)) does not equal hash ($($PMEDetails.SHA256Checksum)) from sis.n-able.com, downloading the latest available version"
            . Get-PMESetup
            # Check Hash
            Write-Output "Checking hash of local file at '$PMEArchives\PMESetup_$($PMEDetails.Version).exe'"
            $Download = Get-LegacyHash -Path "$PMEArchives\PMESetup_$($PMEDetails.Version).exe"
            If ($Download -eq $($PMEDetails.SHA256Checksum)) {
                # Install
                Write-Output "Hash of file is correct"
                If (Test-Path -Path "$PMEProgramDataPath\Repair-PME") {
                    Write-Output "Directory '$PMEProgramDataPath\Repair-PME' already exists, no need to create directory"
                }
                Else {
                    Try {
                        Write-Output "Directory '$PMEProgramDataPath\Repair-PME' does not exist, creating directory"
                        [Void](New-Item -ItemType Directory -Path "$PMEProgramDataPath\Repair-PME" -Force)
                    }
                    Catch {
                        Write-EventLog @WriteEventLogErrorParams -Message "Unable to create directory '$PMEProgramDataPath\Repair-PME' required for saving log capture. Error: $($_.Exception.Message).`nScript: Repair-PME.ps1"
                        Throw "Unable to create directory '$PMEProgramDataPath\Repair-PME' required for saving log capture. Error: $($_.Exception.Message)"
                    }
                }
                Write-Output "Installing $($PMEDetails.FileName) - logs will be saved to '$PMEProgramDataPath\Repair-PME'"
                $DateTime = Get-Date -Format 'yyyy-MM-dd HH-mm-ss'
                $StartProcessParams = @{
                    FilePath     = "$PMEArchives\PMESetup_$($PMEDetails.Version).exe"
                    ArgumentList = "/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS /LOG=`"$PMEProgramDataPath\Repair-PME\Setup-Log-$DateTime.txt`""
                    Wait         = $true
                    PassThru     = $true
                }
                $Install = Start-Process @StartProcessParams
                If ($Install.ExitCode -eq 0) {
                    Write-Host "OK: $($PMEDetails.Name) version $($PMEDetails.Version) successfully installed" -ForegroundColor Green
                } ElseIf ($Install.ExitCode -eq 5) {
                    Write-EventLog @WriteEventLogErrorParams -Message "$($PMEDetails.Name) version $($PMEDetails.Version) was unable to be successfully installed because access is denied, exit code $($Install.ExitCode).`nScript: Repair-PME.ps1"
                    Throw "$($PMEDetails.Name) version $($PMEDetails.Version) was unable to be successfully installed because access is denied, exit code $($Install.ExitCode)"
                }
                Else {
                    Write-EventLog @WriteEventLogErrorParams -Message "$($PMEDetails.Name) version $($PMEDetails.Version) was unable to be successfully installed, exit code $($Install.ExitCode) see 'https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-'.`nScript: Repair-PME.ps1"
                    Throw "$($PMEDetails.Name) version $($PMEDetails.Version) was unable to be successfully installed, exit code $($Install.ExitCode) see 'https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-'"
                }
            }
            Else {
                Write-EventLog @WriteEventLogErrorParams -Message "Hash of file downloaded ($($Download.SHA256Checksum)) does not equal hash ($($PMEDetails.SHA256Checksum)) from sis.n-able.com, aborting.`nScript: Repair-PME.ps1"
                Throw "Hash of file downloaded ($($Download.SHA256Checksum)) does not equal hash ($($PMEDetails.SHA256Checksum)) from sis.n-able.com, aborting"
            }
        }
    }
    Else {
        Write-Output "$($PMEDetails.FileName) does not exist, begin download and install phase"
        # Check for PME Archive Directory
        If (Test-Path -Path "$PMEArchives") {
            Write-Output "Directory '$PMEArchives' already exists, no need to create directory"
        }
        Else {
            Try {
                Write-Output "Directory '$PMEArchives' does not exist, creating directory"
                [Void](New-Item -ItemType Directory -Path "$PMEArchives" -Force)
            }
            Catch {
                Write-EventLog @WriteEventLogErrorParams -Message "Unable to create directory '$PMEArchives' required for download, aborting. Error: $($_.Exception.Message).`nScript: Repair-PME.ps1"
                Throw "Unable to create directory '$PMEArchives' required for download, aborting. Error: $($_.Exception.Message)"
            }
        }
        # Download
        . Get-PMESetup
        # Check Hash
        Write-Output "Checking hash of local file at '$PMEArchives\PMESetup_$($PMEDetails.Version).exe'"
        $Download = Get-LegacyHash -Path "$PMEArchives\PMESetup_$($PMEDetails.Version).exe"
        If ($Download -eq $($PMEDetails.SHA256Checksum)) {
            # Install
            Write-Output "Hash of file is correct"
            If (Test-Path -Path "$PMEProgramDataPath\Repair-PME") {
                Write-Output "Directory '$PMEProgramDataPath\Repair-PME' already exists, no need to create directory"
            }
            Else {
                Try {
                    Write-Output "Directory '$PMEProgramDataPath\Repair-PME' does not exist, creating directory"
                    [Void](New-Item -ItemType Directory -Path "$PMEProgramDataPath\Repair-PME" -Force)
                } 
                Catch {
                    Write-EventLog @WriteEventLogErrorParams -Message "Unable to create directory '$PMEProgramDataPath\Repair-PME' required for saving log capture. Error: $($_.Exception.Message).`nScript: Repair-PME.ps1"
                    Throw "Unable to create directory '$PMEProgramDataPath\Repair-PME' required for saving log capture. Error: $($_.Exception.Message)"
                }
            }
            Write-Output "Installing $($PMEDetails.FileName) - logs will be saved to '$PMEProgramDataPath\Repair-PME'"
            $DateTime = Get-Date -Format 'yyyy-MM-dd HH-mm-ss'
            $StartProcessParams = @{
                FilePath     = "$PMEArchives\PMESetup_$($PMEDetails.Version).exe"
                ArgumentList = "/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS /LOG=`"$PMEProgramDataPath\Repair-PME\Setup Log $DateTime.txt`""
                Wait         = $true
                PassThru     = $true
            }
            $Install = Start-Process @StartProcessParams
            If ($Install.ExitCode -eq 0) {
                Write-Host "OK: $($PMEDetails.Name) version $($PMEDetails.Version) successfully installed" -ForegroundColor Green
            } ElseIf ($Install.ExitCode -eq 5) {
                Write-EventLog @WriteEventLogErrorParams -Message "$($PMEDetails.Name) version $($PMEDetails.Version) was unable to be successfully installed because access is denied, exit code $($Install.ExitCode).`nScript: Repair-PME.ps1"
                Throw "$($PMEDetails.Name) version $($PMEDetails.Version) was unable to be successfully installed because access is denied, exit code $($Install.ExitCode)"
            } 
            Else {
                Write-EventLog @WriteEventLogErrorParams -Message "$($PMEDetails.Name) version $($PMEDetails.Version) was unable to be successfully installed, exit code $($Install.ExitCode) see 'https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-'.`nScript: Repair-PME.ps1"
                Throw "$($PMEDetails.Name) version $($PMEDetails.Version) was unable to be successfully installed, exit code $($Install.ExitCode) see 'https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-'"
            }
        } 
        Else {
            Write-EventLog @WriteEventLogErrorParams -Message "Hash of file downloaded ($($Download.SHA256Checksum)) does not equal hash ($($PMEDetails.SHA256Checksum)) from sis.n-able.com, aborting.`nScript: Repair-PME.ps1"
            Throw "Hash of file downloaded ($($Download.SHA256Checksum)) does not equal hash ($($PMEDetails.SHA256Checksum)) from sis.n-able.com, aborting"
        }
    }
}

Function Confirm-PMEServices {
    If ($Install.ExitCode -eq 0) {
        Write-Host "Checking PME services post-installation..." -ForegroundColor Cyan
        $FileCacheServiceAgentStatus = (get-service "SolarWinds.MSP.CacheService" -ErrorAction SilentlyContinue).Status
        $PMEAgentStatus              = (get-service "PME.Agent.PmeService" -ErrorAction SilentlyContinue).Status
        $RequestHandlerAgentStatus   = (get-service "SolarWinds.MSP.RpcServerService" -ErrorAction SilentlyContinue).status

        Write-Output "PME Agent Status: $PMEAgentStatus"
        Write-Output "File Cache Service Agent Status: $FileCacheServiceAgentStatus"
        Write-Output "Request Handler Agent: $RequestHandlerAgentStatus"
    
        If (($PMEAgentStatus -eq 'Running') -and ($FileCacheServiceAgentStatus -eq 'Running') -and ($RequestHandlerAgentStatus -eq 'Running')) {
            Write-Host "OK: All PME services are installed and running following installation" -Foregroundcolor Green
        }
        Else {
            Write-EventLog @WriteEventLogErrorParams -Message "One or more of the PME services are not installed or running, investigation required.`nScript: Repair-PME.ps1"
            Throw "One or more of the PME services are not installed or running, investigation required"
        }
    }
}

Function Set-End {
    Write-EventLog @WriteEventLogInformationParams -Message "Repair-PME has finished.`nScript: Repair-PME.ps1"
}

. Confirm-Elevation
. Set-Start
. Get-OSVersion
. Get-OSArch
. Get-PMELocations
. Get-PSVersion
. Set-CryptoProtocol
. Invoke-Delay
. Get-RepairPMEUpdate
. Test-Connectivity
. Test-NableCertificate
. Get-NCAgentVersion
. Confirm-PMEInstalled
. Get-PMESetupDetails
. Confirm-PMERecentInstall
. Confirm-PMEUpdatePending
. Clear-RepairPME
. Invoke-PMEDiagnostics
. Stop-PMESetup
. Stop-PMEServices
. Clear-PME
. Get-PMEConfigMisconfigurations
# . Set-PMEConfig
. Install-PME
. Confirm-PMEServices
. Set-End