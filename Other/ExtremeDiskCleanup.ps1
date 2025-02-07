# Name: RemoteDiskCleanup.ps1                              
# Creator: Damien O'Brien                
# CreationDate: 4.4.2022                                                            
# Version: 1.3
# Purpose: Cleanup system with near zero Hard drive space by Force.
# Requirements: Admin access, Powershell on remote pc

# --------------------------- Script begins here --------------------------- #

#Requires -RunAsAdministrator
Set-ExecutionPolicy RemoteSigned

# This will check all Disk Cleanup boxes by manually setting each key in the following registry path to 2.
# Comment out the files that you do not want Disk Cleanup to erase.
$SageSet = "StateFlags0099"
$StateFlags= "Stateflags0099"
$Base = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\"
$VolCaches = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"

$Locations = @(
    "Active Setup Temp Folders"
    "BranchCache"
    "Downloaded Program Files"
    "GameNewsFiles"
    "GameStatisticsFiles"
    "GameUpdateFiles"
    "Internet Cache Files"
    "Memory Dump Files"
    "Offline Pages Files"
    "Old ChkDsk Files"
    "Previous Installations"
    #"Recycle Bin"
    "Service Pack Cleanup"
    "Setup Log Files"
    "System error memory dump files"
    "System error minidump files"
    "Temporary Files"
    "Temporary Setup Files"
    "Temporary Sync Files"
    "Thumbnail Cache"
    "Update Cleanup"
    "Upgrade Discarded Files"
    "User file versions"
    "Windows Defender"
    "Windows Error Reporting Archive Files"
    "Windows Error Reporting Queue Files"
    "Windows Error Reporting System Archive Files"
    "Windows Error Reporting System Queue Files"
    "Windows ESD installation files"
    "Windows Upgrade Log Files"
)

Function Get-Recyclebin{
    [CmdletBinding()]
    Param
    (
        $ComputerOBJ,
        $RetentionTime = "3"
    )
    Write-Host "Empyting Recycle bin items older than $RetentionTime days" -ForegroundColor Yellow
    If($ComputerOBJ.PSRemoting -eq $true){
        $Result = Invoke-Command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
        
        Try{
            $Shell = New-Object -ComObject Shell.Application
            $Recycler = $Shell.NameSpace(0xa)
            $Recycler.Items() 

            foreach($item in $Recycler.Items())
            {
                $DeletedDate = $Recycler.GetDetailsOf($item,2) -replace "\u200f|\u200e","" #Invisible Unicode Characters
                $DeletedDatetime = Get-Date $DeletedDate 
                [Int]$DeletedDays = (New-TimeSpan -Start $DeletedDatetime -End $(Get-Date)).Days

                If($DeletedDays -ge $RetentionTime)
                {
                    Remove-Item -Path $item.Path -Confirm:$false -Force -Recurse
                }
            }
        }
        Catch [System.Exception]{
            $RecyclerError = $true
        }
        Finally{
            If($RecyclerError -eq $False){
                Write-output $True 
            }
            Else{
                Write-Output $False
            }
        }

        
    } -Credential $ComputerOBJ.Credential
        If($Result -eq $True){
            Write-Host "All recycle bin items older than $RetentionTime days were deleted" -ForegroundColor Green
        }
        Else{
            Write-Host "Unable to delete some items in the Recycle Bin." -ForegroundColor Red
        }
    }
    Else{
        Try{
            $Shell = New-Object -ComObject Shell.Application
            $Recycler = $Shell.NameSpace(0xa)
            $Recycler.Items() 

            foreach($item in $Recycler.Items())
            {
                $DeletedDate = $Recycler.GetDetailsOf($item,2) -replace "\u200f|\u200e","" #Invisible Unicode Characters
                $DeletedDatetime = Get-Date $DeletedDate 
                [Int]$DeletedDays = (New-TimeSpan -Start $DeletedDatetime -End $(Get-Date)).Days

                If($DeletedDays -ge $RetentionTime)
                {
                    Remove-Item -Path $item.Path -Confirm:$false -Force -Recurse
                }
            }
        }
        Catch [System.Exception]{
            $RecyclerError = $true
        }
        Finally{
            If($RecyclerError -eq $true){
                Write-Host "Unable to delete some items in the Recycle Bin." -ForegroundColor Red
            }
            Else{
                Write-Host "All recycle bin items older than $RetentionTime days were deleted" -ForegroundColor Green
            }
        }
    }    
}

Function Clean-Path{

    Param
    (
        [String]$Path,
        $ComputerOBJ
    )
    Write-Host "`t...Cleaning $Path"
    If($ComputerOBJ.PSRemoting -eq $True){

        Invoke-Command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {

            If(Test-Path $Using:Path){

                Foreach($Item in $(Get-ChildItem -Path $Using:Path -Recurse)){
    
                    Try{
                        Remove-item -Path $item.FullName -Confirm:$False -Recurse -ErrorAction Stop
                    }
                    Catch [System.Exception]{
                        Write-verbose "$($Item.path) - $($_.Exception.Message)"
                    }
                }
            }

        } -Credential $ComputerOBJ.Credential
    }
    Else{

        If(Test-Path $Path){
        
        Foreach($Item in $(Get-ChildItem -Path $Path -Recurse)){
    
            Try{
                Remove-item -Path $item.FullName -Confirm:$False -Recurse -ErrorAction Stop
            }
            Catch [System.Exception]{
                Write-verbose "$($Item.path) - $($_.Exception.Message)"
            }
        }
    }



    }
}

Function Get-OrigFreeSpace{

    Param
    (
        $ComputerOBJ
    )

    Try{
        $RawFreespace = (Get-WmiObject Win32_logicaldisk -ComputerName $ComputerOBJ.ComputerName -Credential $ComputerOBJ.Credential -ErrorAction Stop | Where-Object {$_.DeviceID -eq 'C:'}).freespace
        $FreeSpaceGB = [decimal]("{0:N2}" -f($RawFreespace/1gb))
        Write-host "Current Free Space on the OS Drive : $FreeSpaceGB GB" -ForegroundColor Magenta
    }
    Catch [System.Exception]{
        $FreeSpaceGB = $False
        Write-Host "Unable to pull free space from OS drive. Press enter to Exit..." -ForegroundColor Red    
    }
    Finally{
        $ComputerOBJ | Add-Member -MemberType NoteProperty -Name OrigFreeSpace -Value $FreeSpaceGB
        Write-output $ComputerOBJ
    }
}

Function Get-FinalFreeSpace{

    Param
    (
        $ComputerOBJ
    )

    Try{
        $RawFreespace = (Get-WmiObject Win32_logicaldisk -ComputerName $ComputerOBJ.ComputerName -Credential $ComputerOBJ.Credential -ErrorAction Stop | Where-Object {$_.DeviceID -eq 'C:'}).freespace
        $FreeSpaceGB = [decimal]("{0:N2}" -f($RawFreespace/1gb))
        Write-host "Final Free Space on the OS Drive : $FreeSpaceGB GB" -ForegroundColor Magenta
    }

    Catch [System.Exception]{
        $FreeSpaceGB = $False
        Write-Host "Unable to pull free space from OS drive. Press enter to Exit..." -ForegroundColor Red    
    }
    Finally{
        $ComputerOBJ | Add-Member -MemberType NoteProperty -Name FinalFreeSpace -Value $FreeSpaceGB
        Write-output $ComputerOBJ
    }
} 

Function Get-Computername {

    Write-Host "Please enter the computername to connect to or just hit enter for localhost" -ForegroundColor Yellow
    $ComputerName = Read-Host

    if($ComputerName -eq '' -or $ComputerName -eq $null){
        $obj = New-object PSObject -Property @{
            ComputerName = $env:COMPUTERNAME
            Remote = $False
        }
    }
    else{
        $obj = New-object PSObject -Property @{
            ComputerName = $Computername
            Remote = $True
        }
    }

    Write-output $obj

}

Function Test-PSRemoting{

    Param
    (
        $ComputerOBJ
    )

    Write-Host "Please enter your credentials for the remote machine." -ForegroundColor Yellow
    $ComputerOBJ | Add-Member NoteProperty -Name Credential -Value (Get-Credential)

    $RemoteHostname = Invoke-command -ComputerName $ComputerOBJ.Computername -ScriptBlock {hostname} -Credential $ComputerOBJ.Credential -erroraction 'silentlycontinue'

    If($RemoteHostname -eq $ComputerOBJ.Computername){
        Write-Host "PowerShell Remoting was successful" -ForegroundColor Green
        $ComputerOBJ | Add-Member NoteProperty -Name PSRemoting -Value $True
    }
    Else {
        Write-host "PowerShell Remoting FAILED press enter to exit script." -ForegroundColor Red
        $ComputerOBJ | Add-Member NoteProperty -Name PSRemoting -Value $False
    }

    Write-output $ComputerOBJ
}

Function Run-CleanMGR{

    Param
    (
        $ComputerOBJ
    )

    If($ComputerOBJ.PSRemoting -eq $true){
        Write-Host "Attempting to Run Windows Disk Cleanup With Parameters..." -ForegroundColor Yellow
        Write-Host "`tApplying $sageset parameters to registry path:"
        Write-Host "`t$Base"
        $CleanMGR = Invoke-command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
                        $ErrorActionPreference = 'Stop'
                        Try{

                            # Set Sageset99/Stateflag0099 reg keys to 1 for a blank slate.
                            foreach($VC in $VolCaches){
                                New-ItemProperty -Path "$($VC.PSPath)" -Name $StateFlags -Value 1 -Type DWORD -Force | Out-Null
                            } 

                            ForEach($Location in $Locations) {
                                Set-ItemProperty -Path $($Base+$Location) -Name $SageSet -Type DWORD -Value 2 -ea silentlycontinue | Out-Null
                            }
                                                       
                            # Convert the Sageset number previously defined and Run the Disk Cleanup process with configured parameters.
                            $Args = "/sagerun:$([string]([int]$SageSet.Substring($SageSet.Length-4)))"
                            Start-Process -Wait "$env:SystemRoot\System32\cleanmgr.exe" -ArgumentList $Args -WindowStyle Hidden
                            
                            # Set Sageset99/Stateflag0099 reg keys back to 1 for a blank slate.
                            foreach($VC in $VolCaches){
                            New-ItemProperty -Path "$($VC.PSPath)" -Name $StateFlags -Value 1 -Type DWORD -Force | Out-Null
                            } 
                            $ErrorActionPreference = 'SilentlyContinue'
                            #Write-Output $true
                        }
                        Catch [System.Exception]{
                            $ErrorActionPreference = 'SilentlyContinue'
                            #Write-output $False
                        }
                    } -Credential $ComputerOBJ.Credential

        If($CleanMGR -eq $True){
            ForEach($Location in $Locations) {
                Write-Host "`t...Cleaning $Location"
            }
            Write-Host "Windows Disk Cleanup has been run successfully." -ForegroundColor Green
        }
        Else{
            Write-host "Cleanmgr is not installed! To use this portion of the script you must install the following windows features:" -ForegroundColor Red
            Write-host "Desktop-Experience, Ink-Handwriting" -ForegroundColor Red
        }
    }
    Else{

        Write-Host "Attempting to Run Windows Disk Cleanup With Parameters..." -ForegroundColor Yellow
        Write-Host "`tApplying $sageset parameters to registry path:"
        Write-Host "`t$Base"
        Echo ""
        $ErrorActionPreference = 'Stop'
        Try{

            # Set Sageset99/Stateflag0099 reg keys to 1 for a blank slate.
            foreach($VC in $VolCaches){
                New-ItemProperty -Path "$($VC.PSPath)" -Name $StateFlags -Value 1 -Type DWORD -Force | Out-Null
            } 

            ForEach($Location in $Locations) {
                Set-ItemProperty -Path $($Base+$Location) -Name $SageSet -Type DWORD -Value 2 -ea silentlycontinue | Out-Null
            }

            # Convert the Sageset number previously defined and Run the Disk Cleanup process with configured parameters.
            $Args = "/sagerun:$([string]([int]$SageSet.Substring($SageSet.Length-4)))"
            Start-Process -Wait "$env:SystemRoot\System32\cleanmgr.exe" -ArgumentList $Args -WindowStyle Hidden

            # Set Sageset99/Stateflag0099 reg keys back to 1 for a blank slate.
            foreach($VC in $VolCaches){
                New-ItemProperty -Path "$($VC.PSPath)" -Name $StateFlags -Value 1 -Type DWORD -Force | Out-Null
            } 
            $ErrorActionPreference = 'SilentlyContinue'
            #Write-Output $true 
            ForEach($Location in $Locations) {
                Write-Host "`t...Cleaning $Location"
            }
            Write-Host "Windows Disk Cleanup has been run successfully." -ForegroundColor Green
        }
        Catch [System.Exception]{
          Write-host "Cleanmgr is not installed! To use this portion of the script you must install the following windows features:" -ForegroundColor Red
          Write-host "Desktop-Experience, Ink-Handwriting" -ForegroundColor Red

        }
        $ErrorActionPreference = 'SilentlyContinue'
    }
}

Function Erase-IExplorerHistory{

    Param
    (
        $ComputerOBJ
    )

    If($ComputerOBJ.PSRemoting -eq $true){
        Write-Host "Attempting to Erase Internet Explorer temp data" -ForegroundColor Yellow
        $CleanIExplorer = Invoke-command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
                        $ErrorActionPreference = 'Stop'
                        Try{
                            Start-Process -FilePath rundll32.exe -ArgumentList 'inetcpl.cpl,ClearMyTracksByProcess 4351' -Wait -NoNewWindow
                            $ErrorActionPreference = 'SilentlyContinue'
                            #Write-Output $true
                        }
                        Catch [System.Exception]{
                            $ErrorActionPreference = 'SilentlyContinue'
                            #Write-output $False
                        }
                    } -Credential $ComputerOBJ.Credential

        If($CleanIExplorer -eq $True){
            Write-Host "Internet Explorer temp data has been successfully erased" -ForegroundColor Green
        }
        Else{
            Write-host "Failed to erase Internet Explorer temp data" -ForegroundColor Red
        }
    }
    Else{

        Write-Host "Attempting to Erase Internet Explorer temp data" -ForegroundColor Yellow
        $ErrorActionPreference = 'Stop'
        Try{
            Start-Process -FilePath rundll32.exe -ArgumentList 'inetcpl.cpl,ClearMyTracksByProcess 4351' -Wait -NoNewWindow
            Write-Host "Internet Explorer temp data has been successfully erased" -ForegroundColor Green
        }
        Catch [System.Exception]{
          Write-host "Failed to erase Internet Explorer temp data" -ForegroundColor Red
        }
        $ErrorActionPreference = 'SilentlyContinue'
    }
}

Function Run-DISM{

    Param
    (
        $ComputerOBJ
    )

    If($ComputerOBJ.PSRemoting -eq $true){
    Write-Host "Running DISM to clean old servicepack files" -ForegroundColor Yellow
    $DISM = Invoke-command -ComputerName $ComputerOBJ.ComputerName -ScriptBlock {
                $ErrorActionPreference = 'Stop'
                Try{
                    $DISMResult = dism.exe /online /cleanup-Image /spsuperseded
                    $ErrorActionPreference = 'SilentlyContinue'
                    Write-Output $DISMResult
                }
                Catch [System.Exception]{
                    $ErrorActionPreference = 'SilentlyContinue'
                    Write-output $False
                }
                } -Credential $ComputerOBJ.Credential

    If($DISM -match 'The operation completed successfully'){
        Write-Host "DISM Completed Successfully." -ForegroundColor Green
    }
    Else{
        Write-Host "Unable to clean old ServicePack Files." -ForegroundColor Red
    }
}
    Else{
        Write-Host "Running DISM to clean old servicepack files" -ForegroundColor Yellow
        $ErrorActionPreference = 'Stop'
        Try{
            $DISMResult = dism.exe /online /cleanup-Image /spsuperseded
            $ErrorActionPreference = 'SilentlyContinue'
        }
        Catch [System.Exception]{
            $ErrorActionPreference = 'SilentlyContinue'
            $DISMResult = $False
        }
        $ErrorActionPreference = 'SilentlyContinue'
        If($DISMResult -match 'The operation completed successfully'){
            Write-Host "DISM Completed Successfully." -ForegroundColor Green
        }
        Else{
            Write-Host "Unable to clean old ServicePack Files." -ForegroundColor Red
        }
    }
}

Clear-Host
Echo "  **This tool will attempt to remove bloatware and erase temp files across all user profiles. Please use with caution.**"
Echo ""
$ComputerOBJ = Get-ComputerName
Echo "You have entered $ComputerOBJ. Is this correct?"
Pause
Echo ""

Start-Transcript -Path C:\Windows\System32\CleanupLogs\$ComputerOBJ.txt
[System.DateTime]::Now
Echo ""

Echo "********************************************************************************************************************"
If($ComputerOBJ.Remote -eq $true){
    $ComputerOBJ = Test-PSRemoting -ComputerOBJ $ComputerOBJ
    If($ComputerOBJ.PSRemoting -eq $False){
        Read-Host
        exit;
    }
}

$ComputerOBJ = Get-OrigFreeSpace -ComputerOBJ $ComputerOBJ

If($ComputerOBJ.OrigFreeSpace -eq $False){
    Read-host
    exit;
}
Echo "********************************************************************************************************************"
Echo ""

#======================================================================================================================================================

Write-Host "Cleaning temp directories across all user profiles" -ForegroundColor Yellow

Clean-path -Path 'C:\Temp\*' -Verbose -ComputerOBJ $ComputerOBJ
Clean-path -Path 'C:\Windows\Temp\*' -Verbose -ComputerOBJ $ComputerOBJ
Clean-Path -Path 'C:\Users\*\Documents\*tmp' -Verbose -ComputerOBJ $ComputerOBJ
Clean-path -Path 'C:\Documents and Settings\*\Local Settings\Temp\*' -ComputerOBJ $ComputerOBJ
Clean-path -Path 'C:\Users\*\Appdata\Local\Temp\*' -Verbose -ComputerOBJ $ComputerOBJ
Clean-path -Path 'C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*' -Verbose -ComputerOBJ $ComputerOBJ
Clean-path -Path 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Cookies\*' -Verbose -ComputerOBJ $ComputerOBJ

## Optional paths. Clean at your own risk.
#Clean-path -Path 'C:\ServiceProfiles\LocalService\AppData\Local\Temp\*' -Verbose -ComputerOBJ $ComputerOBJ
#Clean-path -Path 'C:\Windows\Prefetch' -Verbose -ComputerOBJ $ComputerOBJ
#Clean-path -Path 'C:\Users\*\AppData\Local\Microsoft\Windows\INetCache'-Verbose -ComputerOBJ $ComputerOBJ
#Clean-Path -Path 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent' -Verbose -ComputerOBJ $ComputerOBJ
#Clean-Path -Path 'C:\AppData\Roaming\Microsoft\Windows\Recent' -Verbose -ComputerOBJ $ComputerOBJ
#Clean-Path -Path 'C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Cache' -Verbose -ComputerOBJ $ComputerOBJ
#Clean-Path -Path 'C:\Users\*\AppData\Local\Mozilla\Firefox\Profiles\*.default' -Verbose -ComputerOBJ $ComputerOBJ
#Clean-Path -Path 'C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*.default' -Verbose -ComputerOBJ $ComputerOBJ
#Clean-path -Path 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive' -Verbose -ComputerOBJ $ComputerOBJ
#Clean-path -Path 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue' -Verbose -ComputerOBJ $ComputerOBJ

Write-Host "All Temp Paths have been cleaned" -ForegroundColor Green
Echo ""

#======================================================================================================================================================

Run-CleanMGR -ComputerOBJ $ComputerOBJ
Echo ""
#Erase-IExplorerHistory -ComputerOBJ $ComputerOBJ
Echo ""
Run-DISM -ComputerOBJ $ComputerOBJ
Echo ""
Get-Recyclebin -ComputerOBJ $ComputerOBJ
Echo ""

Winmgmt /salvagerepository

Echo "********************************************************************************************************************"
$ComputerOBJ = Get-FinalFreeSpace -ComputerOBJ $ComputerOBJ
$SpaceRecovered = $($Computerobj.finalfreespace) - $($ComputerOBJ.OrigFreeSpace)

If($SpaceRecovered -lt 0){
    Write-Host "Less than a Gigabyte of Free Space was Recovered." -ForegroundColor Magenta
}
ElseIf($SpaceRecovered -eq 0){
    Write-host "No Space was Recovered" -ForegroundColor Magenta
}
Else{

    Write-host "Free Space Recovered : $SpaceRecovered GB" -ForegroundColor Magenta
}
Echo "********************************************************************************************************************"

Echo ""
Stop-Transcript

# --------------------------- Script ends here --------------------------- #