<#What does this Script do?
Repairs the VSS wrihters when the Backup system in N-able fails
It first checks for the Permissions and Reports back to the User in a logfile created in c:\ProCompLogs\BackupLog.txt


#After the server reboot
#please run "vssadmin list writers" to check if the "System Writer" can be displayed.
#verify that the Cryptographic Services logon as the credentials of the "Network Service"
#>
#Requires -RunAsAdministrator
#Get Computer Name and store as varible
Write-Output "DOES NOT SUPPORT MACOSx" "Before you run this Script you **MUST** have a fresh restart of the computer" "Then re-Run this script" "and Select n "

$UserSaysYes = Read-Host -Prompt 'Do you want to restart >>> Y / N?'
Write-Output $UserSaysYes

#Restart computer by force and use the name of this local machine.
if ($UserSaysYes -eq "y") {
    #    Restart-Computer -ComputerName $env:COMPUTERNAME -Force
    Write-Output "Output -Inside loop" #Write-Host "Host- Inside loop"
}
else {
    <#
    Write-Output "Output -Else Statement" 
    Set-Location "c:\windows\system32"
    # Take Ownership of Directory
    Takeown /f %windir%\winsxs\filemaps\* /a
    # Reset default Permissions for all files in directory
    icacls %windir%\winsxs\filemaps\*.* /grant "NT AUTHORITY\SYSTEM:(RX)"
    icacls %windir%\winsxs\filemaps\*.* /grant "NT Service\trustedinstaller:(F)"
    icacls %windir%\winsxs\filemaps\*.* /grant "BUILTIN\Users:(RX)"
    #>


    <#
        Check for list of VSS writers and if one is Missing exit and throw error code
    #>
    # Store writer list into varible then we will string match in a switch statement
    
    $WriterName = vssadmin list writers | select-string -SimpleMatch "writer name:", "state"
    Write-Output "TEST" $WriterName
    switch ($WriterName) {
        'Task Scheduler Writer' { Write-Output "1" }
        'VSS Metadata Store Writer' { Write-Output "2" }
        'Performance Counters Writer' { Write-Output "3" }
        'System Writer' { Write-Output "4" }
        'ASR Writer' { Write-Output "5" }
        'MSSearch Service Writer' { Write-Output "6" }
        'Shadow Copy Optimization Writer' { Write-Output "7" }
        'WMI Writer' { Write-Output "8" }
        'COM+ REGDB Writer' { Write-Output "9" }
        'Registry Writer' { Write-Output "10" }
        'Sentinel Agent Log VSS Writer' { Write-Output "11" }
        'Sentinel Agent DFI Research Data VSS Writer' { Write-Output "12" }
        'Sentinel Agent Database VSS Writer' { Write-Output "13" }

        Default {
            Write-Output "You dun Fuked up, fix your code"
        }
    }



}








<#Test this out Later for shit that shouldnt be done hehehe
[DscResource()]
class NameOfResource {
    [DscProperty(Key)]
    [string] $KeyName
    
    # Gets the resource's current state.
    [NameOfResource] Get() {
        
        return $this
    }
    
    # Sets the desired state of the resource.
    [void] Set() {
        
    }
    
    # Tests if the resource is in the desired state.
    [bool] Test() {
        
    }
}
#>






<#
CHECKS
- Restart Computer - Complete
- Is Mac? - EXIT with Error "This must be done manually" - Complete but Dirty
- check if VSS system writer is Installed or running "system writer"
- Check if the  Cryptographic service user is "Network Service" if not Change it
- Confirm SET-LOCATION for the Switch Statement to run /as VSSadmin wont work without it
- 
#>