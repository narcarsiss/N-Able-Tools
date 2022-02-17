#Requires -RunAsAdministrator

<#What does this Script do?
Repairs the VSS wrihters when the Backup system in N-able fails
It first checks for the Permissions and Reports back to the User in a logfile created in c:\ProCompLogs\BackupLog.txt
#After the server reboot
#please run "vssadmin list writers" to check if the "System Writer" can be displayed.
#verify that the Cryptographic Services logon as the credentials of the "Network Service"


TODO:
- Create Another String capture for the Error State in VSS list writers
- Clean the text so it's easy to read
- Create If else Statement for the ERROR (if Error RUN FIX >> Else Continue)
- Create a block of code what ever the fuck it's called to store the answer in and call it with .RunRepair
-
#>




#Get Computer Name and store as varible
Write-Output "", "!~~~~ DO NOT RUN ON A SERVER ~~~~!",""
Write-Output "****YOU UNDERSTAND THIS SCRIPT MAY MAKE IT WORSE**", "**NO MY FAULT OF PROBLEM**", "**RUN AT OWN RISK**", 
Write-Output "**SCRIPT DOES NOT SUPPORT MACOSx**","**You MUST have a fresh restart of the computer**", "**DO THAT FIRST OKAY!**" "**THEN COME BACK**", "      "
Start-Sleep 10
$UserSaysYes = Read-Host -Prompt 'Do you want to restart this Computer? >>> Y / N'
Write-Output "THIS WILL TAKE A SEC - HOLD ON!", "     "
# Store the Values from the VSSadmin list writers - then select only the lines with "writer name" - then remove "writer name: " from the string
$WriterName = vssadmin list writers | select-string -SimpleMatch "writer name:"
# Dont ask, just know it deleted anything before and after the floaty ' < thing
$CleanedWriter = $WriterName -replace "^.*?writer name: "

if ($UserSaysYes -eq "y") {
    #   Restart computer by force and use the name of this local machine to do so.
    ## #UNCOMMENT BEFORE GOIUNG LIVE ###   Restart-Computer -ComputerName $env:COMPUTERNAME -Force
}
else {
    <#
        HIDDEN AS IT'LL FUCK A WORKING PC
        ****************************************************
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

        TODO:
        - Add Prompt for user to repair Y/N
        - Add Fixes for Each VSS writer
        - Add replacement /Reinstall of VSS writers
        - If State is anything other than "Stable" Runt he Repair for That Writer / Repair
    #>
    switch ($CleanedWriter) {
        "'Task Scheduler Writer'" { Write-Output ">> Task Scheduler Exists: - Exiting" }
        "'VSS Metadata Store Writer'" { Write-Output ">> VSS Metadata Store - Exist" }
        "'Performance Counters Writer'" { Write-Output ">> Performance Counters - Exist" }
        "'System Writer'" { Write-Output ">> System writer - Exists" }
        "'ASR Writer'" { Write-Output ">> ASR Writer - Exists" }
        "'MSSearch Service Writer'" { Write-Output ">> MSSearch Service - Exists" }
        "'Shadow Copy Optimization Writer'" { Write-Output ">> Showod Copy Optimization - Exists" }
        "'WMI Writer'" { Write-Output ">> WMI - Exists" }
        "'COM+ REGDB Writer'" { Write-Output ">> COM+ REGDB - Exists" }
        "'Registry Writer'" { Write-Output ">> Registry - Exists" }
        "'Sentinel Agent Log VSS Writer'" { Write-Output ">> Sentinal Agent Log VSS - Exists" }
        "'Sentinel Agent DFI Research Data VSS Writer'" { Write-Output ">> Sentinal Agent DFI Research Data VSS - Exists" }
        "'Sentinel Agent Database VSS Writer'" { Write-Output ">> Sentianal Agent Database VSS - Exists" }

        Default {
            Write-Output "Didnt Match a record Try again"
        }
    }



}

<#
Stop the following services: Volume Shadow Copy and Microsoft Software Shadow Copy Provider.
Net Stop VSS
Net Stop SWPRV
#stop the shadow copy services: vss and swprv 
#Re-register the VSS components:
regsvr32 /s ole32.dll
regsvr32 /s oleaut32.dll
regsvr32 /s vss_ps.dll
vssvc /register
regsvr32 /s /i swprv.dll
regsvr32 /s /i eventcls.dll
regsvr32 /s es.dll
regsvr32 /s stdprov.dll
regsvr32 /s vssui.dll
regsvr32 /s msxml.dll
regsvr32 /s msxml3.dll
regsvr32 /s msxml4.dll
vssvc /register
Net Start SWPRV
Net Start VSS
#>













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