<#
Script Created by:
- Damien O'Brien
- damien@procomputers.com.au
- Network Operations Center
Property of Pro Computers Business Center 
*************
Script Version 0.4
- Added Clearer Instruction
- Added more files to Delete
- Added Checks to Excemptions
- Fix error on Directory name (no space)
- Added Registry keys
- Added Folder Directory Delete
- Added Administrator warning check
*************

This script to to add exemptions to Windows defender to fix an Install issue with "Security manager" 
This is a know issue by nable and BitDefender and should be resolved in a future update - If not
Then Run this Script on the clients machine then re-deploy the Security manager.
You may need to add c:\windows\Temp\bdcore_tmp folder if the script throws error.
#>
echo "***********************"
echo "***********************"
echo "***********************"
echo "MUST BE RUN IN SAFEMODE"
echo "***********************"
echo "UNTICK SECURITY MANAGER IN N-CENTERAL"
echo "***********************"
echo "SET AV Cleanup to No removal in Setting > Security Manager"
echo "***********************"
echo "***********************"
echo "***********************"
#Requires -RunAsAdministrator

#Check if script is Running as administrator
$IsAdministrator = [Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544'
Write-Output "Is running as Administrator? " $IsAdministrator

#Add exclusions to Windows Defender to allow Security manager to Install.
#Add-MpPreference -ExclusionPath "C:\Program Files\N-Able Technologies\"
#Add-MpPreference -ExclusionPath "C:\Program Files (x86)\N-Able Technologies\"
#Add-MpPreference -ExclusionPath "C:\Program Files\Managed Antivirus\"
#Add-MpPreference -ExclusionPath "C:\Windows\Temp\bdcore_tmp\"

#Create Bdcore_tmp as this sometimes throws an error if it's not there.
New-Item -path C:\windows\Temp\bdcore_tmp
Add-MpPreference -ExclusionPath "C:\Program Files\N-Able Technologies\","C:\Program Files (x86)\N-Able Technologies\","C:\Windows\Temp\bdcore_tmp\"

#List if Exclusions are working
$AreExclusionsAdded = Get-MpPreference | Select-Object -Property ExclusionPath | Format-Table -AutoSize
Write-Output "You should see Exclusions added here if it worked" $AreExclusionsAdded

#Delete Registry Keys associated with the AV defender
Remove-Item -Path HKCU:\SOFTWARE\Bitdefender\*.* -Recurse
Remove-Item -Path HKCU:\SOFTWARE\AVDefender\*.* -Recurse
Remove-Item -Path 'HKCU:\SOFTWARE\N-Able Technologies\AVDefender\*.*' -Recurse

#Delete folders associated with AV Defender
Remove-Item 'C:\Program Files (x86)\N-able Technologies\Windows Agent\AVDefender' -Recurse
Remove-Item 'C:\Program Files\N-able Technologies\AVDefender\' -Recurse
Remove-Item 'C:\Program Data\N-Able Technologies\' -Recurse
Remove-Item 'C:\Program Files(x86)\N-Able Technologies\Windows Agent\config\AVDefender\Config.xml'
Remove-Item 'C:\Program Files(x86)\N-Able Technologies\Windows Agent\config\AVDefender\ErrorManager.xml'