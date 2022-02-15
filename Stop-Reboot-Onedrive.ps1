<#
Script Created by:
**Initial script from StackOverflow - Heavily cut down for our Needs**
- Damien O'Brien
- damien@procomputers.com.au
- Network Operations Center
Property of Pro Computers Business Center 
*************
Script Version 0.2
- Added Registry file to run for Onedrive
- Cleaned Initial Do loop as we dont need as many checks
- Removed System Memory collection
- Added / Removed Downloading of Onedrive as this is Buggy (downloads Webpage XD)
*************

This script Checks for Onedrive, If running It will kill it, the Restart it
#>

#Get Process Onedrive.exe
$Process = Get-Process *OneDrive*
$isRunning = (Get-Process | Where-Object { $_.Name -eq "OneDrive" }).Count -gt 0
#Get Username without domain listing
$UserName = [Environment]::UserName
#Before Looping to check OneDrive Add Onedrive to the Windows Startup
#New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run -Name OneDrive -PropertyType String -Value "%userprofile%\AppData\Local\Microsoft\OneDrive\Onedrive.exe"
#Check if Onedrive is running, if it is Store in Varible other Wise Continue empty
#then Run through the Loop

if ($isRunning) {
   #Silently Exit the Script as nothing to do.
   echo "One Drive is Running - Exiting"
   exit
}
else {
   #If Onedrive is not running do this :)
   do {
      #Get Process Name and kill it if the service starts during the initial run of this Script
      #Thsi is un needed but is a proactive measure because Im paranoid
      get-Process -processname *OneDrive | Stop-process -Force
   }
         #Count Process amounts, if more than 0 then Start process OneDrive
   while ($Process.Count -gt 0)
   
   do {
      echo "OneDrive Started"
      #If Process is dead, then Start Process under the User Profile.
      #Need to verify if this is running under user Profile or if Running under System profile still?
      Start-Process -FilePath "c:\users\$UserName\appdata\local\microsoft\onedrive\Onedrive.exe" -Wait
      exit
   }
            # (-lt Lower Than)
   while ($Process.Count -lt 1)
   
}

<#
Testing stuffs

#Adding Onedrive to Run Folder under Local User


#Auto Onedrive Downloader
If ($Process -like '*onedrive*') {
        echo "Insite IF Statement 1st Level"
        #Download Onedrive from Microsoft
        $ODClient = "https://go.microsoft.com/fwlink/?linkid=844652"
        #Store Setup in Temp folder
        $output = "$ENV:temp"  + '\OneDriveSetup.exe'
        $apppath = "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe"
        $action = New-ScheduledTaskAction -Execute $apppath
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
        Invoke-WebRequest -Uri $ODClient -OutFile $output
        #Install process with "All user and "silent" arguments
        Start-Process -FilePath $output -ArgumentList '/allusers', '/silent'
        Start-Sleep -Seconds 60   
        Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Launch OneDrive" | Out-Null
        Start-ScheduledTask -TaskName "Launch OneDrive"
        Start-Sleep -Seconds 5
        Unregister-ScheduledTask -TaskName "Launch OneDrive" -Confirm:$false
    }

    else {
#>

#powershell -WindowStyle hidden -Command "& {[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms'); [System.Windows.Forms.MessageBox]::Show('Please start your OneDrive application - Start menu > Onedrive','NOTICE Pro Computers Business Center')}"