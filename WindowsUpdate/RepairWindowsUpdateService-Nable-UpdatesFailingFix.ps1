#Stop Services
net stop wuauserv
net stop cryptSvc
net stop bits
net stop msiserver

remove-Item -path "C:\Windows\SoftwareDistribution" -Recurse -force -Confirm

#Restart Service
net start wuauserv
net start cryptSvc
net start bits
net start msiserver