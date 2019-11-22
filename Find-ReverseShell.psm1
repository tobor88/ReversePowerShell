Function Find-ReverseShell {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$False,
                Positiion=0,
                HelpMessage="Enter a hostname, FQDN, or an IPv4 address")]
            [string]$ComputerName
            ) # End param

BEGIN
{

    If (!($ComputerName.IsPresent))
    {

        $ComputerName = $env:COMPUTERNAME

    } # End If

} # End BEGIN

PROCESS
{

    Write-Host "Checking for Reverse Shells that connect to a System.Net.Sockets.TcpListener object" -ForegroundColor Cyan

    $TcpListenerCheck = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4656 and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='SubjectUserName']!='paessler'] and EventData[Data[@Name='ObjectServer']='WS-Management Listener']]"


    Write-Host "Checking for a Reverse Shell created by a tool such as PowerCat that execute Reverse Shell commands as a process using WSMAN"

    $PowerCatListenerCheck = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4656 and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='ObjectName']='\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN'] and EventData[Data[@Name='SubjectUserName']!=`'$ComputerName$`']]" | Select Message | fl *

} # End PROCESS

END
{

    Write-Host "Reverse Shell check has completed. The last 24 hours have been verified to not have any shells."

} # End END

} # End Function Find-ReverseShell
