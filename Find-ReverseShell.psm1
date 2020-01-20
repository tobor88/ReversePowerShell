<#
.SYNOPSIS
    This cmdlet can be used to discover reverse shell connections from the past 24 hours. It will ignore connections from
    the user Paessler as PRTG uses a similar method for creating a TCP socket listener. This will not identify powercat.ps1
    reverse shell connections as those are created using a different method.

.DESCRIPTION
    Search the Windows Event Viewer for event id 4656 where a tcp listener was created and connected too.

.PARAMETER
    -ComputerName
        This parameter is for helping to better define a connection you may want to look for. This parameter is currently
        not in use for this cmdlet.
.SYNTAX
    Find-ReverseShell [-ComputerName <string>]

.EXAMPLE
    Find-ReverseShell
        This example searches the localhost for evidence of reverse shell connections built on connections to a tcp socket.

    Find-ReverseShell -ComputerName Desktop01
        This example searches for connections from a remote host.
#>
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

    ## This part is a work in progress. Need to discover how to identify this connection.
    # Write-Host "Checking for a Reverse Shell created by a tool such as PowerCat that execute Reverse Shell commands as a process using WSMAN"
    # $PowerCatListenerCheck = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4656 and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='ObjectName']='\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN'] and EventData[Data[@Name='SubjectUserName']!=`'$ComputerName$`']]" | Select Message | fl *

} # End PROCESS

END
{

    If ($TcpListener -ne $Null)
    {

        $TcpListener

        Write-Host "Reverse Shell check has completed. A reverse shell has been discovered to exist from the last 24 hours." -ForegroundColor 'Red'

    }  # End If
    Else
    {

        Write-Host "No Reverse shells have been discovered to exist in the last 24 hours." -ForegroundColor 'Green'

    }  # End Else



} # End END

} # End Function Find-ReverseShell
