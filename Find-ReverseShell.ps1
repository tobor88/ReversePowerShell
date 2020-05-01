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
    https://roberthosborne.com
    
    
.INPUTS
    None


.OUTPUTS
    System.Diagnostics.Eventing.Reader.EventLogntLogRecord
    Find-ReverseShell returns System.Diagnostics.Eventing.Reader.EventLogRecord objects.

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


    Write-Host "Checking for Reverse Shells that connect to a System.Net.Sockets.TcpListener object" -ForegroundColor Cyan
    $TcpListenerCheck = Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=4656 and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='SubjectUserName']!='paessler'] and EventData[Data[@Name='ObjectServer']='WS-Management Listener']]" -ErrorAction SilentlyContinue

    ## This part is a work in progress. Need to discover how to identify this connection.
    # Write-Host "Checking for a Reverse Shell created by a tool such as PowerCat that execute Reverse Shell commands as a process using WSMAN"
    # $PowerCatListenerCheck = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4656 and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='ObjectName']='\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN'] and EventData[Data[@Name='SubjectUserName']!=`'$ComputerName$`']]" | Select Message | fl *

    If ($TcpListenerCheck -ne $Null)
    {

        Write-Verbose "Event was found"
        $TcpListenerCheck | Select-Object -Property *

        Write-Verbose "Building XML file"
        $TcpListenerCheck.ToXml() | Out-File -FilePath $FilePath
        
        Write-Host "Reverse Shell check has completed. A reverse shell has been discovered to exist from the last 24 hours.`n`n$FilePath contains the related events in XML format." -ForegroundColor 'Red'

    }  # End If
    Else
    {

        Write-Host "No Reverse shells have been discovered to exist in the last 24 hours." -ForegroundColor 'Green'

    }  # End Else

} # End Function Find-ReverseShell
