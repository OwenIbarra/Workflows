# Alert when the specified text is found in a text file.
#Requires -Version 4

<#
.SYNOPSIS
    Alert when the specified text is found in a text file.
.DESCRIPTION
    Alert when the specified text is found in a text file.
.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##

PARAMETER: -Path "C:\ReplaceMe\WithPath\To\Text.txt"
    File path to the text file you would like to monitor.

PARAMETER: -TextToMatch "ReplaceMeWithTextToFind"
   Text to alert on when found.

.EXAMPLE
    -Path "C:\Test-FileMonitor.txt" -TextToMatch "bat"
    
    [Alert] Found Text!

.EXAMPLE
    -Path "C:\Test-FileMonitor.txt" -TextToMatch "man" -MatchOnlyOnWholeWord
    
    Text Not Found!

PARAMETER: -MatchOnlyOnWholeWord
    Alert only when your given 'Text To Match' is not contained in another word.

PARAMETER: -CaseSensitive
    Alert only when the casing of your specified 'Text To Match' is identical; for example, alert on 'BAT' but not 'bat'.
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2012
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Path,
    [Parameter()]
    [String]$TextToMatch,
    [Parameter()]
    [Switch]$WholeWordOnly = [System.Convert]::ToBoolean($env:matchOnlyOnWholeWord),
    [Parameter()]
    [Switch]$CaseSensitive = [System.Convert]::ToBoolean($env:caseSensitive)
)

begin {
    # Set Dynamic Script Variables
    if($env:textToMatch -and $env:textToMatch -notlike "null"){
        $TextToMatch = $env:textToMatch
    }
    if($env:textFilePath -and $env:textFilePath -notlike "null"){
        $Path = $env:textFilePath
    }

    # Check for local administrator rights.
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Check that a path was given and if not error out.
    if (-not $Path) {
        Write-Host "[Error] A filepath is required!"
        exit 1
    }

    # If not given text to match error out.
    if (-not $TextToMatch){
        Write-Host "[Error] Text to match is required!"
        exit 1
    }

    # Error out if script is running without local administrator rights.
    if (-not (Test-IsElevated)) {
        Write-Host "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Check that the path given exists.
    if (-not (Test-Path -Path $Path)) {
        Write-Host "[Error] File does not exist!"
        exit 1
    }

    # Check that we're given a file and not a folder.
    $File = Get-Item -Path $Path
    if ($File.PSIsContainer) {
        Write-Host "[Error] Please provide a file path, not a directory."
        exit 1
    }

    $ExitCode = 0
}
process {
    # Check if we were given a binary file and if so error out.
    $ByteCount = 1024
    $ByteArray = Get-Content -Path $Path -Encoding Byte -TotalCount $ByteCount
    if ($ByteArray -contains 0 ) {
        Write-Host "[Error] This script does not support searching binary files!"
        exit 1
    }

    # Retrieve file contents.
    $File = Get-Content -Path $Path

    # If file is empty error out.
    if (-not $File) {
        Write-Host "[Error] reading file, file is either empty or you do not have permission to read it."
        exit 1
    }

    # Scan through each-line checking for our text.
    $File | ForEach-Object {
        # Based on the parameters given match the text.  
        if (-not $CaseSensitive -and -not $WholeWordOnly -and $_ -like "*$TextToMatch*") {
            $Match = $True
        }

        if ($CaseSensitive -and -not $WholeWordOnly -and $_ -clike "*$TextToMatch*") {
            $Match = $True
        }

        if ($WholeWordOnly -and -not $CaseSensitive -and $_ -match "\b$TextToMatch\b") {
            $Match = $True
        }

        if ($WholeWordOnly -and $CaseSensitive -and $_ -cmatch "\b$TextToMatch\b") {
            $Match = $True
        }
    }

    # If our text matched alert.
    if ($Match) {
        Write-Host "[Alert] Found Text!"
    }
    else {
        Write-Host "Text Not Found!"
    }

    exit $ExitCode
}
end {
    
    
    
}
