# Test if the Shadow Copy count falls below a set ThreshHold or is 0.
#Requires -Version 5.1

<#
.SYNOPSIS
    Test if the Shadow Copy count falls below a set ThreshHold or is 0.
.DESCRIPTION
    Test if the Shadow Copy count falls below a set ThreshHold or is 0.
.EXAMPLE
     -ThreshHold 3
    Alerts when Shadow Copy count is below a threshold
.OUTPUTS
    None
.NOTES
    Minium Supported OS: Windows 10, Server 2016
    Release Notes: Renamed script and added Script Variable support
#>

[CmdletBinding()]
param (
    [Parameter()]
    [int]
    $ThreshHold = 3
)

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    if (-not $PSBoundParameters.ContainsKey('ThreshHold')) {
        if ($env:ThreshHold -and $env:ThreshHold -notlike "null") {
            $ThreshHold = $env:ThreshHold
        }
        else {
            # Use default
        }
    }
    else {
        # Use what was passed or default
    }
    
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Get the number of shadow copies from WMI and Sum the results
    $ShadowCopies = $(
        try {
            Get-CimInstance -ClassName Win32_ShadowCopy -Property * -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $null
        }
    )

    if (-not $ShadowCopies) {
        # Shadow Copies is 0 or null
        Write-Host "Shadow Copies Count ($Sum) in 0 or null"
        exit 2
    }

    $Sum = $ShadowCopies | Measure-Object -Property Count -Sum -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Sum -ErrorAction SilentlyContinue

    if ($Sum -ge $ThreshHold) {
        Write-Host "Shadow Copy Count ($Sum) greater than or equal to ThreshHold($ThreshHold)"
        exit 0
    }
    else {
        # Shadow Copies is under ThreshHold
        Write-Host "Shadow Copy Count ($Sum) less than ThreshHold($ThreshHold)"
        exit 1
    }
}
end {
    
    
    
}

