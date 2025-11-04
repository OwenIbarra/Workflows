# Condition/Audit UAC Level. Can save the UAC Level to a custom field if specified.
#Requires -Version 2

<#
.SYNOPSIS
    Condition/Audit UAC Level. Can save the UAC Level to a custom field if specified.
.DESCRIPTION
    Condition/Audit UAC Level. Can save the UAC Level to a custom field if specified.

    Exit Code of 0 is that the UAC Level is set to the defaults or higher
    Exit Code of 1 is that the UAC Level is to lower than defaults
    Exit Code of 2 is when this fails to update a custom field
.EXAMPLE
     -CustomField "uac"
    Saves the UAC Level to a custom field.
.OUTPUTS
    String[]
.NOTES
    Minimum OS Architecture Supported: Windows 7, Windows Server 2012
    Release Notes: Renamed script and added Script Variable support
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$CustomField
)

begin {
    if ($env:customFieldName -and $env:customFieldName -notlike "null") { $CustomField = $env:customFieldName }
    
    # https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#registry-key-settings
    # Define the path in the registry
    $Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    # Define the values to check
    $Values = "FilterAdministratorToken",
    "EnableUIADesktopToggle",
    "ConsentPromptBehaviorAdmin",
    "ConsentPromptBehaviorUser",
    "EnableInstallerDetection",
    "ValidateAdminCodeSignatures",
    "EnableSecureUIAPaths",
    "EnableLUA",
    "PromptOnSecureDesktop",
    "EnableVirtualization"

    # This function is to make it easier to set Ninja Custom Fields.

}
process {

    $UacResults = [PSCustomObject]@{}
    # Loop through each value and get each value and add them to $UacResults as a property
    $Values | ForEach-Object {
        $Value = $_
        $Result = $null
        $Result = Get-ItemProperty -Path $Path -Name $Value -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Value
        if ($null -eq $Result) {
            switch ($Value) {
                'FilterAdministratorToken' { $Result = 0; break }
                'EnableUIADesktopToggle' { $Result = 0; break }
                'ConsentPromptBehaviorAdmin' { $Result = 5; break }
                'ConsentPromptBehaviorUser' { $Result = 3; break }
                'EnableInstallerDetection' { $Result = 0; break } # Assumes enterprise and not Home
                'ValidateAdminCodeSignatures' { $Result = 0; break }
                'EnableSecureUIAPaths' { $Result = 1; break }
                'EnableLUA' { $Result = 1; break }
                'PromptOnSecureDesktop' { $Result = 1; break }
                'EnableVirtualization' { $Result = 1; break }
                Default { $Result = 1 }
            }
        }
        $UacResults | Add-Member -MemberType NoteProperty -Name $Value -Value $Result
    }

    # Is UAC enabled or disabled
    if (
        $UacResults.ConsentPromptBehaviorAdmin -eq 5 -and
        $UacResults.ConsentPromptBehaviorUser -eq 3 -and
        $UacResults.EnableLUA -eq 1 -and
        $UacResults.FilterAdministratorToken -eq 0 -and
        $UacResults.EnableUIADesktopToggle -eq 0 -and
        $UacResults.ConsentPromptBehaviorAdmin -eq 5 -and
        $UacResults.ConsentPromptBehaviorUser -eq 3 -and
        # Enterprise
        (
            (
                (Get-CimInstance -ClassName Win32_OperatingSystem).Caption -notlike "*Home*" -and $UacResults.EnableInstallerDetection -eq 1
            ) -or
            (
                (Get-CimInstance -ClassName Win32_OperatingSystem).Caption -like "*Home*" -and $UacResults.EnableInstallerDetection -eq 0
            )
        ) -and
        $UacResults.ValidateAdminCodeSignatures -eq 0 -and
        $UacResults.EnableSecureUIAPaths -eq 1 -and
        $UacResults.EnableLUA -eq 1 -and
        $UacResults.PromptOnSecureDesktop -eq 1 -and
        $UacResults.EnableVirtualization -eq 1
    ) {
        "UAC Enabled with defaults." | Write-Host
    }
    elseif (
        $UacResults.EnableLUA -eq 0 -or
        $UacResults.ConsentPromptBehaviorAdmin -eq 0 -or
        $UacResults.PromptOnSecureDesktop -eq 0
    ) {
        "UAC Disabled." | Write-Host
    }

    # Get the UAC Level
    $UACLevel = if (
        $UacResults.EnableLUA -eq 0
    ) {
        0
    }
    elseif (
        $UacResults.ConsentPromptBehaviorAdmin -eq 5 -and
        $UacResults.PromptOnSecureDesktop -eq 0 -and
        $UacResults.EnableLUA -eq 1
    ) {
        1
    }
    elseif (
        $UacResults.ConsentPromptBehaviorAdmin -eq 5 -and
        $UacResults.PromptOnSecureDesktop -eq 1 -and
        $UacResults.EnableLUA -eq 1
    ) {
        2
    }
    elseif (
        $UacResults.ConsentPromptBehaviorAdmin -eq 2 -and
        $UacResults.PromptOnSecureDesktop -eq 1 -and
        $UacResults.EnableLUA -eq 1
    ) {
        3
    }

    # Get the Text version of the UAC Level
    $UACLevelText = switch ($UACLevel) {
        0 { "Never notify"; break }
        1 { "Notify me only (do not dim my desktop)"; break }
        2 { "Notify me only (default)"; break }
        3 { "Always notify"; break }
        Default { "Unknown"; break }
    }

    # Output the UAC Level
    "UAC Level: $UACLevel = $UACLevelText" | Write-Host

    # Output the UAC settings
    $UacResults | Out-String | Write-Host

    # When CustomField is used save the UAC Level to that custom field
    if ($CustomField) {
        try {
        }
        catch {
            Write-Error "Failed to update Custom Field ($CustomField)"
            exit 2
        }
    }

    # Return and exit code of 0 if UAC is set to the default or higher, or 1 when not set to the default
    if ($UACLevel -ge 2) {
        exit 0
    }
    elseif ($UACLevel -lt 2) {
        exit 1
    }
    else {
        exit 1
    }
}
end {

}

