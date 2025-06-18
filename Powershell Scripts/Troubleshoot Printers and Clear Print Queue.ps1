# Clear print queues and list printers to help troubleshoot printing issues.
#Requires -Version 5.1

<#
.SYNOPSIS
    Clear print queues and list printers to help troubleshoot printing issues.
.DESCRIPTION
    Clear print queues and list printers to help troubleshoot printing issues.
    This script will stop the printer spooler service, clear all print jobs, and start the printer spooler service.
    If some print jobs are not cleared, then a reboot might be needed before running this script again.
.EXAMPLE
    No parameters needed
.OUTPUTS
    String
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Renamed script
.COMPONENT
    Printer
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$CustomFieldName
)

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    function Set-NinjaProperty {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True)]
            [String]$Name,
            [Parameter()]
            [String]$Type,
            [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
            $Value,
            [Parameter()]
            [String]$DocumentName
        )
        
        # Measure the number of characters in the provided value
        $Characters = $Value | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
    
        # Throw an error if the value exceeds the character limit of 200,000 characters
        if ($Characters -ge 200000) {
            throw "Character limit exceeded: the value is greater than or equal to 200,000 characters."
        }
        
        # Initialize a hashtable for additional documentation parameters
        $DocumentationParams = @{}
    
        # If a document name is provided, add it to the documentation parameters
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
        
        # Define a list of valid field types
        $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG"
    
        # Warn the user if the provided type is not valid
        if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type. Please check here for valid types: https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" }
        
        # Define types that require options to be retrieved
        $NeedsOptions = "Dropdown"
    
        # If the property is being set in a document or field and the type needs options, retrieve them
        if ($DocumentName) {
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1
            }
        }
        else {
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1
            }
        }
        
        # Throw an error if there was an issue retrieving the property options
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }
            
        # Process the property value based on its type
        switch ($Type) {
            "Checkbox" {
                # Convert the value to a boolean for Checkbox type
                $NinjaValue = [System.Convert]::ToBoolean($Value)
            }
            "Date or Date Time" {
                # Convert the value to a Unix timestamp for Date or Date Time type
                $Date = (Get-Date $Value).ToUniversalTime()
                $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date
                $NinjaValue = $TimeSpan.TotalSeconds
            }
            "Dropdown" {
                # Convert the dropdown value to its corresponding GUID
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID
            
                # Throw an error if the value is not present in the dropdown options
                if (!($Selection)) {
                    throw [System.ArgumentOutOfRangeException]::New("Value is not present in dropdown options.")
                }
            
                $NinjaValue = $Selection
            }
            default {
                # For other types, use the value as is
                $NinjaValue = $Value
            }
        }
            
        # Set the property value in the document if a document name is provided
        if ($DocumentName) {
            $CustomField = Ninja-Property-Docs-Set -AttributeName $Name -AttributeValue $NinjaValue @DocumentationParams 2>&1
        }
        else {
            # Otherwise, set the standard property value
            $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1
        }
            
        # Throw an error if setting the property failed
        if ($CustomField.Exception) {
            throw $CustomField
        }
    }
}

process {
    if ($env:CustomFieldName -and $env:CustomFieldName -notlike "null") { $CustomFieldName = $env:CustomFieldName }

    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    $Status = [PSCustomObject]@{
        Cleared                        = $false
        ServiceRestarted               = $false
        ListOfWSDPrinters              = Get-Printer | Where-Object { $_.PortName -like "WSD*" }
        PrintersWithIpAddressOrUncPath = Get-Printer | Where-Object { $_.PortName -like "*IP*" -or $_.PortName -like "*\\*" }
    }

    Write-Host "[Info] Stopping print spooler service"
    try {
        Stop-Service -Name spooler -Force -ErrorAction Stop
    }
    catch {
        $Status.ServiceRestarted = $false
    }
    # Exit Code 2 usually means the service is already stopped
    if ((Get-Service -Name spooler).Status -eq "Stopped") {
        Write-Host "[Info] Stopped print spooler service"
        # Sleep just in case the spooler service is taking some time to stop
        Start-Sleep -Seconds 10
        Write-Host "[Info] Clearing all print queues"
        try {
            Remove-Item -Path "$env:SystemRoot\System32\spool\PRINTERS\*" -Force -ErrorAction SilentlyContinue
            $Status.Cleared = $true
        }
        catch {
            Write-Host "[Warn] Failed to clear all print queues."
        }
        Write-Host "[Info] Cleared all print queues."

        Write-Host "[Info] Starting print spooler service"
        try {
            Start-Service -Name spooler -ErrorAction Stop
        }
        catch {
            Write-Host "[Warn] Failed to start print spooler service. Attempting to stop and start it again."
            Stop-Service -Name spooler -Force -ErrorAction SilentlyContinue
            $Service = Start-Service -Name spooler -ErrorAction SilentlyContinue -PassThru
            if ($Service.Status -ne "Stopped") {
                $Status.ServiceRestarted = $false
            }
        }
        Start-Sleep -Seconds 10
        if ((Get-Service -Name spooler).Status -eq "Running") {
            Write-Host "[Info] Restarted print spooler service."
            $Status.ServiceRestarted = $true
        }
        else {
            Write-Host "[Error] Could not start Print Spooler service."
        }
    }
    else {
        Write-Host "[Error] Could not stop Print Spooler service."
    }

    
    $Output = New-Object System.Collections.Generic.List[string]
    if ($Status.Cleared) {
        $Output.Add("Cleared all print queues.")
    }
    else {
        $Output.Add("Failed to clear all print queues.")
    }

    if ($Status.ServiceRestarted) {
        $Output.Add("Restarted print spooler service.")
    }
    else {
        $Output.Add("Failed to restart print spooler service.")
    }

    if ($Status.ListOfWSDPrinters) {
        Write-Host "[Info] Found WSD printer:"

        $Output.Add("Found WSD printer:")
        $Status.ListOfWSDPrinters | ForEach-Object {
            $Output.Add("$($_.Name)")
            Write-Host "  $($_.Name)"
        }
    }
    else {
        $Output.Add("No WSD printers found.")
    }

    if ($Status.PrintersWithIpAddressOrUncPath) {
        Write-Host "[Info] Found printer with IP address or UNC path:"

        $Output.Add("Found printer with IP address or UNC path:")
        $Status.PrintersWithIpAddressOrUncPath | ForEach-Object {
            if ($_.PortName -like "*\\*" -and $(Test-Connection $($_.PortName -split '\\' | Select-Object -Skip 2 -First 1) -Count 3 -Quiet -ErrorAction SilentlyContinue)) {
                $Output.Add("$($_.Name) (Connected)")
                Write-Host "  $($_.Name) (Connected)"
            }
            elseif ($_.PortName -like "*IP_*" -and $(Test-Connection $($_.PortName -split 'IP_' | Select-Object -Skip 1 -First 1) -Count 3 -Quiet -ErrorAction SilentlyContinue)) {
                $Output.Add("$($_.Name) (Connected)")
                Write-Host "  $($_.Name) (Connected)"
            }
            else {
                $Output.Add("$_ (Disconnected)")
                Write-Host "  $_ (Disconnected)"
            }
        }
    }
    else {
        $Output.Add("No printers with IP address or UNC path found.")
    }
    if ($CustomFieldName) {
        try {
            Write-Host "[Info] Attempting to set Custom Field '$CustomFieldName'."
            Set-NinjaProperty -Name $CustomFieldName -Value $($Output -join [System.Environment]::NewLine | Out-String -Width 4000)
            Write-Host "[Info] Successfully set Custom Field '$CustomFieldName'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
        }
    }
}

end {
    
    
    
}

