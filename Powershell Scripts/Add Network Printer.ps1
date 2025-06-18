# Adds or removes a shared network printer for all user profiles on this computer as a per computer connection.
#Requires -Version 5.1

<#
.SYNOPSIS
    Adds or removes a shared network printer for all user profiles on this computer as a per computer connection.
.DESCRIPTION
    Adds or removes a shared network printer for all user profiles on this computer as a per computer connection.
.EXAMPLE
    -PrinterSharePath '\\SRV22-DC1-TEST\Brother HL-L2395DW series'

    Verifying that the print server 'SRV22-DC1-TEST' is reachable via ping.
    Print server 'SRV22-DC1-TEST' is reachable.
    Verifying '\\SRV22-DC1-TEST\Brother HL-L2395DW series' is a valid printer share.
    Adding the printer '\\SRV22-DC1-TEST\Brother HL-L2395DW series' to the system account.
    Attempting to add the printer for all users.
    Retrieving the printer driver.
    Installing the printer driver.
    Printer driver installed.
    Restarting the print spooler.
    The printer has been successfully added.

PARAMETER: -PrinterSharePath '\\REPLACE-ME\My Printer Share'
    Specify the path to the Windows server printer share you would like to add for all users on this computer. E.g., '\\PRNT-SRV\My Printer Share'.

PARAMETER: -Remove
    Removes the printer from this computer instead of adding it.

PARAMETER: -Restart
    A restart may be required for this script to take effect immediately.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Updated checkbox script variables.
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$PrinterSharePath,
    [Parameter()]
    [Switch]$Remove = [System.Convert]::ToBoolean($env:removePrinter),
    [Parameter()]
    [Switch]$Restart = [System.Convert]::ToBoolean($env:forceRestart)
)

begin {
    # If script form variables are used, replace the preset parameters with their value.
    if ($env:printerSharePath -and $env:printerSharePath -notlike "null") { $PrinterSharePath = $env:printerSharePath }

    # If $PrinterSharePath exists, remove any leading double quotes and trim whitespace.
    if ($PrinterSharePath) {
        $PrinterSharePath = $PrinterSharePath -replace '^"' -replace ''
        $PrinterSharePath = $PrinterSharePath.Trim()
    }

    # Check if $PrinterSharePath is empty; if so, display an error and exit.
    if (!$PrinterSharePath) {
        Write-Host -Object "[Error] Please provide a valid printer share path to add. For example: '\\CONTOSO-PRNT-SRV\My Printer'."
        exit 1
    }

    # Validate that $PrinterSharePath is in the correct UNC path format; if not, display an error and exit.
    if ($PrinterSharePath -notmatch "^\\\\.+\\.+") {
        Write-Host -Object "[Error] An invalid printer share path '$PrinterSharePath' was provided. Shared printer paths should be in the format \\Windows-Server-Name\Printer-Share-Name."
        exit 1
    }

    # Extract the server name from $PrinterSharePath.
    $Server = $PrinterSharePath -replace "\\[^\\]*$" -replace "^\\\\"
    if ($Server) {
        $Server = $Server.Trim()
    }
    
    # Check if $Server is empty; if so, display an error and exit.
    if (!$Server) {
        Write-Host -Object "[Error] The server specified in the path '$PrinterSharePath' is invalid. Please provide a valid printer share path in the format '\\CONTOSO-PRNT-SRV\My_Printer'."
        exit 1
    }

    # Validate that $Server contains only allowed characters; if not, display an error and exit.
    if ($Server -match "[^a-zA-Z0-9:.-]") {
        Write-Host -Object "[Error] The server '$Server' specified in the path '$PrinterSharePath' is invalid. Hostnames and IP addresses can only contain alphabetic characters, digits, colons, dots, and hyphens."
        exit 1
    }

    # If $Server is an IP address, split it into octets and check that each is within the valid range (0–255).
    if ($Server -match "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+") {
        $Server -split '\.' | ForEach-Object {
            if ([long]$_ -gt 255 -or [long]$_ -lt 0) {
                Write-Host -Object "[Error] The server '$Server' specified in the path '$PrinterSharePath' is invalid. IP address octets cannot exceed 255 or be less than 0."
                exit 1
            }
        }
    }

    # Validate the IP address format by casting $Server to [ipaddress]; if invalid, catch the exception and display an error.
    if ($Server -match ":" -or $Server -match "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+") {
        try {
            $ErrorActionPreference = "Stop"
            [ipaddress]$ipAddress = $Server
            $ErrorActionPreference = "Continue"
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] The server '$Server' specified in the path '$PrinterSharePath' is invalid. The ip address given is invalid."
            exit 1
        }
    }

    # If not removing the printer, verify the server is reachable by pinging it; if not, display an error and exit.
    if (!$Remove) {
        try {
            Write-Host -Object "Verifying that the print server '$Server' is reachable via ping."
            Test-Connection -ComputerName $Server -ErrorAction Stop | Out-Null
            Write-Host -Object "Print server '$Server' is reachable."
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] The device '$Server' at the path '$PrinterSharePath' is invalid. The print server is not reachable."
            exit 1
        }
    }

    # Extract the share name from $PrinterSharePath by removing the server name.
    $ShareName = $PrinterSharePath -replace "^\\\\$Server\\" -replace "\\$"
    if ($ShareName) {
        $ShareName = $ShareName.Trim()
    }

    # Check if $ShareName is empty; if so, display an error and exit.
    if (!$ShareName) {
        Write-Host -Object "[Error] The share name specified in the path '$PrinterSharePath' is invalid. Please provide a valid printer share in the format '\\CONTOSO-PRNT-SRV\My Printer'."
        exit 1
    }

    # Validate that $ShareName does not contain any invalid characters (backslash, forward slash, double quote, or comma).
    if ($ShareName -match '[/,"\\]') {
        Write-Host -Object "[Error] The printer share '$ShareName' specified in the path '$PrinterSharePath' is invalid. Printer shares cannot contain a backslash, forward slash, double quote, or comma."
        exit 1
    }

    # Attempt to verify the printer share's existence; check all printer shares on $Server or locally if removing.
    try {
        Write-Host -Object "Verifying '$PrinterSharePath' is a valid printer share."

        $CurrentPrinterShares = Get-Printer -ErrorAction Stop | Where-Object { $_.Type -eq "Connection" -and $_.Shared -eq $True -and $_.ComputerName -eq $Server }
        
        if (!$Remove) {
            $AllPrinterShares = Get-Printer -ComputerName $Server -ErrorAction Stop | Where-Object { $_.Shared -eq $True }
        }
        else {
            $AllPrinterShares = $CurrentPrinterShares
        }
    }
    catch {
        # Catch any errors while retrieving printer shares and display a relevant message.
        Write-Host -Object "[Error] $($_.Exception.Message)"
        if ($Remove) {
            Write-Host -Object "[Error] Failed to retrieve shared printers from the device $env:ComputerName."
        }
        else {
            Write-Host -Object "[Error] Failed to retrieve shared printers from the device $Server."
        }
        exit 1
    }

    # If no printer shares exist on the server, display an error.
    if (!$AllPrinterShares -and !$Remove) {
        Write-Host -Object "[Error] The printer share '$ShareName' specified in the path '$PrinterSharePath' is invalid. No printer shares exist on $Server."
        exit 1
    }

    # If no all-user printer shares exist when removing, display an error.
    if (!$AllPrinterShares -and $Remove) {
        Write-Host -Object "[Error] The printer share '$ShareName' specified in the path '$PrinterSharePath' is invalid. No per computer printer shares are currently added to $env:ComputerName."
        exit 1
    }

    # If $ShareName is not present in $AllPrinterShares, display an error listing the current shares.
    if ($AllPrinterShares.ShareName -notcontains $ShareName) {
        Write-Host -Object "[Error] The printer share '$ShareName' specified in the path '$PrinterSharePath' is invalid. The printer share does not exist."

        if (!$Remove) {
            Write-Host -Object "### Current Printer Shares on $Server ###"
        }
        else {
            Write-Host -Object "### Current Printer Shares on $env:ComputerName ###"
        }
        $AllPrinterShares | Format-Table ShareName, PortName, DriverName
        exit 1
    }

    # Check if we are adding the printer (not removing) and if a printer share with the specified $ShareName already exists in the current printer shares on this computer.
    if (!$Remove -and $CurrentPrinterShares.ShareName -contains $ShareName) {
        Write-Host -Object "[Error] The printer share '$ShareName' specified in the path '$PrinterSharePath' is invalid. The printer share already exists on this computer."
        exit 1
    }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    if ($ExitCode) {
        $ExitCode = 0
    }
}
process {
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }
    
    # Log the operation being performed (add or remove the printer from the system account).
    if ($Remove) {
        Write-Host -Object "Removing the printer '$PrinterSharePath' from the system account."
    }
    else {
        Write-Host -Object "Adding the printer '$PrinterSharePath' to the system account."
    }

    # Try to add or remove the printer connection based on the $Remove flag.
    try {
        if ($Remove) {
            # Retrieve the specific printer connection to be removed.
            $PrinterToRemove = Get-Printer -ErrorAction Stop | Where-Object { $_.ShareName -eq $ShareName -and $_.Type -eq "Connection" -and $_.Shared -eq $True }
            
            # Remove the retrieved printer connection.
            Remove-Printer -InputObject $PrinterToRemove -ErrorAction Stop
        }
        else {
            # Add the printer connection using the specified share path.
            Add-Printer -ConnectionName $PrinterSharePath -ErrorAction Stop
        }
    }
    catch {
        # Handle any errors that occur during add or remove operations.
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to add or remove the printer from the system account."
        exit 1
    }

    # Log the operation of adding or removing the printer for all users.
    if ($Remove) {
        Write-Host -Object "Attempting to remove the printer for all users."
    }
    else {
        Write-Host -Object "Attempting to add the printer for all users."
    }

    # Try to execute the global add/remove command for the printer using rundll32.
    try {
        # Capture the start time of the script to track operation duration.
        $StartTime = Get-Date

        $ProcessTimeOut = 10

        # Determine the print operation type ("/gd" for remove, "/ga" for add) based on the $Remove flag.
        $AddOrRemove = if ($Remove) { "/gd" }else { "/ga" }

        # Start the process to add or remove the printer for all users.
        $Process = Start-Process -FilePath "$env:SystemRoot\system32\rundll32.exe" -ArgumentList @(
            "printui.dll,", "PrintUIEntry", $AddOrRemove, "/n`"$PrinterSharePath`""
        ) -PassThru -NoNewWindow

        # Wait for the process to complete or timeout.
        while (!$Process.HasExited) {
            if ($StartTime.AddMinutes($ProcessTimeOut) -lt $(Get-Date)) {
                # Timeout reached; log an error and exit.
                Write-Host -Object "[Error] $ProcessTimeOut minute timeout reached. Failed to add or remove the printer."
                exit 1
            }
            Start-Sleep -Milliseconds 100
        }
    }
    catch {
        # Handle any errors that occur during the rundll32 operation.
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to add or remove the printer with the path '$PrinterSharePath'."
        exit 1
    }

    # Restart the print spooler if removing the printer.
    if ($Remove) {
        Write-Host -Object "Restarting the print spooler."
        try {
            Restart-Service -Name Spooler -ErrorAction Stop
        }
        catch {
            # Handle any errors that occur during spooler restart.
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to restart the print spooler."
            exit 1
        }

        # If the $Restart flag is set, schedule a system restart.
        if ($Restart) {
            $RestartDate = (Get-Date).AddMinutes(1)
            Write-Host -Object "Scheduling a restart for $($RestartDate.ToShortDateString()) at $($RestartDate.ToShortTimeString())."
            try {
                Start-Process shutdown.exe -ArgumentList "/r /t 60" -Wait -NoNewWindow
            }
            catch {
                # Handle any errors that occur while scheduling the restart.
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to schedule restart."
                exit 1
            }
        }

        # Retrieve the current printer shares
        $CurrentPrinterShares = Get-Printer -ErrorAction Stop | Where-Object { $_.Type -eq "Connection" -and $_.Shared -eq $True -and $_.ComputerName -eq $Server -and $_.ShareName -eq $ShareName }

        # If we are removing the printer and it does not exist in the current printer shares (meaning it was successfully removed), log a success message.
        if (!$CurrentPrinterShares) {
            Write-Host -Object "The printer is scheduled for removal."
            if (!$Restart) {
                Write-Warning -Message "A restart is required to complete the removal."
            }
            else {
                Write-Warning -Message "The removal will complete after the restart."
            }
        }
        else {
            Write-Host -Object "[Error] The printer was found. Failed to remove the printer"
            exit 1
        }

        exit
    }

    # Retrieve the printer driver for the specified printer.
    Write-Host -Object "Retrieving the printer driver."
    try {
        $ErrorActionPreference = "Stop"

        # Get the driver name for the specified printer.
        $PrinterDriverName = Get-Printer -ComputerName $Server | Where-Object { $_.ShareName -eq $ShareName } | Select-Object -ExpandProperty "DriverName"

        # Retrieve the full printer driver object by name.
        $PrinterDriver = Get-PrinterDriver -ComputerName $Server -Name $PrinterDriverName | Select-Object -ExpandProperty "Name"
        $ErrorActionPreference = "Continue"
    }
    catch {
        # Handle errors that occur during printer driver retrieval.
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to retrieve the printer driver."
        exit 1
    }

    # Install the retrieved printer driver on the local system.
    Write-Host -Object "Installing the printer driver."
    try {
        Add-PrinterDriver -Name $PrinterDriver -ErrorAction Stop
    }
    catch {
        # Handle errors that occur during printer driver installation.
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to install the printer driver."
        exit 1
    }

    # Log successful installation of the printer driver.
    Write-Host -Object "Printer driver installed."

    # Restart the print spooler to apply the driver installation.
    Write-Host -Object "Restarting the print spooler."
    try {
        Restart-Service -Name Spooler -ErrorAction Stop
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to restart the print spooler."
        exit 1
    }

    # Schedule a system restart if the $Restart flag is set.
    if ($Restart) {
        # Set the restart time to one minute from now.
        $RestartDate = (Get-Date).AddMinutes(1)
        Write-Host -Object "Scheduling a restart for $($RestartDate.ToShortDateString()) at $($RestartDate.ToShortTimeString())."
        try {
            Start-Process shutdown.exe -ArgumentList "/r /t 60" -Wait -NoNewWindow
        }
        catch {
            # Handle errors that occur while scheduling the restart.
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to schedule restart."
            exit 1
        }
    }

    # Retrieve the current printer shares
    $CurrentPrinterShares = Get-Printer -ErrorAction Stop | Where-Object { $_.Type -eq "Connection" -and $_.Shared -eq $True -and $_.ComputerName -eq $Server -and $_.ShareName -eq $ShareName }

    # If we are not removing the printer and it exists in the current printer shares (meaning it was successfully added), log a success message.
    if ($CurrentPrinterShares) {
        Write-Host -Object "The printer has been successfully added."
    }
    else {
        Write-Host -Object "[Error] The printer was not found. Failed to add the printer."
        exit 1
    }

    exit $ExitCode
}
end {
    
    
    
}

