# Disables the automatic login feature and ensures that a dialog box is presented each time a user signs in.
#Requires -Version 5.1

<#
.SYNOPSIS
    Disables the automatic login feature and ensures that a dialog box is presented each time a user signs in.
.DESCRIPTION
    Disables the automatic login feature and ensures that a dialog box is presented each time a user signs in.
.EXAMPLE
    -Title "A Title" -Message "A Message"
    
    Retrieving existing security policy...
                                                                           
    The task has completed successfully.
    See log %windir%\security\logs\scesrv.log for detail info.
    Modifying policy to include the login banner.
    Applying updated policy...
    Completed 5 percent (0/18) 	Process Security Policy area        
    Completed 22 percent (3/18) 	Process Security Policy area        
    Completed 44 percent (7/18) 	Process Security Policy area        
    Completed 61 percent (10/18) 	Process Security Policy area        
    Completed 77 percent (13/18) 	Process Security Policy area        
    Completed 100 percent (18/18) 	Process Security Policy area        
                                                                            
    The task has completed successfully.
    See log %windir%\security\logs\scesrv.log for detail info.


PARAMETER: -Title "ReplaceMeWithYourDesiredTitle"
    Specify the title of the dialog box to be used in the logon banner.

PARAMETER: -Message "ReplaceMeWithYourDesiredMessage"
    Specify the main text body to be used in the logon banner. 

PARAMETER: -MicrosoftDefaults
    Reverts all the modified settings to their Microsoft default value.

PARAMETER: -ForceRestart
    Schedules a restart for 60 seconds from now so that the login banner may take immediate effect.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Title,
    [Parameter()]
    [String]$Message,
    [Parameter()]
    [Switch]$MicrosoftDefaults = [System.Convert]::ToBoolean($env:revertToMicrosoftDefaults),
    [Parameter()]
    [Switch]$ForceRestart = [System.Convert]::ToBoolean($env:forceRestart)
)

begin {
    if ($env:logonBannerTitle -and $env:logonBannerTitle -notlike "null") { $Title = $env:logonBannerTitle }
    if ($env:logonBannerText -and $env:logonBannerText -notlike "null") { $Message = $env:logonBannerText }

    # Check if a title is provided. If it exists, trim any leading or trailing whitespace.
    if ($Title) {
        $Title = $Title.Trim()
    }

    # If no title is provided and Microsoft defaults are not being used, output an error and exit the script.
    if (!$Title -and !$MicrosoftDefaults) {
        Write-Host "[Error] Missing title for the login banner."
        exit 1
    }

    # Check if a message is provided. If it exists, trim any leading or trailing whitespace.
    if ($Message) {
        $Message = $Message.Trim()
    }

    # If no message is provided and Microsoft defaults are not being used, output an error and exit the script.
    if (!$Message -and !$MicrosoftDefaults) {
        Write-Host "[Error] Missing message for the login banner."
        exit 1
    }

    # If Microsoft defaults are specified to be used but either a title or message is also provided, error out due to the title and message not being present by default.
    if ($MicrosoftDefaults -and ($Title -or $Message)) {
        Write-Host "[Error] A login banner is not present by default. If you use the 'Revert To Microsoft Defaults' checkmark, leave the 'Login Banner Title' and the 'Login Banner Text' empty."
        exit 1
    }

    function Test-IsDomainJoined {
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            return $(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        }
        else {
            return $(Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain
        }
    }

    function Set-RegKey {
        param (
            $Path,
            $Name,
            $Value,
            [ValidateSet("DWord", "QWord", "String", "ExpandedString", "Binary", "MultiString", "Unknown")]
            $PropertyType = "DWord"
        )

        # Check if the specified path exists, if not, create it.
        if (-not $(Test-Path -Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }

        # Check if the property already exists at the path.
        if ((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue)) {

            # Retrieve the current value of the registry key.
            $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
            try {
                # Attempt to update the property's value.
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                # If an error occurs during the update, print an error message and exit.
                Write-Host "[Error] Unable to Set registry key for $Name please see below error!"
                Write-Host "[Error] $($_.Message)"
                exit 1
            }
            # Print a confirmation of the change.
            Write-Host "$Path\$Name changed from $CurrentValue to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
        else {
            try {
                # If the property does not exist, create it with the specified value and type.
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                # If an error occurs during creation, print an error message and exit.
                Write-Host "[Error] Unable to Set registry key for $Name please see below error!"
                Write-Host "[Error] $($_.Exception.Message)"
                exit 1
            }

            # Print a confirmation of the change.
            Write-Host "Set $Path\$Name to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
    }
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # Check if the current user session is elevated with administrator privileges. If not, display an error message and exit the script.
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Retrieve the AutoAdminLogon and DefaultPassword registry values to check for automatic login settings and stored passwords.
    $AutoLogin = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "AutoAdminLogon" -ErrorAction SilentlyContinue
    $DefaultPassword = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DefaultPassword" -ErrorAction SilentlyContinue
    $PasswordLessSetting = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device" -Name "DevicePasswordLessBuildVersion" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DevicePasswordLessBuildVersion" -ErrorAction SilentlyContinue

    # Alert if a password is stored in the registry, which might be insecure if in plain text.
    if ($DefaultPassword) {
        Write-Host "[Alert] A Password is stored in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultPassword. This password is likely in plain text."
    }

    # Check if the device is part of a domain, and if so, recommend using group policy for login banner settings.
    if (Test-IsDomainJoined) {
        Write-Host "[Error] This device is domain joined. Login Banner modifications should be setup using group policy."
        Write-Host "[Info] Group Policy Location: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Interactive logon:(...)"
        Write-Host "[Info] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/interactive-logon-message-text-for-users-attempting-to-log-on"
        exit 1
    }

    # Turn off automatic login if it is enabled.
    if ($AutoLogin -ne 0) {
        Set-RegKey -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0
    }

    # Disable automatic login if it is enabled
    if ($PasswordLessSetting -eq 0) {
        Set-RegKey -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device" -Name "DevicePasswordLessBuildVersion" -Value 2
    }

    # Announce the start of the security policy retrieval process.
    Write-Host "Retrieving existing security policy..."

    # Export the current security policy and record the output to a temporary file.
    $SecurityPolicyPath = "$env:TEMP\enable-loginbanner.cfg"
    $ExportPolicy = Start-Process SecEdit.exe -ArgumentList "/export /cfg $SecurityPolicyPath" -RedirectStandardOutput "$env:TEMP\enable-loginbanner.txt" -NoNewWindow -Wait -PassThru
    $ExportPolicyOutput = Get-Content -Path "$env:TEMP\enable-loginbanner.txt"

    # Display the output of the policy export and clean up the temporary file.
    if ($ExportPolicyOutput) {
        $ExportPolicyOutput | Write-Host
        Remove-Item "$env:TEMP\enable-loginbanner.txt"
    }

    # Check the exit code of the export process and display an error message if the export failed.
    if ($ExportPolicy.ExitCode -ne 0) {
        Write-Host -Object "Exit Code: $($ExportPolicy.ExitCode)"
        Write-Host -Object "[Error] Unable to edit security policy."
        exit 1
    }
    
    # Check if Microsoft default settings are specified to modify the login banner.
    if ($MicrosoftDefaults) {
        Write-Host "Removing login banner from security policy..."

        # Initialize a new list to store modified security policy settings.
        $NewSecPolicy = New-Object System.Collections.Generic.List[string]

        # Read the current security policy and process each line.
        Get-Content $SecurityPolicyPath | ForEach-Object {

            # If the line contains settings for LegalNoticeCaption or LegalNoticeText, reset these values.
            if ($_ -match "LegalNoticeCaption" -or $_ -match "LegalNoticeText") {
                $NewSecPolicy.Add(($_ -replace ",.*", ","))
            }
            else {
                $NewSecPolicy.Add($_)
            }
        }

        # Write the modified security policy back to the configuration file.
        $NewSecPolicy | Out-File $SecurityPolicyPath

        Write-Host "Applying updated policy..."
        # Apply the modified security policy using SecEdit.exe.
        $UpdateSecurityPolicy = Start-Process SecEdit.exe -ArgumentList "/configure /db c:\windows\security\local.sdb /cfg $SecurityPolicyPath" -RedirectStandardOutput "$env:TEMP\enable-loginbanner.txt" -Wait -NoNewWindow -PassThru
    
        # Capture the output from the policy update and display it.
        $UpdatePolicyOutput = Get-Content -Path "$env:TEMP\enable-loginbanner.txt"
        if ($UpdatePolicyOutput) {
            $UpdatePolicyOutput | Write-Host
            Remove-Item "$env:TEMP\enable-loginbanner.txt"
        }
    

        # Check the exit code of the policy update process and handle errors.
        if ($UpdateSecurityPolicy.ExitCode -ne 0) {
            Write-Host -Object "Exit Code: $($UpdateSecurityPolicy.ExitCode)"
            Write-Host -Object "[Error] Unable to update security policy."
            exit 1
        }
        else {

            if ($ForceRestart) {
                Write-Warning -Message "Scheduling system restart for 60 seconds from now. $((Get-Date).AddMinutes(60))"
                Start-Process shutdown.exe -ArgumentList "/r /t 60" -Wait -NoNewWindow
            }
            else {
                Write-Warning -Message "A restart may be required for the login banner to be removed. Please restart at your earliest convenience."
            }
            
            exit $ExitCode
        }
    }

    # Begin modification to include the login banner in the security policy.
    Write-Host "Modifying policy to include the login banner."

    # Check if the current policy already includes a title for the login banner.
    if (Get-Content $SecurityPolicyPath | Where-Object { $_ -like "*LegalNoticeCaption*" }) {
        # Replace the existing title with a new one, maintaining other parts of the line.
        $Caption = (Get-Content $SecurityPolicyPath | Where-Object { $_ -like "*LegalNoticeCaption*" }) -replace ',.*', ",`"$Title`""
        (Get-Content $SecurityPolicyPath) -replace ".*LegalNoticeCaption.*", "$Caption" | Out-File $SecurityPolicyPath
    }
    else {
        # If no title is present, create a new list for the modified policy settings.
        $NewSecPolicy = New-Object System.Collections.Generic.List[string]
        # Define the new title setting with the specified title
        $Caption = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption=1,`"$Title`""

        # Read the current policy and add the new title setting where appropriate.
        Get-Content $SecurityPolicyPath | ForEach-Object {
            if ($_ -match "\[Registry Values\]") {
                $NewSecPolicy.Add($_)
                $NewSecPolicy.Add($Caption)
            }
            else {
                $NewSecPolicy.Add($_)
            }
        }

        # Write the modified settings back to the configuration file.
        $NewSecPolicy | Out-File $SecurityPolicyPath
    }

    # Check if the security policy file shows that the login banner text has already been set.
    if (Get-Content $SecurityPolicyPath | Where-Object { $_ -like "*LegalNoticeText*" }) {
        # If the setting is found, modify its existing entry by replacing the existing text after the comma
        # with a formatted version of $Message. Commas in $Message are replaced with '","', and new lines are replaced with commas.
        $Text = (Get-Content $SecurityPolicyPath | Where-Object { $_ -like "*LegalNoticeText*" }) -replace ',.*', ",$($Message -replace ',','","' -replace '\n',',')"
        
        # Replace the entire line that contains "LegalNoticeText" with the new formatted text, and overwrite the file.
        (Get-Content $SecurityPolicyPath) -replace ".*LegalNoticeText.*", "$Text" | Out-File $SecurityPolicyPath
    }
    else {
        # If the setting is not found in the file, initialize a new list to store all lines for the updated policy.
        $NewSecPolicy = New-Object System.Collections.Generic.List[string]

        # Create a new line for "LegalNoticeText" with the provided $Message formatted similarly to the replacement process above.
        $Text = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText=7,$($Message -replace ',','","' -replace '\n',',')"

        # Read each line of the security policy. If the line matches "[Registry Values]", it indicates the start of registry settings.
        Get-Content $SecurityPolicyPath | ForEach-Object {
            if ($_ -match "\[Registry Values\]") {
                # Add the current line and immediately follow it with the new "LegalNoticeText" setting.
                $NewSecPolicy.Add($_)
                $NewSecPolicy.Add($Text)
            }
            else {
                # Add other lines without modification.
                $NewSecPolicy.Add($_)
            }
        }

        # Write the updated list back to the security policy file, thus including the new "LegalNoticeText".
        $NewSecPolicy | Out-File $SecurityPolicyPath
    }

    # Display a message indicating that the updated security policy is being applied.
    Write-Host "Applying updated policy..."
    $UpdateSecurityPolicy = Start-Process SecEdit.exe -ArgumentList "/configure /db c:\windows\security\local.sdb /cfg $SecurityPolicyPath /areas securitypolicy" -RedirectStandardOutput "$env:TEMP\enable-loginbanner.txt" -Wait -NoNewWindow -PassThru
    
    $UpdatePolicyOutput = Get-Content -Path "$env:TEMP\enable-loginbanner.txt"
    # If there is any output from the SecEdit process, display it in the console.
    if ($UpdatePolicyOutput) {
        $UpdatePolicyOutput | Write-Host
        Remove-Item "$env:TEMP\enable-loginbanner.txt"
    }
    

    # Check if the SecEdit process completed successfully by examining the exit code.
    if ($UpdateSecurityPolicy.ExitCode -ne 0) {
        Write-Host -Object "Exit Code: $($UpdateSecurityPolicy.ExitCode)"
        Write-Host -Object "[Error] Unable to update security policy."
        exit 1
    }

    if ($ForceRestart) {
        Write-Warning -Message "Scheduling system restart for 60 seconds from now. $((Get-Date).AddMinutes(60))"
        Start-Process shutdown.exe -ArgumentList "/r /t 60" -Wait -NoNewWindow
    }
    else {
        Write-Warning -Message "A restart may be required for the login banner to take effect. Please restart at your earliest convenience."
    }
    
    exit $ExitCode
}
end {
    
    
    
}
