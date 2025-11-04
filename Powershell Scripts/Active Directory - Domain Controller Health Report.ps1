# Analyzes the state of a domain controller and reports any problems to help with troubleshooting. Optionally, set a WYSIWYG custom field.
#Requires -Version 5.1

<#
.SYNOPSIS
    Analyzes the state of a domain controller and reports any problems to help with troubleshooting. Optionally, set a WYSIWYG custom field.
.DESCRIPTION
    Analyzes the state of a domain controller and reports any problems to help with troubleshooting. Optionally, set a WYSIWYG custom field.
.EXAMPLE
    (No Parameters)
    
Retrieving Directory Server Diagnosis Test Results.

Passing Tests: CheckSDRefDom, Connectivity, CrossRefValidation, DFSREvent, FrsEvent, Intersite, KccEvent, KnowsOfRoleHolders, MachineAccount, NCSecDesc, NetLogons, ObjectsReplicated, Replications, RidManager, Services, SystemLog, SysVolCheck, VerifyReferences

[Alert] Failed Tests Detected!
Failed Tests: Advertising, LocatorCheck

### Detailed Output ###

Directory Server Diagnosis
Performing initial setup:
   Trying to find home server...
   Home Server = SRV16-DC2-TEST
   * Identified AD Forest. 
   Done gathering initial info.
Doing initial required tests
   Testing server: Default-First-Site-Name\SRV16-DC2-TEST
      Starting test: Connectivity
         ......................... SRV16-DC2-TEST passed test Connectivity
Doing primary tests
   Testing server: Default-First-Site-Name\SRV16-DC2-TEST
      Starting test: Advertising
         Warning: SRV16-DC2-TEST is not advertising as a time server.
         ......................... SRV16-DC2-TEST failed test Advertising
   Running partition tests on : ForestDnsZones
   Running partition tests on : DomainDnsZones
   Running partition tests on : Schema
   Running partition tests on : Configuration
   Running partition tests on : test
   Running enterprise tests on : test.lan

Directory Server Diagnosis
Performing initial setup:
   Trying to find home server...
   Home Server = SRV16-DC2-TEST
   * Identified AD Forest. 
   Done gathering initial info.
Doing initial required tests
   Testing server: Default-First-Site-Name\SRV16-DC2-TEST
      Starting test: Connectivity
         ......................... SRV16-DC2-TEST passed test Connectivity
Doing primary tests
   Testing server: Default-First-Site-Name\SRV16-DC2-TEST
   Running partition tests on : ForestDnsZones
   Running partition tests on : DomainDnsZones
   Running partition tests on : Schema
   Running partition tests on : Configuration
   Running partition tests on : test
   Running enterprise tests on : test.lan
      Starting test: LocatorCheck
         Warning: DcGetDcName(TIME_SERVER) call failed, error 1355
         A Time Server could not be located.
         The server holding the PDC role is down.
         Warning: DcGetDcName(GOOD_TIME_SERVER_PREFERRED) call failed, error
         1355
         A Good Time Server could not be located.
         ......................... test.lan failed test LocatorCheck

PARAMETER: -wysiwygCustomField "ReplaceMeWithaWYSIWYGcustomField"
    Name of a WYSIWYG custom field to optionally save the results to.
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$wysiwygCustomField
)

begin {
    # If script form variables are used, replace command line parameters with their value. 
    if ($env:wysiwygCustomFieldName -and $env:wysiwygCustomFieldName -notlike "null") { $wysiwygCustomField = $env:wysiwygCustomFieldName }

    # Function to test if the current machine is a domain controller
    function Test-IsDomainController {
        $OS = if ($PSVersionTable.PSVersion.Major -lt 5) {
            Get-WmiObject -Class Win32_OperatingSystem
        }
        else {
            Get-CimInstance -ClassName Win32_OperatingSystem
        }

        # Check if the OS is a domain controller (ProductType 2)
        if ($OS.ProductType -eq "2") {
            return $true
        }
    }

    function Get-DCDiagResults {
        # Define the list of DCDiag tests to run
        $DCDiagTestsToRun = "Connectivity", "Advertising", "FrsEvent", "DFSREvent", "SysVolCheck", "KccEvent", "KnowsOfRoleHolders", "MachineAccount", "NCSecDesc", "NetLogons", "ObjectsReplicated", "Replications", "RidManager", "Services", "SystemLog", "VerifyReferences", "CheckSDRefDom", "CrossRefValidation", "LocatorCheck", "Intersite"
    
        foreach ($DCTest in $DCDiagTestsToRun) {
            # Run DCDiag for the current test and save the output to a file
            $DCDiag = Start-Process -FilePath "DCDiag.exe" -ArgumentList "/test:$DCTest", "/f:$env:TEMP\dc-diag-$DCTest.txt" -PassThru -Wait -NoNewWindow

            # Check if the DCDiag test failed
            if ($DCDiag.ExitCode -ne 0) {
                Write-Host "[Error] Running $DCTest!"
                exit 1
            }

            # Read the raw results from the output file and filter out empty lines
            $RawResult = Get-Content -Path "$env:TEMP\dc-diag-$DCTest.txt" | Where-Object { $_.Trim() }
            
            # Find the status line indicating whether the test passed or failed
            $StatusLine = $RawResult | Where-Object { $_ -match "\. .* test $DCTest" }

            # Extract the status (passed or failed) from the status line
            $Status = $StatusLine -split ' ' | Where-Object { $_ -like "passed" -or $_ -like "failed" }

            # Create a custom object to store the test results
            [PSCustomObject]@{
                Test   = $DCTest
                Status = $Status
                Result = $RawResult
            }

            # Remove the temporary output file
            Remove-Item -Path "$env:TEMP\dc-diag-$DCTest.txt"
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
    # Check if the script is run with Administrator privileges
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Check if the script is run on a Domain Controller
    if (!(Test-IsDomainController)) {
        Write-Host -Object "[Error] This script needs to be run on a Domain Controller."
        exit 1
    }

    # Initialize lists to store passing and failing tests
    $PassingTests = New-Object System.Collections.Generic.List[object]
    $FailedTests = New-Object System.Collections.Generic.List[object]

    # Notify the user that the tests are being retrieved
    Write-Host -Object "`nRetrieving Directory Server Diagnosis Test Results."
    $TestResults = Get-DCDiagResults

    # Process each test result
    foreach ($Result in $TestResults) {
        $TestFailed = $False

        # Check if any status in the result indicates a failure
        $Result.Status | ForEach-Object {
            if ($_ -notmatch "pass") {
                $TestFailed = $True
            }
        }

        # Add the result to the appropriate list
        if ($TestFailed) {
            $FailedTests.Add($Result)
        }
        else {
            $PassingTests.Add($Result)
        }
    }

    # Optionally set a WYSIWYG custom field if specified
    if ($wysiwygCustomField) {
        Write-Host ""
        Write-Host "Note: Custom field '$wysiwygCustomField' was specified but NinjaOne integration has been removed."
        Write-Host "All output has been displayed above."
    }

    # Display the list of passing tests
    if ($PassingTests.Count -gt 0) {
        Write-Host -Object ""
        Write-Host -Object "Passing Tests: " -NoNewline
        Write-Host -Object ($PassingTests.Test | Sort-Object) -Separator ", "
        Write-Host -Object ""
    }

    # Display the list of failed tests with detailed output
    if ($FailedTests.Count -gt 0) {
        Write-Host -Object "[Alert] Failed Tests Detected!"
        Write-Host -Object "Failed Tests: " -NoNewline
        Write-Host -Object ($FailedTests.Test | Sort-Object) -Separator ", "

        Write-Host -Object "`n### Detailed Output ###"
        $FailedTests | Sort-Object Test | ForEach-Object {
            Write-Host -Object ""
            Write-Host -Object ($_.Result | Out-String)
            Write-Host -Object ""
        }
    }
    else {
        Write-Host -Object "All Directory Server Diagnosis Tests Pass!"
    }

    exit $ExitCode
}
end {

}
