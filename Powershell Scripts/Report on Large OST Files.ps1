# Find large OST files in the users folder or recursively under C:\.
<#
.SYNOPSIS
    Find large OST files in the user's folder or recursively under C:\.
.DESCRIPTION
    Find large OST files in the user's folder or recursively under C:\.
.PARAMETER MinSize
    The minimum file size. This expects the file size to be in gigabytes.
.PARAMETER AllFolders
    Will search all folders under C:\.
.EXAMPLE
     -MinSize 50
    Search for OST files larger than 50GB in each user's Outlook folder.
.EXAMPLE
     -AllFolders -MinSize 50
    Search for OST files larger than 50GB under C:\ recursively.
.OUTPUTS
    String[]
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Exit code 1: If at least 1 OST was found larger than MinSize
    Exit code 0: If no OST's where found larger than MinSize
    Release Notes: Updated Calculated Name
#>
[CmdletBinding()]
param (
    [Parameter()]
    [double]
    $MinSize = 50,
    [switch]
    $AllFolders = [System.Convert]::ToBoolean($env:AllFolders)
)

begin {
    if ($env:minimumOstSize) {
        $MinSize = $env:minimumOstSize
    }
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    function Get-FriendlySize {
        param($Bytes)
        # Converts Bytes to the highest matching unit
        $Sizes = 'Bytes,KB,MB,GB,TB,PB,EB,ZB' -split ','
        for ($i = 0; ($Bytes -ge 1kb) -and ($i -lt $Sizes.Count); $i++) { $Bytes /= 1kb }
        $N = 2
        if ($i -eq 0) { $N = 0 }
        if ($Bytes) { "{0:N$($N)} {1}" -f $Bytes, $Sizes[$i] }else { "0 B" }
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
    $script:Found = $false

    if ($AllFolders) {
        $FoundFiles = Get-ChildItem C:\ -Filter *.ost -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Length / ($MinSize * 1GB) -gt 1 }
        $FoundFiles | Select-Object FullName, Length | ForEach-Object {
            $Name = $_.FullName
            $Size = $_.Length
            Write-Host "$Name $(Get-FriendlySize -Bytes $Size)"
        }
        # If you wish to automatically remove the file(s) uncomment the line below. Do note that this is permanent! Make backups!
        # $FoundFiles | Remove-Item -Force -Confirm:$false
        if ($FoundFiles) {
            $script:Found = $true
        }
    }
    else {
        $UsersFolder = "C:\Users"
        $Outlook = "AppData\Local\Microsoft\Outlook"
        Get-ChildItem -Path $UsersFolder | ForEach-Object {
            $User = $_
            $Folder = "$UsersFolder\$User\$Outlook"
            if ($(Test-Path -Path $Folder)) {
                $FoundFiles = Get-ChildItem $Folder -Filter *.ost | Where-Object { $_.Length / ($MinSize * 1GB) -gt 1 }
                $FoundFiles | Select-Object FullName, Length | ForEach-Object {
                    $Name = $_.FullName
                    $Size = $_.Length
                    Write-Host "$Name $(Get-FriendlySize -Bytes $Size)"
                }
                # If you wish to automatically remove the file(s) uncomment the line below. Do note that this is permanent! Make backups!
                # $FoundFiles | Remove-Item -Force -Confirm:$false
                if ($FoundFiles) {
                    Write-Verbose "Found"
                    $script:Found = $true
                }
            }
        }
    }

    if ($script:Found) {
        Write-Host "[Error] Found at least one OST larger than $MinSize GB."
        exit 1
    }
    Write-Host "[Info] Did not find an OST file larger than $MinSize GB."
    exit 0
}
end {
    
    
    
}


