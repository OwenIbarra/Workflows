# Get a tree list of folder sizes for a given path with folders that meet a minimum size.
#Requires -Version 5.1

<#
.SYNOPSIS
    Get a tree list of folder sizes for a given path with folders that meet a minimum size.
.DESCRIPTION
    Get a tree list of folder sizes for a given path with folders that meet a minimum size.
.EXAMPLE
    -Path C:\Users -MinSize "500 MB" -Depth "3"
    
    DisplayPath                      FriendlySize
    -----------                      ------------
    C:\Users                         925.83 MB   
      C:\Users\All Users             809.31 MB   
        C:\Users\All Users\Microsoft 681.52 MB   

PARAMETER: -Path "C:\ReplaceMeWithYourDesiredFolderPath"
    Specifies the starting path to get the folders and subfolders to report on.

PARAMETER: -Depth "3"
    Specifies the depth of folders to return. The larger this number is, the longer the script will take to complete.

PARAMETER: -MinSize "100 KB"
    Specifies the minimum size of folders to return.

PARAMETER: -SortBy "Size"
    Specifies the sorting method for the folder list. Choose 'Size' to sort folders by their size in descending order or 'Alphabetical' to sort folders by their name in alphabetical order.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Added error message for failed directories.
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Path,
    [Parameter()]
    [long]$Depth = 3,
    [Parameter()]
    $MinSize = 500MB,
    [Parameter()]
    [String]$SortBy = "Size"
)

begin {
    # If script form variables are used, replace the command line parameters with them.
    if ($env:rootPath -and $env:rootPath -notlike "null") { $Path = $env:rootPath }
    if ($env:depth -and $env:depth -notlike "null") { $Depth = $env:depth }
    if ($env:minimumFolderSize -and $env:minimumFolderSize -notlike "null") { $MinSize = $env:minimumFolderSize }
    if ($env:sortBy -and $env:sortBy -notlike "null") { $SortBy = $env:sortBy }

    # Check if the Path variable is set; if not, display an error and exit.
    if (!$Path) {
        Write-Host -Object "[Error] No path was given. Please provide a path to search."
        exit 1
    }

    # Check if the MinSize variable is set; if not, display an error and exit.
    if (!$MinSize) {
        Write-Host -Object "[Error] No minimum folder size was given. Please provide a minimum size to search."
        exit 1
    }

    # Check if the Path variable contains any invalid characters; if so, display an error and exit.
    if ($Path -match '[<>"/|?]') {
        Write-Host -Object "[Error] The path given ($Path) contains an invalid character such as '<>`"/|:?'."
        exit 1
    }

    # Check if the Path exists; if not, display an error and exit.
    if (!(Test-Path -Path $Path -ErrorAction SilentlyContinue)) {
        Write-Host -Object "[Error] Path '$Path' does not exist!"
        exit 1
    }

    # Check if the MinSize variable contains any invalid characters or patterns; if so, display an error and exit.
    if ($MinSize -match '[^0-9|PB|TB|GB|MB|KB|B|Bytes|\s]' -or $MinSize -match 'P.+B|T.+B|G.+B|M.+B|K.+B' ) {
        Write-Host "[Error] '$MinSize' contains invalid characters. Only '0-9' characters and characters used to denote size are allowed, e.g., 'GB' or 'MB'"
        exit 1
    }

    # Define the valid sort options.
    $ValidSort = "Size", "Alphabetical"

    # Check if the SortBy variable contains a valid sort option; if not, display an error and exit.
    if ($ValidSort -notcontains $SortBy) {
        Write-Host "[Error] An invalid sort option was given: '$SortBy'. Only 'Size' and 'Alphabetical' are valid sort options."
        exit 1
    }

    function Get-Size {
        param ([string]$String)
        switch -wildcard ($String) {
            '*PB' { [long]$($String -replace '[^\d+]+') * 1PB; break }
            '*TB' { [long]$($String -replace '[^\d+]+') * 1TB; break }
            '*GB' { [long]$($String -replace '[^\d+]+') * 1GB; break }
            '*MB' { [long]$($String -replace '[^\d+]+') * 1MB; break }
            '*KB' { [long]$($String -replace '[^\d+]+') * 1KB; break }
            '*B' { [long]$($String -replace '[^\d+]+') * 1; break }
            '*Bytes' { [long]$($String -replace '[^\d+]+') * 1; break }
            Default { [long]$($String -replace '[^\d+]+') * 1 }
        }
    }

    function Get-FriendlySize {
        param(
            [Parameter(ValueFromPipeline = $True)]
            $Bytes
        )
        # Converts Bytes to the highest matching unit
        $Sizes = 'Bytes,KB,MB,GB,TB,PB,EB,ZB' -split ','
        for ($i = 0; ($Bytes -ge 1kb) -and ($i -lt $Sizes.Count); $i++) { $Bytes /= 1kb }
        $N = 2
        if ($i -eq 0) { $N = 0 }
        if ($Bytes) { "{0:N$($N)} {1}" -f $Bytes, $Sizes[$i] }else { "0 B" }
    }
    function Get-SizeInfo {
        [CmdletBinding()]
        param(
            [parameter(mandatory = $true, position = 0)][string]$TargetFolder,
            #defines the depth to which individual folder data is provided
            [parameter(mandatory = $true, position = 1)][long]$DepthLimit
        )
        $obj = New-Object PSObject -Property @{Name = $targetFolder; Size = 0; Subs = @() }
        # Are we at the depth limit? Then just do a recursive Get-ChildItem
        if ($DepthLimit -eq 1) {
            $obj.Size = (Get-ChildItem $targetFolder -Recurse -Force -File -ErrorAction SilentlyContinue -ErrorVariable '+ChildItemErrors' | Measure-Object -Sum -Property Length).Sum
            return $obj
        }
        # We are not at the depth limit, keep recursing
        $obj.Subs = foreach ($S in Get-ChildItem -Path $targetFolder -Force) {
            if ($S.PSIsContainer) {
                $tmp = Get-SizeInfo $S.FullName ($DepthLimit - 1) -ErrorAction SilentlyContinue -ErrorVariable '+ChildItemErrors'
                $obj.Size += $tmp.Size
                Write-Output $tmp
            }
            else {
                $obj.Size += $S.length
            }
        }
        return $obj
    }
    function Write-Results {
        param(
            [parameter(mandatory = $true, position = 0)]$Data,
            [parameter(mandatory = $true, position = 1)][long]$IndentDepth,
            [parameter(mandatory = $true, position = 2)][long]$MinSize
        )
    
        [PSCustomObject]@{
            TruePath     = $Data.Name
            DisplayPath  = "$((' ' * ($IndentDepth + 2)) + $Data.Name)"
            Depth        = $IndentDepth
            Bytes        = $Data.Size
            FriendlySize = Get-FriendlySize -Bytes $Data.Size
            IsLarger     = $Data.Size -ge $MinSize
        }

        foreach ($S in $Data.Subs) {
            Write-Results $S ($IndentDepth + 1) $MinSize
        }
    }
    function Get-SubFolderSize {
        [CmdletBinding()]
        param(
            [parameter(mandatory = $true, position = 0)]
            [string]$targetFolder,
    
            [long]$DepthLimit = 3,
            [long]$MinSize = 500MB
        )
        if (-not (Test-Path $targetFolder)) {
            Write-Host "[Error] The target [$targetFolder] does not exist"
            exit
        }
        $Data = Get-SizeInfo $targetFolder $DepthLimit
    
        #returning $data will provide a useful PS object rather than plain text
        # return $Data
    
        #generate a human friendly listing
        Write-Results $Data 0 $MinSize
    }
    function Reconstruct-Tree {
        param (
            [array]$Folders,
            [int]$CurrentDepth = 0,
            [string]$ParentPath = ""
        )

        # Create a new list to store the result
        $result = New-Object System.Collections.Generic.List[object]

        # Filter folders to get only those at the current depth and that match the parent path
        $currentLevelFolders = $Folders | Where-Object { $_.Depth -eq $CurrentDepth -and $_.TruePath -like "$ParentPath*" }

        # Loop through each folder at the current level
        foreach ($folder in $currentLevelFolders) {
            # Add the current folder to the result list
            $result.Add($folder)

            # Recursively call Reconstruct-Tree for the next depth level and the current folder's path
            Reconstruct-Tree -Folders $Folders -CurrentDepth ($CurrentDepth + 1) -ParentPath $folder.TruePath | ForEach-Object {
                # Add each sub-folder to the result list
                $result.Add($_)
            }
        }

        # Return the reconstructed list of folders preserving the tree structure
        return $result
    }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Test-IsSystem {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return $id.Name -like "NT AUTHORITY*" -or $id.IsSystem
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    if (!(Test-IsElevated) -and !(Test-IsSystem)) {
        Write-Host "[Warning] Not running as SYSTEM account, results might be slightly inaccurate."
    }

    try {
        $SearchPath = Get-Item -Path $Path -Force -ErrorAction Stop | Select-Object -ExpandProperty FullName
    }
    catch {
        Write-Host -Object "[Error] Unable to retrieve search path."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    $Size = Get-Size $MinSize

    $BasicSubFolderInfo = Get-SizeInfo -TargetFolder $SearchPath -DepthLimit $Depth -ErrorAction SilentlyContinue -ErrorVariable ChildItemErrors
    $SubFoldersWithDisplayPath = Write-Results $BasicSubFolderInfo 0 $Size
    
    if ($SortBy -eq "Size") {
        $Results = $SubFoldersWithDisplayPath | Where-Object { $_.IsLarger } | Select-Object -Property DisplayPath, FriendlySize, TruePath, Bytes, Depth | Sort-Object -Property Depth, @{Expression = { $_.Bytes }; Descending = $true }
        $FinalResult = Reconstruct-Tree -Folders $Results
        $FinalResult | Format-Table DisplayPath, FriendlySize -AutoSize | Out-String | Write-Host
    }
    else {
        $SubFoldersWithDisplayPath | Where-Object { $_.IsLarger } | Select-Object -Property DisplayPath, FriendlySize | Format-Table -AutoSize | Out-String | Write-Host
    }

    if ($ChildItemErrors) {
        Write-Host -Object "[Error] An error occurred while processing the items in your search path. This report may be inaccurate. See the errors below for more details.`n"
        $ChildItemErrors | ForEach-Object {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    exit $ExitCode
}
end {
    
    
    
}

