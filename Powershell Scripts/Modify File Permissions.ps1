# Modify User Permissions for files and folder.
#Requires -Version 5.1

<#
.SYNOPSIS
    Modify User Permissions for files and folder.
.DESCRIPTION
    Modify User Permissions for files and folder. You can assign or block multiple permissions to multiple users, and multiple files and folders.
.EXAMPLE
     -User "Test" -Path "C:\Test" -Permissions FullControl
    Gives FullControl permissions to the user Test for just the folder C:\Test
.EXAMPLE
     -User "Test1", "Test2" -Path "C:\Test" -Permissions FullControl
    Gives FullControl permissions to the user Test1 and Test2 for just the folder C:\Test
.EXAMPLE
     -User "Test1", "Test2" -Path "C:\Test", "C:\Temp" -Permissions FullControl
    Gives FullControl permissions to the user Test1 and Test2 for just the folders C:\Test and C:\Temp
.EXAMPLE
     -User "Test" -Path "C:\Test\Document.docx" -Permissions FullControl
    Gives FullControl permissions to the user Test for just the file C:\Test\Document.docx
.EXAMPLE
     -User "Test" -Path "C:\Test\Document.docx" -Permissions ReadData, Modify
    Gives ReadData and Modify permissions to the user Test for just the file C:\Test\Document.docx
.EXAMPLE
     -User "Test" -Path "C:\Test\Document.docx" -Permissions FullControl -Block
    Blocks FullControl permissions from the user Test for just the file C:\Test\Document.docx
.EXAMPLE
     -User "Test" -Path "C:\Test" -Permissions FullControl -Recursive
    Gives FullControl permissions to the user Test for the folder C:\Test and any folder or file under it will inherit FullControl
.EXAMPLE
    PS C:\> .\Modify-User-Permissions.ps1 -User "Test" -Path "C:\Test" -Permissions FullControl -Recursive
    Gives FullControl permissions to the user Test for the folder C:\Test and any folder or file under it will inherit FullControl
.INPUTS
    Inputs (User,Path,Permissions)
.OUTPUTS
    FileSecurity
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Renamed script and added Script Variable support
.COMPONENT
    ManageUsers
#>

[CmdletBinding()]
param (
    [ValidateScript(
        {
            # Validate that the User(s) exist
            if ($(Get-LocalUser -Name $_)) { $true } else { $false }
        }
    )]
    [String[]]
    # The user name of the user you want to apply Permissions to a Path(s)
    $User,
    [ValidateScript({ Test-Path -Path $_ })]
    [String[]]
    # File path that you want to apply Permissions to
    $Path,
    # Permission to set the path(s) for the user(s)
    # This accepts the following:
    #  ListDirectory, ReadData, WriteData, CreateFiles, CreateDirectories, AppendData, ReadExtendedAttributes,
    #  WriteExtendedAttributes, Traverse, ExecuteFile, DeleteSubdirectoriesAndFiles, ReadAttributes,
    #  WriteAttributes, Write, Delete, ReadPermissions, Read, ReadAndExecute, Modify, ChangePermissions,
    #  TakeOwnership, Synchronize, FullControl
    [System.Security.AccessControl.FileSystemRights[]]
    $Permissions,
    # Block the specified Permissions for the specified $User
    [Switch]$Block = [System.Convert]::ToBoolean($env:block),
    # Apply the Permissions down through a folder structure, i.e. inheritance
    [Switch]$Recursive = [System.Convert]::ToBoolean($env:enableInheritance)
)

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
        { Write-Output $true }
        else
        { Write-Output $false }
    }
}

process {
    if ($env:user -and $env:user -notlike "null") {
        $User = $env:user
    }

    if ($env:filePath -and $env:filePath -notlike "null") {
        $Path = $env:filePath
    }

    if ($env:permissions -and $env:permissions -notlike "null") {
        $Permissions = $env:permissions
    }

    if (-not $User -and -not $Path -and -not $Permissions) {
        Write-Error "A user, filePath, and permission to set is required."
        exit 1
    }

    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    $script:HasError = $false
    $Path | ForEach-Object {
        $CurPath = Get-Item -Path $_
        $User | ForEach-Object {
            $NewAcl = Get-Acl -Path $CurPath
            # Set properties
            $identity = Get-LocalUser -Name $_
            $fileSystemRights = $Permissions
            $type = $(if ($Block) { [System.Security.AccessControl.AccessControlType]::Deny }else { [System.Security.AccessControl.AccessControlType]::Allow })
            $fileSystemRights | ForEach-Object {
                # Create new rule
                Write-Host "Creating $type $_ rule for user: $identity"
                # Check if Recursive was used and that the current path is a folder
                if ($CurPath.PSIsContainer -and $Recursive) {
                    $inheritanceFlags = 'ObjectInherit,ContainerInherit'
                    $NewAcl.SetAccessRuleProtection($false, $true)
                }
                else {
                    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
                }
                $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
                $fileSystemAccessRuleArgumentList = $identity, $_, $inheritanceFlags, $propagationFlags, $type
                $fileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fileSystemAccessRuleArgumentList

                # Apply new rule
                $NewAcl.SetAccessRule($fileSystemAccessRule)
                try {
                    Set-Acl -Path $CurPath -AclObject $NewAcl -Passthru
                }
                catch {
                    Write-Error $_
                    $script:HasError = $true
                }
            }
        }
    }
    if ($script:HasError) {
        exit 1
    }
}

end {
    
    
    
}

