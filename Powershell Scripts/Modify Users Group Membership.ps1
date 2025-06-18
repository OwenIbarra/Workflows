# Add or remove a user to a group in Active Directory or the local computer.
#Requires -Version 2.0

<#
.SYNOPSIS
    Add or remove a user to a group in Active Directory or the local computer.
.DESCRIPTION
    Add or remove a user to a group in Active Directory or the local computer.
.EXAMPLE
     -Group "MyGroup" -UserName "MyUser" -Action Add -IsDomainUser
    Adds MyUser to the group MyGroup in AD.
.EXAMPLE
     -Group "MyGroup" -UserName "MyUser" -Action Remove -IsDomainUser
    Removes MyUser from the group MyGroup in AD.
.EXAMPLE
     -Group "MyGroup" -UserName "MyUser" -Action Add
    Adds MyUser to the group MyGroup on the local computer.
.EXAMPLE
    PS C:\> Modify-User-Membership.ps1 -Group "MyGroup" -UserName "MyUser" -Action Remove
    Removes MyUser from the group MyGroup on the local computer.
.OUTPUTS
    String[]
.NOTES
    Minimum OS Architecture Supported: Windows 7, Windows Server 2012
    This will require RSAT with the AD feature to be installed to function.
    Release Notes: Renamed script and added Script Variable support
.COMPONENT
    ManageUsers
#>

[CmdletBinding()]
param (
    # Specify one Group
    [Parameter()]
    [String]$Group,
    # Specify one User
    [Parameter()]
    [String]$UserName,
    # Add or Remove user from group
    [Parameter()]
    [ValidateSet("Add", "Remove")]
    [String]$Action,
    # Modify a domain user's membership
    [Parameter()]
    [Switch]$IsDomainUser = [System.Convert]::ToBoolean($env:isADomainUser)
)

begin {
    if ($env:userToModify -and $env:userToModify -notlike "null") { $UserName = $env:userToModify }
    if ($env:groupName -and $env:groupName -notlike "null") { $Group = $env:groupName }
    if ($env:action -and $env:action -notlike "null") { $Action = $env:action }

    if (-not ($Group) -and -not ($UserName)) { Write-Error "A user and group must be specified!"; Exit 1 }
    if (-not ($Action)) { Write-Error "An action must be specified!"; Exit 1 }
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
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
    if (-not $IsDomainUser) {
        # Modify Local User
        if ($Action -like "Remove") {
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                # Connect to localhost
                try {
                    $ADSI = [ADSI]("WinNT://$env:COMPUTERNAME")
                }
                catch {
                    Write-Error -Message "Failed to connect to $env:COMPUTERNAME via ADSI object"
                    exit 1
                }
                # Find the group
                try {
                    $ASDIGroup = $ADSI.Children.Find($Group, 'group')
                }
                catch {
                    Write-Error -Message "Failed to find $Group via ADSI object"
                    exit 1
                }
                # Remove the user from the group
                try {
                    $ASDIGroup.Remove(("WinNT://$env:COMPUTERNAME/$UserName"))
                }
                catch {
                    Write-Error -Message "Failed to remove User $UserName from Group $Group"
                    exit 529 # ERROR_MEMBER_NOT_IN_GROUP
                }
                
            }
            else {
                if (
                    # Check that the group exists
                (Get-LocalGroup -Name $Group -ErrorAction SilentlyContinue) -and
                    # Check that the user exists in the group
                (Get-LocalGroupMember -Group $Group -Member $UserName -ErrorAction SilentlyContinue)
                ) {
                    Write-Output "Found $UserName in Group $Group, removing."
                    try {
                        # Remove user from Group, -Confirm:$false used to not prompt and stop the script
                        Remove-LocalGroupMember -Group $Group -Member $UserName -Confirm:$false
                        Write-Output "Removed User $UserName from Group $Group"
                    }
                    catch {
                        Write-Error -Message "Failed to remove User $UserName from Group $Group"
                        exit 529 # ERROR_MEMBER_NOT_IN_GROUP
                    }
                }
                elseif (-not (Get-LocalGroup -Name $Group -ErrorAction SilentlyContinue)) {
                    Write-Error -Message "Group $Group does not exist"
                    exit 528 # ERROR_NO_SUCH_GROUP
                }
                elseif (-not (Get-LocalGroupMember -Group $Group -Member $UserName -ErrorAction SilentlyContinue)) {
                    Write-Error -Message "User does not exist in Group $Group"
                    exit 529 # ERROR_MEMBER_NOT_IN_GROUP
                }
            }
            
        }
        elseif ($Action -like "Add") {
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                # Connect to localhost
                try {
                    $ADSI = [ADSI]("WinNT://$env:COMPUTERNAME")
                }
                catch {
                    Write-Error -Message "Failed to connect to $env:COMPUTERNAME via ADSI object"
                    exit 1
                }
                # Find the group
                try {
                    $ASDIGroup = $ADSI.Children.Find($Group, 'group')
                }
                catch {
                    Write-Error -Message "Failed to find $Group via ADSI object"
                    exit 1
                }
                # Get the members of the group
                $GroupResults = try {
                    $ASDIGroup.psbase.invoke('members') | ForEach-Object {
                        $_.GetType().InvokeMember("Name", "GetProperty", $Null, $_, $Null)
                    }
                }
                catch {
                    $null
                }
                # Check if the user is in the group
                if ($UserName -in $GroupResults) {
                    # User already in Group
                    Write-Output "User $UserName already in Group $Group"
                    exit 1320 # ERROR_MEMBER_IN_GROUP
                }
                else {
                    # User not in group, add them to the group
                    try {
                        $ASDIGroup.Add(("WinNT://$env:COMPUTERNAME/$UserName"))
                    }
                    catch {
                        Write-Error -Message "Failed to add User $UserName to Group $Group"
                        exit 1388 # ERROR_INVALID_MEMBER
                    }
                    
                    # We can verify the membership by running the following  command:
                    if ($UserName -in (
                            $ASDIGroup.psbase.invoke('members') | ForEach-Object {
                                $_.GetType().InvokeMember("Name", "GetProperty", $Null, $_, $Null)
                            }
                        )
                    ) {
                        # User in Group
                        Write-Output "Added User $UserName to Group $Group"
                    }
                    else {
                        Write-Error -Message "Failed to add User $UserName to Group $Group"
                        exit 1388 # ERROR_INVALID_MEMBER
                    }
                }
                
            }
            else {
                # Verify that the user and group exist
                if (
                    # Check that the user exists
                (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue) -and
                    # Check that the group exists
                (Get-LocalGroup -Name $Group -ErrorAction SilentlyContinue)
                ) {
                    # Check if user is already in group
                    if (-not (Get-LocalGroupMember -Group $Group -Member $UserName -ErrorAction SilentlyContinue)) {
                        # User not in group, good to add
                        try {
                            # Add user to group
                            Add-LocalGroupMember -Group $Group -Member (Get-LocalUser -Name $UserName)
                            Write-Output "Added User $UserName to Group $Group"
                        }
                        catch {
                            Write-Error -Message "Failed to add User $UserName to Group $Group"
                            exit 1388 # ERROR_INVALID_MEMBER
                        }
                    }
                    else {
                        # User already in Group
                        Write-Output "User $UserName already in Group $Group"
                        exit 1320 # ERROR_MEMBER_IN_GROUP
                    }
                
                }
            }
        }
    }
    else {
        if ((Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue)) {
            try {
                Import-Module -Name ActiveDirectory
                # Get most of our data needed for the logic, and to reduce the number of time we need to talk to AD
                $ADUser = (Get-ADUser -Identity $UserName -Properties SamAccountName -ErrorAction SilentlyContinue).SamAccountName
                $ADGroup = Get-ADGroup -Identity $Group -ErrorAction SilentlyContinue
                $ADInGroup = Get-ADGroupMember -Identity $Group -ErrorAction SilentlyContinue | Where-Object { $_.SamAccountName -like $ADUser }
            }
            catch {
                Write-Error -Message "Ninja Agent could not access AD, please check that the agent has permissions to add and remove users from groups."
                exit 5 # Access Denied exit code
            }
            
            # Modify AD User
            if ($Action -like "Remove") {
                # Verify that the user and group exist, and if the user is in the group
                if (
                    $ADUser -and
                    # Check that the group exists
                    $ADGroup -and
                    # Check that the user exists in the group
                    $ADInGroup
                ) {
                    Write-Output "Found $UserName in Group $Group, removing."
                    try {
                        # Remove user from Group, -Confirm:$false used to not prompt and stop the script
                        Remove-ADGroupMember -Identity $Group -Members $ADUser -Confirm:$false
                        Write-Output "Removed User $UserName from Group $Group"
                    }
                    catch {
                        Write-Error -Message "Failed to remove User $UserName from Group $Group"
                        exit 529 # ERROR_MEMBER_NOT_IN_GROUP
                    }
                }
                elseif (-not $ADGroup) {
                    Write-Error -Message "Group $Group does not exist"
                    exit 528 # ERROR_NO_SUCH_GROUP
                }
                elseif (-not $ADInGroup) {
                    Write-Error -Message "User does not exist in Group $Group"
                    exit 529 # ERROR_MEMBER_NOT_IN_GROUP
                }
            }
            elseif ($Action -like "Add") {
                # Verify that the user and group exist
                if (
                    # Check that the user exists
                    $ADUser -and
                    # Check that the group exists
                    $ADGroup
                ) {
                    # Check if user is already in group
                    if (-not $ADInGroup) {
                        # User not in group, good to add
                        try {
                            # Add user to group
                            Add-ADGroupMember -Identity $Group -Members $ADUser
                            Write-Output "Added User $UserName to Group $Group"
                        }
                        catch {
                            Write-Error -Message "Failed to add User $UserName to Group $Group"
                            exit 1388 # ERROR_INVALID_MEMBER
                        }
                    }
                    else {
                        # User already in Group
                        Write-Output "User $UserName already in Group $Group"
                        exit 1320 # ERROR_MEMBER_IN_GROUP
                    }
                }
            }
        }
        else {
            # Throw error that RSAT: ActiveDirectory isn't installed
            Write-Error -Message "RSAT: ActiveDirectory is not installed or not found on this computer. The PowerShell Module called ActiveDirectory is needed to proceed." -RecommendedAction "https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2019-ps"
            exit 2 # File Not Found exit code
        }
    }
}
end {
    
    
    
}


