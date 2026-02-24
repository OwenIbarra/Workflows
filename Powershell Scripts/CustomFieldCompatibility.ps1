if (-not (Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue)) {
    if (-not $script:WorkflowCustomFieldStore) {
        $script:WorkflowCustomFieldStore = @{}
    }

    function Get-WorkflowCustomFieldStoreKey {
        param(
            [Parameter()]
            [String]$Name,
            [Parameter()]
            [String]$DocumentName,
            [Parameter()]
            [String]$AttributeName
        )

        if ($AttributeName) {
            if ($DocumentName) {
                return ("doc:{0}:{1}" -f $DocumentName, $AttributeName)
            }

            return "doc:$AttributeName"
        }

        return "field:$Name"
    }

    function Ninja-Property-Set {
        param(
            [Parameter(Mandatory = $true)]
            [String]$Name,
            [Parameter(Mandatory = $true)]
            $Value
        )

        $script:WorkflowCustomFieldStore[(Get-WorkflowCustomFieldStoreKey -Name $Name)] = $Value
        $Value
    }

    function Ninja-Property-Get {
        param(
            [Parameter(Mandatory = $true)]
            [String]$Name
        )

        $script:WorkflowCustomFieldStore[(Get-WorkflowCustomFieldStoreKey -Name $Name)]
    }

    function Ninja-Property-Options {
        param(
            [Parameter(Mandatory = $true)]
            [String]$Name
        )

        @()
    }

    function Ninja-Property-Docs-Set {
        param(
            [Parameter(Mandatory = $true)]
            [String]$AttributeName,
            [Parameter(Mandatory = $true)]
            $AttributeValue,
            [Parameter()]
            [String]$DocumentName
        )

        $script:WorkflowCustomFieldStore[(Get-WorkflowCustomFieldStoreKey -AttributeName $AttributeName -DocumentName $DocumentName)] = $AttributeValue
        $AttributeValue
    }

    function Ninja-Property-Docs-Get {
        param(
            [Parameter(Mandatory = $true)]
            [String]$AttributeName,
            [Parameter()]
            [String]$DocumentName
        )

        $script:WorkflowCustomFieldStore[(Get-WorkflowCustomFieldStoreKey -AttributeName $AttributeName -DocumentName $DocumentName)]
    }

    function Ninja-Property-Docs-Options {
        param(
            [Parameter(Mandatory = $true)]
            [String]$AttributeName,
            [Parameter()]
            [String]$DocumentName
        )

        @()
    }
}
