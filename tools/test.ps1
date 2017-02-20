Param(
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Subject,

    [Parameter()]
    [string]
    $FriendlyName = "",

    [Parameter()]
    [string[]]
    $AlternativeNames = ""
)


dir $Subject