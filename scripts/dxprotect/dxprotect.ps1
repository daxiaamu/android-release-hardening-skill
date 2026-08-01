param(
    [Parameter(Mandatory = $true)][string]$Config,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$ExtraArgs
)

$python = Get-Command python -ErrorAction Stop
& $python.Source "$PSScriptRoot\tools\protect.py" --config $Config @ExtraArgs
exit $LASTEXITCODE
