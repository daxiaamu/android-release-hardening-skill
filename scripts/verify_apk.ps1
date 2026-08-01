param(
    [Parameter(Mandatory=$true)][string]$ApkPath,
    [Parameter(Mandatory=$true)][string]$ExpectedCertSha256,
    [string]$ApkSigner = '',
    [bool]$RequireV1 = $true,
    [bool]$RequireV2 = $true,
    [bool]$RequireV3 = $true,
    [string]$JsonOut = ''
)
$ErrorActionPreference = 'Stop'
$apk = (Resolve-Path -LiteralPath $ApkPath).Path
if (-not $ApkSigner) {
    $sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } elseif ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } else { '' }
    if (-not $sdk) { throw 'Set ANDROID_HOME/ANDROID_SDK_ROOT or pass -ApkSigner' }
    $candidate = Get-ChildItem (Join-Path $sdk 'build-tools') -Directory | Sort-Object Name -Descending | ForEach-Object { Join-Path $_.FullName 'apksigner.bat' } | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $candidate) { throw 'apksigner was not found' }
    $ApkSigner = $candidate
}
$expected = ($ExpectedCertSha256 -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
if ($expected.Length -ne 64) { throw 'ExpectedCertSha256 must contain 64 hex characters' }
$saved = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$output = (& $ApkSigner verify --verbose --print-certs $apk 2>&1) -join "`n"
$code = $LASTEXITCODE
$ErrorActionPreference = $saved
if ($code -ne 0) { throw "apksigner verify failed:`n$output" }
function Scheme([string]$name) { return [bool]($output -match "Verified using $name scheme .*:\s*true") }
$v1 = Scheme 'v1'
$v2 = Scheme 'v2'
$v3 = Scheme 'v3'
$match = [regex]::Match($output, 'certificate SHA-256 digest:\s*([0-9a-fA-F]+)')
if (-not $match.Success) { throw 'Certificate SHA-256 was not present in apksigner output' }
$actual = $match.Groups[1].Value.ToUpperInvariant()
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $apk).Hash
$errors = @()
if ($actual -ne $expected) { $errors += "certificate mismatch: $actual" }
if ($RequireV1 -and -not $v1) { $errors += 'v1 required but absent' }
if ($RequireV2 -and -not $v2) { $errors += 'v2 required but absent' }
if ($RequireV3 -and -not $v3) { $errors += 'v3 required but absent' }
$result = [ordered]@{ apk=$apk; sha256=$hash; certSha256=$actual; v1=$v1; v2=$v2; v3=$v3; passed=($errors.Count -eq 0); errors=$errors }
$json = $result | ConvertTo-Json -Depth 4
if ($JsonOut) { Set-Content -LiteralPath $JsonOut -Value $json -Encoding UTF8 }
Write-Output $json
if ($errors.Count) { exit 2 }
