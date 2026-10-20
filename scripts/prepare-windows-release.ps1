param([Parameter(Mandatory)][string]$ExpectedTag, [switch]$AllowUnsigned)
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$version = (Get-Content -LiteralPath (Join-Path $repoRoot 'package.json') -Raw | ConvertFrom-Json).version
if ($version -notmatch '^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$' -or $ExpectedTag -cne "v$version") { throw 'Release tag must match package.json version.' }
$source = [IO.Path]::GetFullPath((Join-Path $repoRoot '../verification/build-work/packages/win-unpacked'))
$output = [IO.Path]::GetFullPath((Join-Path $repoRoot '../verification/ci-release'))
if (Test-Path -LiteralPath $output) { throw 'Release output exists; inspect it before retrying.' }
$files = @(Get-ChildItem -LiteralPath $source -Recurse -Force -File)
if (-not $files.Count -or (Get-ChildItem -LiteralPath $source -Recurse -Force -Attributes ReparsePoint)) { throw 'Missing application or unsafe package link.' }
if ($files | Where-Object { $_.Name -match '^(\.env(?:\..*)?|authorized_keys|known_hosts|id_ed25519.*|id_rsa.*)$' -or $_.Extension -in @('.key', '.pem', '.pub', '.log', '.dmp') }) { throw 'Unexpected private or diagnostic file in package.' }
$signature = (Get-AuthenticodeSignature -LiteralPath (Join-Path $source 'KeyForge.exe')).Status.ToString()
if ($signature -ne 'Valid' -and -not ($AllowUnsigned -and $signature -eq 'NotSigned')) { throw 'Application signature is invalid or unsigned output was not explicitly allowed.' }
$gitRoot = & git -C $repoRoot rev-parse --show-toplevel
if ($LASTEXITCODE -ne 0 -or [IO.Path]::GetFullPath($gitRoot) -ne $repoRoot) { throw 'Unexpected repository root.' }
$sourceCommit = & git -C $repoRoot rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[a-f0-9]{40}$') { throw 'Cannot identify release commit.' }
New-Item -ItemType Directory -Path $output | Out-Null
$bundle = Join-Path $output 'KeyForge'
Copy-Item -LiteralPath $source -Destination $bundle -Recurse
$name = "KeyForge-$version-windows-x64.zip"
$archive = Join-Path $output $name
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($bundle, $archive, [IO.Compression.CompressionLevel]::Optimal, $true)
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
$utf8 = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $output 'SHA256SUMS.txt'), "$hash  $name`n", $utf8)
$manifest = [ordered]@{version=$version; tag=$ExpectedTag; filename=$name; sha256=$hash; size=(Get-Item -LiteralPath $archive).Length; signature=$signature; sourceCommit=$sourceCommit}
[IO.File]::WriteAllText((Join-Path $output 'release-manifest.json'), ($manifest | ConvertTo-Json) + "`n", $utf8)
Write-Output "Prepared final public artifact: $name; signature: $signature; SHA256: $hash"
