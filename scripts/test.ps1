# Builds zal-net's tools/tester.nim and hands over to it; see that file for the rules.
param(
  [ValidateSet("fast", "full", "stress", "platform")]
  [string]$Suite = "fast",
  [string]$AwsLc = "C:\dev\awslc",
  [string]$ZalNetDir = "..\zal-net",
  [string]$BuildDir = "build/test",
  [string[]]$Workers = @("1"),
  [string[]]$Tests = @(),
  [string]$Flags = "",
  [switch]$Release,
  [string]$Nimony = "nimony",
  [int]$TimeoutSec = 120
)
$ErrorActionPreference = "Continue"
Set-Location (Join-Path $PSScriptRoot "..")
# The compiler builds zal-net's plugins in their own directory: give it a path that stays valid there.
$env:ZAL_NET_DIR = (Resolve-Path $ZalNetDir).Path
$env:AWSLC = (Resolve-Path $AwsLc).Path
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
$BuildDir = (Resolve-Path $BuildDir).Path
$tester = Join-Path $BuildDir "tester.exe"
$env:LOCALAPPDATA = Join-Path $BuildDir "c-cache"
& $Nimony c --ff "--nimcache:$BuildDir\cache-tester" "-o:$tester" (Join-Path $env:ZAL_NET_DIR "tools\tester.nim") *> (Join-Path $BuildDir "tester.log")
if ($LASTEXITCODE -ne 0) { Get-Content (Join-Path $BuildDir "tester.log"); exit 1 }
$list = @($Workers | ForEach-Object { $_.Split(",") } | Where-Object { $_ }) -join ","
$a = @("--nimony:$Nimony", "--build:$BuildDir", "--workers:$list", "--timeout:$TimeoutSec")
if ($Flags) { $Flags.Split(" ") | Where-Object { $_ } | ForEach-Object { $a += "--flag:$_" } }
if ($Release) { $a += "--flag:-d:release" }
$Tests = @($Tests | ForEach-Object { $_.Split(",") } | Where-Object { $_ })
foreach ($t in $Tests) {
  # A path, a category/tname, or a bare test name.
  if (Test-Path $t) { $a += $t; continue }
  if (Test-Path "tests/$t.nim") { $a += "tests/$t.nim"; continue }
  $named = @(Get-ChildItem tests -Recurse -Filter "$t.nim")
  $a += $(if ($named.Count -gt 0) { $named[0].FullName } else { $t })
}
if ($Tests.Count -eq 0) {
  if ($Suite -eq "full") { $a += "tests", "examples" } else { $a += "--suite:$Suite" }
}
& $tester @a
exit $LASTEXITCODE
