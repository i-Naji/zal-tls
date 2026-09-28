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
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
$BuildDir = (Resolve-Path $BuildDir).Path
$Workers = @($Workers | ForEach-Object { $_.Split(",") } | Where-Object { $_ })
$Tests = @($Tests | ForEach-Object { $_.Split(",") } | Where-Object { $_ })
if ($Tests.Count -eq 0 -and $Suite -ne "full") {
  switch ($Suite) {
    "fast" { $Tests = @("tbytes", "taead", "thash", "tconfig", "trecordapi", "thandshake", "ttlsref", "tapplicationtls", "tcryptobounds", "twritergate") }
    "stress" { $Tests = @("tmemory", "tfuzz") }
    "platform" { $Tests = @("tktls", "tktlsbounds", "tkernelsplice", "tkernelrelay") }
  }
}
foreach ($name in $Tests) {
  if (-not (Test-Path "tests\$name.nim" -PathType Leaf)) {
    Write-Output "FAIL missing source tests\$name.nim"
    exit 1
  }
}
$sources = if ($Tests.Count -gt 0) {
  @($Tests | ForEach-Object { Get-Item "tests\$_.nim" })
} else {
  @(Get-ChildItem tests -Filter "t*.nim") + @(Get-ChildItem examples -Filter "*.nim")
}
$fail = 0
foreach ($be in @("runtime")) {
  $compileArgs = @("--path:src", "--path:$ZalNetDir\src", "--passC:-I$AwsLc\include", "--passL:$AwsLc\lib\libcrypto.a",
             "--passL:-lws2_32", "--passL:-lbcrypt", "--passL:-ladvapi32")
  if ($Flags) { $compileArgs += $Flags.Split(" ") }
  if ($Release) { $compileArgs += "-d:release" }
  $compileArgs += "--mm:atomicArc", "-d:useMimalloc"
  New-Item -ItemType Directory -Force -Path "$BuildDir\$be" | Out-Null
  foreach ($src in $sources) {
    $name = $src.BaseName
    $out = "$BuildDir\$be\$name.exe"
    $previousLocalAppData = $env:LOCALAPPDATA
    try {
      $env:LOCALAPPDATA = "$BuildDir\$be\c-cache-$name"
      New-Item -ItemType Directory -Force -Path $env:LOCALAPPDATA | Out-Null
      & $Nimony c --ff @compileArgs "--nimcache:$BuildDir\$be\cache-$name" "-o:$out" $src.FullName *> "$BuildDir\$be\$name.log"
      $compileExit = $LASTEXITCODE
    } finally {
      $env:LOCALAPPDATA = $previousLocalAppData
    }
    if ($compileExit -ne 0) { Write-Output "FAIL build $be $name"; $fail = 1; continue }
    if ($src.DirectoryName -like "*examples") { Write-Output "ok   build $be $name"; continue }
    foreach ($worker in $Workers) {
      $env:ZAL_WORKERS = "$worker"
      $output = "$BuildDir\$be\$name.w$worker.out"
      $process = Start-Process -FilePath $out -NoNewWindow -PassThru -RedirectStandardOutput $output -RedirectStandardError "$output.err"
      $null = $process.Handle
      if (-not $process.WaitForExit($TimeoutSec * 1000)) {
        $process.Kill()
        Write-Output "FAIL $be $name workers=$worker (timeout)"
        $fail = 1
      } elseif ($process.ExitCode -ne 0) {
        Write-Output "FAIL $be $name workers=$worker"
        $fail = 1
      } else {
        Write-Output "ok   $be $name workers=$worker"
      }
    }
  }
}
exit $fail
