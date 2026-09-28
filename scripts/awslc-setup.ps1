param(
  [string]$Directory = "build/aws-lc",
  [string]$Compiler = "gcc",
  [int]$Jobs = 4
)
$ErrorActionPreference = "Stop"
$pin = (Get-Content (Join-Path $PSScriptRoot "../ci/aws-lc.ref")).Split(" ")
$commit = $pin[1]
New-Item -ItemType Directory -Force $Directory | Out-Null
$Directory = (Resolve-Path $Directory).Path
$source = Join-Path $Directory "src"
$build = Join-Path $Directory "cache"
$install = Join-Path $Directory "install"
if (-not (Test-Path "$source/.git")) {
  git clone --depth 1 --branch $pin[0] https://github.com/aws/aws-lc.git $source
  if ($LASTEXITCODE -ne 0) { throw "AWS-LC clone failed" }
}
if ((git -C $source rev-parse HEAD) -ne $commit) { throw "AWS-LC revision differs from ci/aws-lc.ref" }
$flags = @("-S", $source, "-B", $build, "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
  "-DCMAKE_C_COMPILER=$Compiler", "-DCMAKE_INSTALL_PREFIX=$install", "-DBUILD_SHARED_LIBS=OFF",
  "-DBUILD_TESTING=OFF", "-DBUILD_LIBSSL=OFF", "-DDISABLE_GO=ON", "-DOPENSSL_NO_ASM=ON")
if ($Compiler -eq "gcc") { $flags += "-DCMAKE_CXX_COMPILER=g++" }
cmake @flags
if ($LASTEXITCODE -ne 0) { throw "AWS-LC configuration failed" }
cmake --build $build --parallel $Jobs
if ($LASTEXITCODE -ne 0) { throw "AWS-LC build failed" }
cmake --install $build
if ($LASTEXITCODE -ne 0) { throw "AWS-LC installation failed" }
$install
