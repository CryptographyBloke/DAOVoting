# T005 local GPU validation and benchmark workflow (Windows, NVIDIA GPU).
# Run from the repository root in Windows PowerShell 5.1 or PowerShell 7:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\reproduce_gpu.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\reproduce_gpu.ps1 -Large
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\reproduce_gpu.ps1 -Quick
#
# Steps: hardware/toolchain discovery -> build (CPU and GPU features) ->
# CPU + emulated-kernel tests -> device vectors -> batch-size sweep and
# end-to-end CPU/GPU comparison -> full protocol runs with GPU verification,
# public verification and oracle -> summary. Every output goes to a new
# directory results\local\t005-gpu-<timestamp>-<rev>. Private run material
# (results\local\...\private) must never be published.

param(
    [ValidateRange(1, 1000)][int] $Reps = 5,
    [string] $Sizes = "1,4,16,64,256,1024,4096,16384,65536,262144",
    [string] $TallyN = "8,64,256,1024",
    [ValidateRange(1, 1000)][int] $ProtocolReps = 3,
    [ValidateRange(0, 64)][int] $Device = 0,
    [int] $MinBatch = 0,          # adaptive threshold; 0 = derive from the sweep
    [string] $Feature = "",       # cuda (CUDA 12.x) or cuda13; "" = detect
    [switch] $Large,              # also full protocol runs at n = 256 and 1024
    [switch] $Quick,              # n = 8 and 64 only, fewer repetitions
    [switch] $SkipTests
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Native([string]$exe, [string[]]$argv, [string]$log) {
    # Windows PowerShell 5.1 turns redirected native stderr into errors.
    $prev = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    if ($log) { & $exe @argv 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $log -Append }
    else { & $exe @argv }
    $code = $LASTEXITCODE; $ErrorActionPreference = $prev
    if ($code -ne 0) { throw "failed ($code): $exe $($argv -join ' ')" }
}
function WriteJson($obj, $path) { $obj | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $path }

if ($Quick) { $TallyN = "8,64"; $Reps = 3; $ProtocolReps = 2; $Sizes = "1,16,256,4096,65536" }

# 1. Hardware and toolchain discovery ---------------------------------------
Step "1. Hardware and toolchain discovery"
foreach ($t in "cargo", "rustc", "git", "nvidia-smi") {
    if (-not (Get-Command $t -ErrorAction SilentlyContinue)) {
        throw "$t not found. Install Rust (rustup.rs, MSVC), Git and the NVIDIA driver; see reports/T005.md section D."
    }
}
$rev = (git rev-parse --short=12 HEAD).Trim()
$stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
$Out = Join-Path $PSScriptRoot "results\local\t005-gpu-$stamp-$rev"
if (Test-Path $Out) { throw "output directory exists: $Out" }
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$log = Join-Path $Out "run.log"

$smi = (nvidia-smi --query-gpu=name,memory.total,driver_version,compute_cap,pcie.link.gen.max,pcie.link.width.max,power.limit --format=csv,noheader) | Select-Object -First 1
Write-Host "GPU: $smi"
$cuda = $env:CUDA_PATH
$nvrtc = $null
if ($cuda -and (Test-Path $cuda)) {
    $nvrtc = Get-ChildItem -Path (Join-Path $cuda "bin") -Recurse -Filter "nvrtc64_*.dll" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notlike "*builtins*" } | Select-Object -First 1
}
if (-not $nvrtc) { throw "NVRTC not found: install the CUDA Toolkit 12.x or 13.x (sets CUDA_PATH); see reports/T005.md section D." }
# make NVRTC (and its builtins DLL) loadable for this session
$env:PATH = "$($nvrtc.DirectoryName);$env:PATH"
if (-not $Feature) {
    if ($nvrtc.Name -like "nvrtc64_13*") { $Feature = "cuda13" } else { $Feature = "cuda" }
}
$nvcc = ""
if (Get-Command nvcc -ErrorAction SilentlyContinue) { $nvcc = ((nvcc --version) -join " ") }
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$os = Get-CimInstance Win32_OperatingSystem
$machine = [ordered]@{
    source_revision = (git rev-parse HEAD).Trim()
    source_dirty = [bool](git status --porcelain --untracked-files=no)
    date = (Get-Date).ToString("o")
    gpu_nvidia_smi = $smi
    cuda_path = $cuda; nvrtc_dll = $nvrtc.FullName; nvcc = $nvcc; cargo_feature = $Feature
    cpu = $cpu.Name.Trim(); cores = $cpu.NumberOfCores; logical = $cpu.NumberOfLogicalProcessors
    os = "$($os.Caption) $($os.Version) build $($os.BuildNumber)"
    memory_gb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    rustc = (rustc -V); cargo = (cargo -V)
    power_scheme = ((powercfg /getactivescheme) -join " ")
}
WriteJson $machine (Join-Path $Out "machine.json")
nvidia-smi -q | Set-Content (Join-Path $Out "nvidia-smi-q.txt")
Write-Host "feature: $Feature   NVRTC: $($nvrtc.FullName)"

# 2. Build ---------------------------------------------------------------------
Step "2. Build (CPU-only reference build, then GPU + emulation build)"
Native "cargo" @("build", "--release", "--locked") $log
$cpuExe = Join-Path $Out "wod-cpu.exe"
Copy-Item "target\release\wod.exe" $cpuExe
Native "cargo" @("build", "--release", "--locked", "--features", "$Feature,cuda-emu") $log
$wod = Join-Path $Out "wod-gpu.exe"
Copy-Item "target\release\wod.exe" $wod

# 3. Tests ---------------------------------------------------------------------
if (-not $SkipTests) {
    Step "3. CPU and emulated-kernel correctness tests"
    Native "cargo" @("test", "--release", "--locked", "--features", "$Feature,cuda-emu") (Join-Path $Out "tests.log")
}

# 4. Device check and vectors ----------------------------------------------------
Step "4. NVRTC compile, device properties, deterministic vectors on the GPU"
$cc = (($smi -split ",")[3]).Trim() -replace "\.", ""
& $wod gpu-check --arch "compute_$cc" --device $Device | Set-Content (Join-Path $Out "gpu_check.json")
if ($LASTEXITCODE -ne 0) { throw "gpu-check failed" }
Get-Content (Join-Path $Out "gpu_check.json")
Native $wod @("gpu-vectors", "--check", "tests\vectors\bjj_mul_v1.json", "--backend", "cuda:$Device") (Join-Path $Out "vectors.log")

# GPU utilization / memory monitor (background, 200 ms)
$mon = Join-Path $Out "gpu_monitor.csv"
$monJob = Start-Job -ScriptBlock { param($f) nvidia-smi --query-gpu=timestamp,utilization.gpu,utilization.memory,memory.used,clocks.sm,power.draw,temperature.gpu --format=csv -lms 200 | Out-File -Encoding ascii $f } -ArgumentList $mon
try {
    # 5. Batch-size sweep and end-to-end engine comparison ------------------------
    Step "5. CPU vs GPU: batch sweep and end-to-end tally/replay (n = $TallyN)"
    Native $wod @("gpu-bench", "--backend", "cuda:$Device", "--sizes", $Sizes, "--reps", "$Reps", "--n", $TallyN, "--out", (Join-Path $Out "bench-cuda")) $log
    $sweep = (Get-Content (Join-Path $Out "bench-cuda\gpu_bench.json") -Raw | ConvertFrom-Json).gpu_bench.sweep
    if ($MinBatch -le 0) {
        $win = $sweep | Where-Object { $_.speedup -ge 1.0 } | Sort-Object jobs | Select-Object -First 1
        if ($win) { $MinBatch = [int]$win.jobs } else { $MinBatch = 1000000000 }
    }
    Write-Host "adaptive threshold (first batch size with S >= 1): $MinBatch"
    Native $wod @("gpu-bench", "--backend", "auto:$($MinBatch):$Device", "--sizes", $Sizes, "--reps", "$Reps", "--n", $TallyN, "--out", (Join-Path $Out "bench-auto")) $log

    # 6. CPU profile on this machine (baseline hotspots) ---------------------------
    Step "6. CPU hotspot profile"
    Native $cpuExe @("profile", "--n", $TallyN, "--groth-reps", "5", "--out", (Join-Path $Out "profile")) $log

    # 7. Full protocol: Groth16 ballots, admission, tally, TCP trustees, public verifier, oracle
    Step "7. Full protocol runs (inline / batched CPU / CUDA verification)"
    $pn = "8,64"; if ($Large) { $pn = "8,64,256,1024" }
    foreach ($vb in @("inline", "cpu", "cuda:$Device", "auto:$($MinBatch):$Device")) {
        $name = ($vb -replace "[:]", "-")
        Native $wod @("--verify-backend", $vb, "experiment", "--n", $pn, "--modes", "local,dist", "--rtt-ms", "0",
                      "--reps", "$ProtocolReps", "--out", (Join-Path $Out "protocol-$name")) $log
    }
} finally {
    Stop-Job $monJob -ErrorAction SilentlyContinue; Remove-Job $monJob -Force -ErrorAction SilentlyContinue
}

# 8. Summary -------------------------------------------------------------------------
Step "8. Summary"
Native $wod @("gpu-summary", "--dir", $Out) $null
Get-Content (Join-Path $Out "summary.md")
Write-Host "`nResults: $Out" -ForegroundColor Green
Write-Host "Do not publish */private folders (test-only trustee shares, votes, oracle W)." -ForegroundColor Yellow
