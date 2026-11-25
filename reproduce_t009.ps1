# T009 local reproduction (Windows PowerShell; RTX 4050 machine of T006/T008).
# Builds, tests, runs the T009 CPU experiments and the GPU-relevant ones.
# Output: results\local\t009-<timestamp>-<rev>\ (ignored by git; no private
# material is produced by these commands: all inputs are generated in memory).
param(
    [switch] $FinalGpuEvaluation, # T010 paired seven-configuration campaign
    [switch] $SkipBuild,
    [switch] $SkipTests,
    [switch] $Gpu,                # also build with cuda13 and run GPU configurations
    [string] $Engine1024Configs = 'v1-cpu,v1-tate,v3-cpu,v4-cpu,v5-cpu,v6-cpu,v7-cpu,v8-cpu,v9-cpu',
    [int] $Reps = 3
)
$ErrorActionPreference = 'Stop'
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
if ($Gpu) { $env:PATH = "$env:CUDA_PATH\bin\x64;$env:PATH" }
if (-not $env:RAYON_NUM_THREADS) { $env:RAYON_NUM_THREADS = '24' }
$rev = (git rev-parse --short=12 HEAD).Trim()
$dirty = [bool](git status --porcelain)
$out = Join-Path 'results\local' ("t009-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + "-$rev")
if ($FinalGpuEvaluation) { $out = $out -replace "t009-", "t010-" }
if (Test-Path -LiteralPath $out) { throw "Run directory exists: $out" }
New-Item -ItemType Directory -Path $out | Out-Null
$features = if ($Gpu) { @('--features','cuda13,cuda-emu') } else { @() }
if (-not $SkipBuild) {
    cargo fmt --all -- --check; if ($LASTEXITCODE) { throw 'fmt' }
    cargo build --release --locked @features; if ($LASTEXITCODE) { throw 'build' }
}
if (-not $SkipTests) {
    cargo test --release --locked @features; if ($LASTEXITCODE) { throw 'tests' }
}
$wod = '.\target\release\wod.exe'
function Run([string[]] $a) { & $wod @a; if ($LASTEXITCODE) { throw "wod $($a -join ' ')" } }

if ($FinalGpuEvaluation) {
    if (-not $Gpu) { throw 'T010 requires -Gpu' }
    $ac = @(Get-CimInstance -Namespace root/wmi -ClassName BatteryStatus | Select-Object -ExpandProperty PowerOnline)
    if ($ac -contains $false) { throw 'Connect AC power' }
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $os = Get-CimInstance Win32_OperatingSystem
    $machine = @{source_revision=(git rev-parse HEAD).Trim();source_dirty=$dirty;cpu=$cpu.Name;
      physical_cores=$cpu.NumberOfCores;logical_cores=$cpu.NumberOfLogicalProcessors;
      ram_bytes=$os.TotalVisibleMemorySize*1024;os=$os.Caption;os_build=$os.BuildNumber;
      rustc=(rustc -V);cargo=(cargo -V);cuda=(nvcc --version | Out-String);
      gpu=(nvidia-smi -q | Out-String);power=(powercfg /getactivescheme | Out-String);
      ac_power_online=$ac;rayon_threads=$env:RAYON_NUM_THREADS;
      cargo_lock_sha256=(Get-FileHash Cargo.lock -Algorithm SHA256).Hash;
      binary_sha256=(Get-FileHash $wod -Algorithm SHA256).Hash}
    $machine | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $out 'machine.json')
    Run @('gpu-vectors','--check','tests/vectors/bjj_mul_v1.json','--backend','cuda')
    $cfg = 'v1-cpu,v1-tate,v1-gpu,v5-cpu,v6-cpu,v9-cpu,v9-gpu'
    foreach ($n in @(64,256,1024)) {
      Run @('secure-bench','--n',"$n",'--reps',"$Reps",'--configs',$cfg,'--out',"$out/engine-n$n")
    }
    @{status='complete';source_revision=(git rev-parse HEAD).Trim();source_dirty=$dirty;reps=$Reps;
      configurations=$cfg;n=@(64,256,1024);completed_utc=[DateTimeOffset]::UtcNow.ToString('o')} |
      ConvertTo-Json | Set-Content (Join-Path $out 'manifest.json')
    Write-Host "T010 results in $out"
    exit 0
}
Run @('subgroup-bench','--points','4096','--reps','5','--out',"$out\subgroup")
Run @('lin-sweep','--k','1,16,64,256,1024,4096,16384','--reps',"$Reps",'--out',"$out\lin")
Run @('tdec-sweep','--k','1,16,64,256,1024,4096,16384','--trustees','5','--threshold','3','--reps',"$Reps",'--out',"$out\tdec")
$cfg = 'v1-cpu,v1-tate,v3-cpu,v3-individual,v4-cpu,v5-cpu,v5-individual,v6-cpu,v7-cpu,v8-cpu,v9-cpu'
if ($Gpu) { $cfg += ',v1-gpu,v9-gpu,v5-gpu-msm,v6-gpu-msm' ; $Engine1024Configs += ',v1-gpu,v9-gpu' }
Run @('secure-bench','--n','8,64,256','--reps',"$Reps",'--configs',$cfg,'--out',"$out\engine-small")
Run @('secure-bench','--n','1024','--reps','1','--configs',$Engine1024Configs,'--out',"$out\engine-1024")
# full protocol with Groth16 ballots, five TCP trustees, verifier and oracle
foreach ($f in @('v5','v8','v9')) {
    Run @('--format',$f,'experiment','--n','8,64','--modes','local,dist','--reps',"$Reps",'--out',"$out\protocol-$f")
}
if ($Gpu) {
    Run @('--format','v9','--verify-backend','auto:4096:0','experiment','--n','8,64','--modes','local,dist','--reps',"$Reps",'--out',"$out\protocol-v9-gpu")
    Run @('gpu-vectors','--check','tests\vectors\bjj_mul_v1.json','--backend','cuda')
}
@{source_revision=$rev; source_dirty=$dirty; out=$out; gpu=[bool]$Gpu; reps=$Reps;
  completed_utc=[DateTimeOffset]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content (Join-Path $out 'manifest.json')
Write-Host "T009 results in $out"
