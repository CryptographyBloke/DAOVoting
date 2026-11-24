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
    [switch] $SkipTests,
    [switch] $SkipBuild,
    [switch] $ProtocolOnly,
    [string] $PreparedInputs = "", # optional existing, genuine admitted elections; read-only
    [ValidateRange(1, 256)][int] $Threads = 24,
    [switch] $CofactorResearch,
    [ValidateSet('Validate','Msm','Proofs','Codec','Protocol','Engine','All')][string] $ResearchPhase = 'Validate',
    [switch] $TrusteeComparison
)

$ErrorActionPreference = "Stop"
# An explicit Windows PowerShell executable can inherit PowerShell 7's module
# search path from a Python launcher. Load its own hashing/JSON cmdlets.
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    Import-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Utility') -ErrorAction Stop
}
$savedPath = $env:PATH
$savedThreads = $env:RAYON_NUM_THREADS
if (-not ('WodGpuPower' -as [type])) {
    Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class WodGpuPower { [DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint flags); }'
}
# Prevent idle sleep for this thread only; restore even if a command fails.
if ([WodGpuPower]::SetThreadExecutionState([uint32]2147483649) -eq 0) { throw 'cannot inhibit idle sleep' }
try {
Set-Location $PSScriptRoot
$env:RAYON_NUM_THREADS = "$Threads"

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
function RunJson([string]$exe, [string[]]$argv, [string]$path) {
    $prev = $ErrorActionPreference
    $errorLog = Join-Path $Out ('logs/cli-' + [guid]::NewGuid().ToString('N') + '.stderr.log')
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $ErrorActionPreference = "Continue"
        & $exe @argv 2> $errorLog | Set-Content -Encoding UTF8 $path
        $code = $LASTEXITCODE
    } finally { $timer.Stop(); $ErrorActionPreference = $prev }
    if ($null -eq $code -or $code -ne 0) { throw "failed ($code): $exe $($argv -join ' ')" }
    $result = Get-Content $path -Raw | ConvertFrom-Json
    $result | Add-Member -NotePropertyName cli_wall_seconds -NotePropertyValue $timer.Elapsed.TotalSeconds
    return $result
}

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
$prefix = if ($CofactorResearch) { 't008-cofactor' } else { 't005-gpu' }
$Out = Join-Path $PSScriptRoot "results\local\$prefix-$stamp-$rev"
if (Test-Path $Out) { throw "output directory exists: $Out" }
New-Item -ItemType Directory -Force -Path $Out | Out-Null
New-Item -ItemType Directory -Path (Join-Path $Out 'logs') | Out-Null
$log = Join-Path $Out "run.log"

$smi = (nvidia-smi '--query-gpu=name,memory.total,driver_version,compute_cap,pcie.link.gen.max,pcie.link.width.max,power.limit' '--format=csv,noheader') | Select-Object -First 1
if ($LASTEXITCODE -ne 0) { throw 'nvidia-smi discovery failed' }
Write-Host "GPU: $smi"
$cuda = $env:CUDA_PATH
$nvrtc = $null
if ($cuda -and (Test-Path $cuda)) {
    $nvrtc = Get-ChildItem -Path (Join-Path $cuda "bin") -Recurse -Filter "nvrtc64_*.dll" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notlike "*builtins*" -and $_.Name -notlike "*.alt.dll" } | Select-Object -First 1
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
$ac = @(Get-CimInstance -Namespace root/wmi -ClassName BatteryStatus -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PowerOnline)
if ($ac -contains $false) { throw 'Connect AC power before benchmarking' }
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
    ac_power_online = $ac; idle_sleep_inhibited = $true
    cargo_lock_sha256 = (Get-FileHash Cargo.lock -Algorithm SHA256).Hash.ToLowerInvariant()
}
WriteJson $machine (Join-Path $Out "machine.json")
nvidia-smi -q | Set-Content (Join-Path $Out "nvidia-smi-q.txt")
Write-Host "feature: $Feature   NVRTC: $($nvrtc.FullName)"

# 2. Build ---------------------------------------------------------------------
Step "2. Build (CPU-only reference build, then GPU + emulation build)"
Native "cargo" @("fmt", "--check") $log
if (-not $SkipBuild) {
Native "cargo" @("build", "--release", "--locked") $log
$cpuExe = Join-Path $Out "wod-cpu.exe"
Copy-Item "target\release\wod.exe" $cpuExe
Native "cargo" @("build", "--release", "--locked", "--features", "$Feature,cuda-emu") $log
$wod = Join-Path $Out "wod-gpu.exe"
Copy-Item "target\release\wod.exe" $wod
} else {
    $wod = Join-Path $Out "wod-gpu.exe"
    $cpuExe = Join-Path $Out "wod-cpu.exe"
    Copy-Item "target\release\wod.exe" $wod
    Copy-Item "target\release\wod.exe" $cpuExe
}

$machine.gpu_binary_sha256 = (Get-FileHash -LiteralPath $wod -Algorithm SHA256).Hash.ToLowerInvariant()
WriteJson $machine (Join-Path $Out 'machine.json')

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
$check = Get-Content (Join-Path $Out "gpu_check.json") -Raw | ConvertFrom-Json
if (-not $check.nvrtc.ok -or -not $check.device.ok -or $check.device.vector_mismatches -ne 0) {
    throw "GPU compilation or arithmetic validation failed"
}
Native $wod @("gpu-vectors", "--check", "tests\vectors\bjj_mul_v1.json", "--backend", "cuda:$Device") (Join-Path $Out "vectors.log")

# GPU utilization / memory monitor (background, 200 ms)
$mon = Join-Path $Out "gpu_monitor.csv"
$query = '--query-gpu=timestamp,utilization.gpu,utilization.memory,memory.used,clocks.sm,power.draw,temperature.gpu'
# Quote the query as one native argument on Windows PowerShell 5.1, including
# inside the job, and fail before benchmarking if monitoring is unavailable.
$probe = @(nvidia-smi $query '--format=csv')
if ($LASTEXITCODE -ne 0 -or $probe.Count -lt 2) { throw 'GPU telemetry query failed' }
$monJob = Start-Job -ScriptBlock { param($f, $q) nvidia-smi $q '--format=csv' -lms 200 | Out-File -Encoding ascii $f } -ArgumentList $mon, $query
$cpuJob = Start-Job -ScriptBlock {
    param($exe, $file)
    while ($true) {
        Get-Process -Name 'wod-gpu' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe } | ForEach-Object {
            [pscustomobject]@{utc=[DateTimeOffset]::UtcNow.ToString('o');pid=$_.Id;cpu_seconds=$_.CPU;rss_bytes=$_.WorkingSet64}
        } | Export-Csv -NoTypeInformation -Append -Encoding UTF8 $file
        Start-Sleep -Milliseconds 500
    }
} -ArgumentList $wod, (Join-Path $Out 'cpu_monitor.csv')
try {
    if ($CofactorResearch) {
        # This branch deliberately returns through both existing finally blocks.
        # It does not enter or change the historical T005/T006 workflow below.
        function PublicCopy([string]$source, [string]$dest) {
            if (Test-Path -LiteralPath $dest) { throw "refuse replay output collision: $dest" }
            New-Item -ItemType Directory -Path (Join-Path $dest 'public') -Force | Out-Null
            foreach ($f in @('setup.bin','ledger.bin','transcript.bin','claim.json')) {
                Copy-Item -LiteralPath (Join-Path $source "public/$f") -Destination (Join-Path $dest "public/$f")
            }
        }
        function PublicHashes([string]$dir) {
            $hashes = @{}
            Get-ChildItem -LiteralPath (Join-Path $dir 'public') -File | ForEach-Object {
                $hashes[$_.Name] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            return $hashes
        }
        function ResearchFlags($config) {
            return @('--format',$config.format,'--lift-policy',$config.policy,
                '--v2-verify',$config.verify,'--v2-coeff','random','--verify-backend',$config.backend)
        }
        function CheckPublic($v, [int]$n, $decision) {
            if (-not $v.accept -or $v.ballots -ne $n -or $v.gates_verified -ne (17*$n-2) -or $v.decision -ne $decision) {
                throw 'independent public verification rejected'
            }
            foreach ($predicate in @('chain','snapshot','backend','binding','hash','bit','claim')) {
                if (-not $v.$predicate) { throw "acceptance predicate failed: $predicate" }
            }
        }
        function ResearchTally($config, [int]$n, [int]$rep, [string]$mode, [string]$base, $order) {
            $dir = Join-Path $Out "protocol/n$n/rep$rep/$mode-$($config.name)"
            if (Test-Path -LiteralPath $dir) { throw "refuse tally collision: $dir" }
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $dir 'public') | Out-Null
            foreach ($f in @('setup.bin','ledger.bin')) {
                Copy-Item -LiteralPath (Join-Path $base "public/$f") -Destination (Join-Path $dir "public/$f")
            }
            Copy-Item -LiteralPath (Join-Path $base 'private') -Destination (Join-Path $dir 'private') -Recurse
            New-Item -ItemType Directory -Path (Join-Path $dir 'work') | Out-Null
            $flags = ResearchFlags $config
            Write-Host "T008 tally n=$n rep=$rep mode=$mode config=$($config.name)"
            $started = [DateTimeOffset]::UtcNow.ToString('o')
            $tally = RunJson $wod ($flags + @('tally','--dir',$dir,'--mode',$mode,'--threads-per-trustee','4')) (Join-Path $dir 'work/tally.json')
            $copy = Join-Path $dir 'work/individual-cpu'
            PublicCopy $dir $copy
            $cpu = RunJson $wod @('--verify-backend','inline','--v2-verify','individual','verify','--dir',$copy) (Join-Path $dir 'public/cpu-verifier.json')
            CheckPublic $cpu $n $tally.decision
            Native $wod @('oracle','--dir',$dir) (Join-Path $dir 'private/oracle-cli.log') | Out-Host
            $oracle = Get-Content (Join-Path $dir 'private/oracle.json') -Raw | ConvertFrom-Json
            if ($oracle.bit -ne $tally.decision) { throw 'plaintext oracle disagreed after CPU verification' }
            $inputHashes = @{}
            foreach ($f in @('setup.bin','ledger.bin')) {
                $inputHashes[$f] = (Get-FileHash -LiteralPath (Join-Path $base "public/$f") -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            $result = [ordered]@{source_commit=$machine.source_revision;source_dirty=$machine.source_dirty;machine=$machine;
                n=$n;rep=$rep;mode=$mode;config=$config;execution_order=$order;started_utc=$started;completed_utc=[DateTimeOffset]::UtcNow.ToString('o');
                directory=$dir;parameters=@{threshold=$cpu.threshold;trustees=$cpu.trustees;shamir_degree=$cpu.shamir_degree;decryption_threshold=5;injected_rtt_ms=0};
                prepared_input_sha256=$inputHashes;tally=$tally;verification=$cpu;oracle_agrees=$true;public_sha256=(PublicHashes $dir)}
            WriteJson $result (Join-Path $dir 'public/manifest.json')
            return $result
        }
        $researchN = @($TallyN -split ',' | ForEach-Object { [int]$_ } | Where-Object { $_ -le 64 -or $Large })
        if ($researchN.Count -eq 0) { throw 'no electorate sizes selected; use -Large for n>=256' }
        if ($researchN | Where-Object { $_ -notin @(8,64,256,1024) }) { throw 'research supports n=8,64,256,1024' }
        $researchResults = [ordered]@{phase=$ResearchPhase;machine=$machine;parameters=@{n=$researchN;large=[bool]$Large;
            reps=$Reps;public_replay_reps=3;trustee_comparison=[bool]$TrusteeComparison;threads_per_trustee=4}}
        if ($ResearchPhase -in @('Validate','All')) {
            Step 'T008 scalar/MSM/lift vectors and device memory validation'
            foreach ($backend in @("cuda:$Device","cuda-msm:$Device","cert:cuda:$Device")) {
                Native $wod @('msm-vectors','--check','tests/vectors/t007_msm_v1.json','--backend',$backend) (Join-Path $Out 'logs/msm-vectors.log') | Out-Host
                Native $wod @('msm-vectors','--check','tests/vectors/t008_lifts_v1.json','--backend',$backend) (Join-Path $Out 'logs/secure-lift-vectors.log') | Out-Host
            }
            $sanitizer = Join-Path $cuda 'compute-sanitizer/compute-sanitizer.exe'
            if (Test-Path -LiteralPath $sanitizer) {
                Native $sanitizer @('--tool','memcheck','--error-exitcode','99',$wod,'gpu-vectors','--check','tests/vectors/bjj_mul_v1.json','--backend',"cuda:$Device") (Join-Path $Out 'logs/memcheck-scalar.log') | Out-Host
                Native $sanitizer @('--tool','memcheck','--error-exitcode','99',$wod,'msm-vectors','--check','tests/vectors/t007_msm_v1.json','--backend',"cuda-msm:$Device") (Join-Path $Out 'logs/memcheck-msm.log') | Out-Host
                $researchResults.compute_sanitizer = 'PASS'
            } else { $researchResults.compute_sanitizer = 'UNAVAILABLE' }
            $researchResults.vectors = 'PASS'
            $researchResults.cert_msm_scope = 'cert:cuda MSM is trusted CPU Pippenger; real GPU product certification is exercised by V1-certified Protocol runs.'
        }
        if ($ResearchPhase -in @('Msm','All')) {
            Native $wod @('msm-sweep','--sizes','1,4,16,64,256,1024,4096,16384,81920','--backends',"cpu,cuda:$Device,cuda-msm:$Device",'--reps',"$Reps",'--out',(Join-Path $Out 'work/msm')) $log | Out-Host
        }
        if ($ResearchPhase -in @('Proofs','All')) {
            Native $wod @('mixed-proof-sweep','--sizes','1,4,16,64,256,1024,4096,16384','--backends',"cpu,cuda:$Device,cuda-msm:$Device",'--reps',"$Reps",'--out',(Join-Path $Out 'work/proofs')) $log | Out-Host
        }
        if ($ResearchPhase -in @('Codec','All')) {
            Native $wod @('codec-bench','--points','81920','--reps',"$Reps",'--out',(Join-Path $Out 'work/codec')) $log | Out-Host
        }
        if ($ResearchPhase -in @('Engine','All')) {
            foreach ($n in $researchN) {
                $nr = if ($n -le 64) { 3 } else { 1 }
                Native $wod @('secure-bench','--n',"$n",'--reps',"$nr",'--configs','v1-cpu,v3-cpu,v3-gpu-msm,v4-cpu,v4-gpu-msm','--out',(Join-Path $Out "work/engine-n$n")) $log | Out-Host
            }
        }
        if ($ResearchPhase -in @('Protocol','All')) {
            if (-not $PreparedInputs -or -not (Test-Path -LiteralPath $PreparedInputs -PathType Container)) { throw 'Protocol phase requires -PreparedInputs with genuine pre-claim bases' }
            $configs = @(
                [pscustomobject]@{name='v1-cpu';format='v1';policy='randomized';backend='cpu';verify='batch'},
                [pscustomobject]@{name='v2-legacy';format='v2';policy='randomized';backend='cpu';verify='batch'},
                [pscustomobject]@{name='v3-canonical';format='v3';policy='canonical';backend='cpu';verify='batch'},
                [pscustomobject]@{name='v3-randomized';format='v3';policy='randomized';backend='cpu';verify='batch'},
                [pscustomobject]@{name='v4-randomized';format='v4';policy='randomized';backend='cpu';verify='batch'})
            $protocol = @(); $replay = @(); $trustees = @(); $ni = 0
            foreach ($n in $researchN) {
                $bases = @(Get-ChildItem -LiteralPath $PreparedInputs -Recurse -Directory -Filter base | Where-Object { $_.FullName -match "[\\/]n$n[\\/]rep0[\\/]base$" })
                if ($bases.Count -ne 1) { throw "need one unclaimed original base for n=$n" }
                $base = $bases[0].FullName
                foreach ($f in @('transcript.bin','claim.json')) {
                    if (Test-Path -LiteralPath (Join-Path $base "public/$f")) { throw 'PreparedInputs must be a pre-claim base' }
                }
                $order = @(0..4 | ForEach-Object { $configs[($_+$ni)%5] })
                foreach ($config in $order) {
                    $case = ResearchTally $config $n 0 'local' $base @($order.name)
                    $protocol += $case
                    # Canonical A is the producer-overhead reference; its exact
                    # individual CPU replay above is mandatory, without pooling
                    # it into the principal randomized-representation samples.
                    if ($config.name -eq 'v3-canonical') { continue }
                    $policies = if ($config.format -eq 'v1') { @('inline','cpu',"auto:4096:$Device","cert:auto:4096:$Device") }
                        elseif ($config.format -eq 'v2') { @('individual','cpu',"auto:4096:$Device") }
                        elseif ($config.format -eq 'v3') { @('individual','cpu',"auto:4096:$Device","auto-msm:4096:$Device") }
                        else { @('cpu',"auto-msm:4096:$Device") }
                    for ($rep=0; $rep -lt 3; $rep++) {
                        $rotation = @(0..($policies.Count-1) | ForEach-Object { $policies[($_+$rep+$ni)%$policies.Count] })
                        foreach ($spec in $rotation) {
                            $name = $spec -replace ':','-'
                            $dir = Join-Path $Out "replay/n$n/$($config.name)/rep$rep/$name"
                            PublicCopy $case.directory $dir
                            $verification = if ($spec -eq 'individual') { 'individual' } else { 'batch' }
                            $backend = if ($spec -eq 'individual') { 'inline' } else { $spec }
                            Write-Host "T008 replay n=$n rep=$rep format=$($config.name) backend=$spec"
                            $started = [DateTimeOffset]::UtcNow.ToString('o')
                            $v = RunJson $wod @('--v2-verify',$verification,'--v2-coeff','random','--verify-backend',$backend,'verify','--dir',$dir) (Join-Path $dir 'public/replay.json')
                            CheckPublic $v $n $case.tally.decision
                            $row = [ordered]@{source_commit=$machine.source_revision;source_dirty=$machine.source_dirty;machine=$machine;
                                n=$n;rep=$rep;config=$config;backend=$backend;verification_method=$verification;execution_order=$rotation;
                                started_utc=$started;completed_utc=[DateTimeOffset]::UtcNow.ToString('o');
                                fixture_manifest_sha256=(Get-FileHash -LiteralPath (Join-Path $case.directory 'public/manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant();
                                report=$v;oracle_agrees=$true;public_sha256=(PublicHashes $dir)}
                            WriteJson $row (Join-Path $dir 'public/manifest.json'); $replay += $row
                        }
                    }
                }
                if ($TrusteeComparison) {
                    $dist = @($configs[0],
                        [pscustomobject]@{name='v1-cert';format='v1';policy='randomized';backend="cert:auto:4096:$Device";verify='batch'},
                        $configs[3],
                        [pscustomobject]@{name='v3-auto-msm';format='v3';policy='randomized';backend="auto-msm:4096:$Device";verify='batch'},
                        $configs[4],
                        [pscustomobject]@{name='v4-auto-msm';format='v4';policy='randomized';backend="auto-msm:4096:$Device";verify='batch'})
                    $nr = if ($n -le 64) { 3 } else { 1 }
                    for ($rep=0; $rep -lt $nr; $rep++) {
                        $rotation = @(0..($dist.Count-1) | ForEach-Object { $dist[($_+$rep+$ni)%$dist.Count] })
                        foreach ($config in $rotation) { $trustees += ResearchTally $config $n $rep 'dist' $base @($rotation.name) }
                    }
                }
                $ni++
            }
            WriteJson $protocol (Join-Path $Out 'protocol-results.json')
            WriteJson $replay (Join-Path $Out 'public-replay-results.json')
            WriteJson $trustees (Join-Path $Out 'trustee-results.json')
            $researchResults.protocol_runs = $protocol.Count; $researchResults.replay_runs = $replay.Count; $researchResults.trustee_runs = $trustees.Count
        }
        $researchResults.status = 'complete'
        $researchResults.completed_utc = [DateTimeOffset]::UtcNow.ToString('o')
        WriteJson $researchResults (Join-Path $Out 'manifest.json')
        Write-Host "T008 completed: $Out" -ForegroundColor Green
        return
    }
    if (-not $ProtocolOnly) {
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
    } elseif ($MinBatch -le 0) { throw '-ProtocolOnly requires an explicit measured -MinBatch' }

    # 7. Full protocol: Groth16 ballots, admission, tally, TCP trustees, public verifier, oracle
    Step "7. Full protocol runs (inline / batched CPU / CUDA verification)"
    if ($PreparedInputs) {
        if (-not (Test-Path -LiteralPath $PreparedInputs -PathType Container)) { throw 'Prepared inputs not found' }
        $all = @(); $ni = 0
        foreach ($nv in ($TallyN -split ',')) {
            $n = [int]$nv
            $base = @(Get-ChildItem -LiteralPath $PreparedInputs -Recurse -Directory -Filter base |
                Where-Object { $_.FullName -match "[\\/]n$n[\\/]rep0[\\/]base$" })
            if ($base.Count -ne 1) { throw "need exactly one original pre-claim base for n=$n" }
            $inputHashes = @{}
            foreach ($f in @('setup.bin','ledger.bin')) {
                $inputHashes[$f] = (Get-FileHash -LiteralPath (Join-Path $base[0].FullName "public/$f") -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            $repetitions = $ProtocolReps
            if ($n -ge 256) { $repetitions = 1 }
            for ($rep=0; $rep -lt $repetitions; $rep++) {
                foreach ($mode in @('local','dist')) {
                    $policies = @('inline','cpu',"cuda:$Device","auto:$($MinBatch):$Device")
                    $offset = ($rep + $ni + [int]($mode -eq 'dist')) % 4
                    $order = @(0..3 | ForEach-Object { $policies[($_ + $offset) % 4] })
                    foreach ($vb in $order) {
                        $name = $vb -replace ':','-'
                        $dir = Join-Path $Out "protocol/n$n/rep$rep/$mode-$name"
                        if (Test-Path -LiteralPath $dir) { throw 'refusing protocol output collision' }
                        New-Item -ItemType Directory -Path $dir -Force | Out-Null
                        foreach ($category in @('public','private')) {
                            Copy-Item -LiteralPath (Join-Path $base[0].FullName $category) -Destination (Join-Path $dir $category) -Recurse
                        }
                        New-Item -ItemType Directory -Path (Join-Path $dir 'work') | Out-Null
                        Write-Host "n=$n rep=$rep mode=$mode backend=$vb"
                        $tally = RunJson $wod @('--verify-backend',$vb,'tally','--dir',$dir,'--mode',$mode,'--threads-per-trustee','4') (Join-Path $dir 'work/tally.json')
                        $reports = @{}
                        foreach ($verification in @('inline',$vb)) {
                            $label = if ($reports.Count -eq 0) { 'cpu' } else { 'selected' }
                            $copy = Join-Path $dir "work/replay-$label"
                            New-Item -ItemType Directory -Path (Join-Path $copy 'public') -Force | Out-Null
                            foreach ($f in @('setup.bin','ledger.bin','transcript.bin','claim.json')) {
                                Copy-Item -LiteralPath (Join-Path $dir "public/$f") -Destination (Join-Path $copy "public/$f")
                            }
                            $v = RunJson $wod @('--verify-backend',$verification,'verify','--dir',$copy) (Join-Path $dir "public/verify-$label.json")
                            if (-not $v.accept -or $v.ballots -ne $n -or $v.decision -ne $tally.decision) { throw 'public replay rejected' }
                            $reports[$label] = $v
                        }
                        Native $wod @('oracle','--dir',$dir) (Join-Path $dir 'private/oracle-cli.log')
                        $oracle = Get-Content (Join-Path $dir 'private/oracle.json') -Raw | ConvertFrom-Json
                        if ($oracle.bit -ne $tally.decision) { throw 'oracle mismatch' }
                        $hashes = @{}
                        Get-ChildItem (Join-Path $dir 'public') -File | ForEach-Object {
                            $hashes[$_.Name] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                        }
                        $manifest = [ordered]@{source_commit=$machine.source_revision;source_dirty=$machine.source_dirty;machine=$machine;
                            n=$n;rep=$rep;mode=$mode;backend=$vb;execution_order=$order;prepared_input_sha256=$inputHashes;
                            input_origin=(Resolve-Path -LiteralPath $PreparedInputs).Path;completed_utc=[DateTimeOffset]::UtcNow.ToString('o');
                            tally=$tally;verification=$reports;oracle_agrees=$true;public_sha256=$hashes}
                        WriteJson $manifest (Join-Path $dir 'public/manifest.json')
                        $all += $manifest
                    }
                }
            }
            $ni++
        }
        WriteJson $all (Join-Path $Out 'protocol-results.json')
    } else {
    $pn = "8,64"; if ($Large) { $pn = "8,64,256,1024" }
    foreach ($vb in @("inline", "cpu", "cuda:$Device", "auto:$($MinBatch):$Device")) {
        $name = ($vb -replace "[:]", "-")
        Native $wod @("--verify-backend", $vb, "experiment", "--n", $pn, "--modes", "local,dist", "--rtt-ms", "0",
                      "--reps", "$ProtocolReps", "--out", (Join-Path $Out "protocol-$name")) $log
    }
    }
} finally {
    Stop-Job $monJob -ErrorAction SilentlyContinue; Remove-Job $monJob -Force -ErrorAction SilentlyContinue
    Stop-Job $cpuJob -ErrorAction SilentlyContinue; Remove-Job $cpuJob -Force -ErrorAction SilentlyContinue
}

# 8. Summary -------------------------------------------------------------------------
Step "8. Summary"
Native $wod @("gpu-summary", "--dir", $Out) $null
WriteJson ([ordered]@{status='complete';machine=$machine;cargo_lock_sha256=(Get-FileHash Cargo.lock -Algorithm SHA256).Hash.ToLowerInvariant();
    protocol_only=[bool]$ProtocolOnly;prepared_inputs=$PreparedInputs;min_batch=$MinBatch;threads=$Threads}) (Join-Path $Out 'manifest.json')
Get-Content (Join-Path $Out "summary.md")
Write-Host "`nResults: $Out" -ForegroundColor Green
Write-Host "Do not publish */private folders (test-only trustee shares, votes, oracle W)." -ForegroundColor Yellow
} finally {
    [void][WodGpuPower]::SetThreadExecutionState([uint32]2147483648)
    $env:PATH = $savedPath
    $env:RAYON_NUM_THREADS = $savedThreads
}
