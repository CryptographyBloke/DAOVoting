# Build, test and reproduce winner-only weighted voting experiments on Windows.
# Run from any directory with Windows PowerShell 5.1 or PowerShell 7:
#   powershell -ExecutionPolicy Bypass -File .\reproduce.ps1
#   powershell -ExecutionPolicy Bypass -File .\reproduce.ps1 -Reps 5 -RttMs 0,10,50
#   powershell -ExecutionPolicy Bypass -File .\reproduce.ps1 -Large
#   powershell -ExecutionPolicy Bypass -File .\reproduce.ps1 -N 8,64 -Reps 3
#
# -Out is a base directory below results\local. Each invocation creates a new
# timestamp + source-revision directory there and refuses collisions.

param(
    [int[]]  $N          = @(8),
    [ValidateRange(1, 2147483647)][int] $Reps = 3,
    [int[]]  $RttMs       = @(0, 10, 50),
    [ValidateRange(1, 2147483647)][int] $GateReps = 20,
    [ValidateRange(1, 2147483647)][int] $BenchIters = 300,
    [string] $Out         = "results\local",
    [switch] $Large,
    [switch] $SkipTests,
    [switch] $SchedulerComparison,
    [ValidateRange(1, 4096)][int] $SchedulerThreads = 24
)

$ErrorActionPreference = "Stop"
$previousRayonThreads = $env:RAYON_NUM_THREADS
try {
Set-Location $PSScriptRoot
if ($SchedulerComparison) {
    if ($Large) { throw '-SchedulerComparison and -Large are separate experiment profiles' }
    if (-not $PSBoundParameters.ContainsKey('N')) { $N = @(8,64,256,1024) }
    $RttMs = @(0)
    $env:RAYON_NUM_THREADS = "$SchedulerThreads"
}

function Step([string]$Message) {
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    $encoding = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $Text, $encoding)
}

function Run([string]$Exe, [string[]]$Argv, [string]$LogPath) {
    $oldErrorActionPreference = $ErrorActionPreference
    $nativePreference = Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue
    $ErrorActionPreference = "Continue"
    if ($null -ne $nativePreference) {
        $PSNativeCommandUseErrorActionPreference = $false
    }
    try {
        & $Exe @Argv 2>&1 | Tee-Object -FilePath $LogPath
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $oldErrorActionPreference
        if ($null -ne $nativePreference) {
            $PSNativeCommandUseErrorActionPreference = $nativePreference.Value
        }
    }
    if ($null -eq $code -or $code -ne 0) {
        throw "command failed ($code): $Exe $($Argv -join ' ') (see $LogPath)"
    }
}

if ($N.Count -eq 0) { throw "-N must contain at least one voter count" }
foreach ($voterCount in $N) {
    if ($voterCount -lt 2 -or (($voterCount -band ($voterCount - 1)) -ne 0)) {
        throw "each -N value must be a power of two >= 2: $voterCount"
    }
}
if ($RttMs.Count -eq 0 -or @($RttMs | Where-Object { $_ -lt 0 }).Count -gt 0) {
    throw "-RttMs must contain nonnegative values"
}

foreach ($tool in "cargo", "rustc", "git") {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool not found on PATH. Install Rust (MSVC) and Git, then reopen PowerShell."
    }
}

$sourceCommit = (git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or -not $sourceCommit) {
    throw "could not identify the source Git commit"
}
$dirtyPaths = @(git status --porcelain --untracked-files=all)
if ($LASTEXITCODE -ne 0) { throw "could not read Git working-tree status" }
$sourceDirty = $dirtyPaths.Count -gt 0

$localRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "results\local"))
$outRoot = [System.IO.Path]::GetFullPath($Out)
$localPrefix = $localRoot.TrimEnd('\') + '\'
$underLocal = $outRoot.Equals($localRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
    $outRoot.StartsWith($localPrefix, [System.StringComparison]::OrdinalIgnoreCase)
if (-not $underLocal) {
    throw "-Out must be results\local or a directory beneath it; resolved path: $outRoot"
}
New-Item -ItemType Directory -Force -Path $outRoot | Out-Null

$runStamp = [DateTimeOffset]::Now.ToString("yyyyMMdd-HHmmss-fff")
$baseRunId = "$runStamp-$($sourceCommit.Substring(0, 8))"
$runId = $baseRunId
$suffix = 0
while (Test-Path -LiteralPath (Join-Path $outRoot $runId)) {
    $suffix++
    $runId = "$baseRunId-$('{0:D2}' -f $suffix)"
}
$Out = Join-Path $outRoot $runId
New-Item -ItemType Directory -Path $Out | Out-Null
$logs = Join-Path $Out "logs"
New-Item -ItemType Directory -Path $logs | Out-Null
$runStartedUtc = [DateTimeOffset]::UtcNow.ToString("o")

$rustc = (& rustc -V).Trim()
if ($LASTEXITCODE -ne 0) { throw "rustc -V failed" }
$cargo = (& cargo -V).Trim()
if ($LASTEXITCODE -ne 0) { throw "cargo -V failed" }
$ver = [version](($rustc -split ' ')[1] -replace '-.*', '')
if ($ver -lt [version]"1.85.0") {
    throw "Rust >= 1.85 required (edition 2024); run 'rustup update stable'."
}
$wod = Join-Path $PSScriptRoot "target\release\wod.exe"
$lockPath = Join-Path $PSScriptRoot "Cargo.lock"
$lockHash = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()

$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$os = Get-CimInstance Win32_OperatingSystem
$machine = [ordered]@{
    cpu = $cpu.Name.Trim()
    physical_cores = $cpu.NumberOfCores
    logical_processors = $cpu.NumberOfLogicalProcessors
    max_clock_mhz = $cpu.MaxClockSpeed
    os = "$($os.Caption) $($os.Version) build $($os.BuildNumber)"
    memory_gb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    rustc = $rustc
    cargo = $cargo
    powershell = $PSVersionTable.PSVersion.ToString()
    rayon_threads_environment = $env:RAYON_NUM_THREADS
    active_power_scheme = ((& powercfg /getactivescheme) -join ' ')
}
$machineJsonPath = Join-Path $Out "machine.json"
Write-Utf8NoBom $machineJsonPath ($machine | ConvertTo-Json -Depth 8)

# 1-2. Toolchain and release build --------------------------------------------
Step "1. Rust toolchain"
Write-Host "$rustc`n$cargo"
Step "2. Release build"
$timer = [System.Diagnostics.Stopwatch]::StartNew()
Run "cargo" @("build", "--release", "--locked") (Join-Path $logs "build.log")
$timer.Stop()
$buildSeconds = $timer.Elapsed.TotalSeconds
Write-Host ("build: {0:N1} s" -f $buildSeconds)

# 3. Correctness tests ---------------------------------------------------------
$testsSeconds = $null
$testsStatus = "SKIPPED"
if (-not $SkipTests) {
    Step "3. Cryptographic correctness and integration tests"
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    Run "cargo" @("test", "--release", "--locked") (Join-Path $logs "tests.log")
    $timer.Stop()
    $testsSeconds = $timer.Elapsed.TotalSeconds
    $testsStatus = "PASS"
}

# 4. Single conditional gate and operation benchmarks -------------------------
if ($SchedulerComparison) { Step "4. Controlled scheduler profile (microbenchmarks excluded)" }
else { Step "4. Single CGY conditional gate ($GateReps reps) and operation benchmarks" }
if (-not $SchedulerComparison) {
Run $wod @("gate", "--reps", "$GateReps", "--out", $Out) (Join-Path $logs "gate.log")
Run $wod @("bench", "--iters", "$BenchIters", "--groth-iters", "5", "--out", $Out) (Join-Path $logs "bench.log")
}

# 5. Full elections: local and five trustee processes at configured RTTs -------
$rtt = ($RttMs -join ",")
$runs = @(@{ n = ($N -join ","); reps = $Reps; rtt = $rtt })
if ($Large) {
    $runs += @{ n = "64"; reps = 3; rtt = "0" }
    $runs += @{ n = "256,1024"; reps = 1; rtt = "0" }
}
if ($SchedulerComparison) {
    $runs = @($N | ForEach-Object { @{ n = "$_"; reps = $(if ($_ -eq 1024) { 1 } else { $Reps }); rtt = "0" } })
}
$runIndex = 0
$orderOffset = 0
foreach ($experiment in $runs) {
    $runIndex++
    if ($SchedulerComparison) { Step "5. Paired local schedulers n=$($experiment.n) reps=$($experiment.reps), alternating order" }
    else { Step "5. Experiment n=$($experiment.n) reps=$($experiment.reps) (co-located + 5 trustee processes, RTT $($experiment.rtt) ms)" }
    $dir = Join-Path $Out "exp$runIndex"
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    if ($SchedulerComparison) {
        Run $wod @("experiment", "--n", $experiment.n, "--modes", "local", "--scheduler", "both", "--order-offset", "$orderOffset", "--machine-json", $machineJsonPath, "--reps", "$($experiment.reps)", "--out", $dir) (Join-Path $logs "experiment-$runIndex.log")
        $orderOffset += $experiment.reps
    } else {
        Run $wod @("experiment", "--n", $experiment.n, "--modes", "local,dist", "--rtt-ms", $experiment.rtt, "--reps", "$($experiment.reps)", "--out", $dir) (Join-Path $logs "experiment-$runIndex.log")
    }
    $timer.Stop()
    $wall = [ordered]@{ seconds_end_to_end = $timer.Elapsed.TotalSeconds }
    Write-Utf8NoBom (Join-Path $dir "wall.json") ($wall | ConvertTo-Json -Depth 4)
    Write-Host ("experiment wall time: {0:N1} s" -f $timer.Elapsed.TotalSeconds)
}

# 6-7. Read the separate verifier-process and oracle results ------------------
# `wod experiment` has already launched the verifier as a separate process and
# run the plaintext oracle after it. Do not rerun either stage here: doing so
# would rewrite public/verify.json after its public manifest was hashed.
Step "6. Independent public verification and 7. plaintext oracle results"
$firstN = $N | Select-Object -First 1
$firstRtt = $RttMs | Select-Object -First 1
$runDir = Join-Path $Out "exp1\n$firstN\rep0\dist-rtt$firstRtt"
if ($SchedulerComparison) { $runDir = Join-Path $Out "exp1\n$firstN\rep0\local-reference" }
$claim = Get-Content (Join-Path $runDir "public\claim.json") -Raw | ConvertFrom-Json
$standalone = Get-Content (Join-Path $runDir "public\verify.json") -Raw | ConvertFrom-Json
$firstManifest = Get-Content (Join-Path $runDir "public\manifest.json") -Raw | ConvertFrom-Json
if (-not $standalone.accept -or -not $firstManifest.oracle_agrees) {
    throw "standalone verification or plaintext-oracle comparison failed"
}
Write-Host "published decision bit: $($claim.decision)"

# 8. Summaries, public-artifact audit, hashes and authoritative manifest -------
Step "8. Collecting results"
$summaries = @(Get-ChildItem -Path $Out -Recurse -Filter summary.json | ForEach-Object {
    Get-Content $_.FullName -Raw | ConvertFrom-Json
})
$results = [ordered]@{
    source_commit = $sourceCommit
    source_dirty = $sourceDirty
    machine = $machine
    cargo_lock_sha256 = $lockHash
    gate = if ($SchedulerComparison) { $null } else { (Get-Content (Join-Path $Out "gate.json") -Raw | ConvertFrom-Json) }
    bench = if ($SchedulerComparison) { $null } else { (Get-Content (Join-Path $Out "bench.json") -Raw | ConvertFrom-Json).bench }
    experiments = $summaries
    standalone_verification = $standalone
    plaintext_oracle_agrees = $firstManifest.oracle_agrees
}
$resultsJson = $results | ConvertTo-Json -Depth 20
Write-Utf8NoBom (Join-Path $Out "results.json") $resultsJson

$md = @(
    "# Local experiment summary",
    "",
    "Run: ``$runId``",
    "Source: ``$sourceCommit`` (working tree $(if ($sourceDirty) { 'dirty' } else { 'clean' }))",
    "Machine: $($machine.cpu), $($machine.logical_processors) logical processors, $($machine.os), $rustc",
    "Cargo.lock SHA-256: ``$lockHash``",
    "Standalone public verification: PASS",
    "Plaintext oracle decision agreement: PASS (plaintext total remains under ``private/``)",
    ""
)
Get-ChildItem -Path $Out -Recurse -Filter summary.md | ForEach-Object {
    $md += Get-Content $_.FullName
    $md += ""
}
$md += "Run directory: ``$Out``"
Write-Utf8NoBom (Join-Path $Out "summary.md") ($md -join [Environment]::NewLine)

$publicFiles = @(Get-ChildItem -Path $Out -Recurse -File | Where-Object {
    $_.FullName -match '[\\/]public[\\/]'
} | Sort-Object FullName)
$secretNamePattern = '(^|[\\/])public[\\/](trustee_[^\\/]+\.bin|voters\.bin|oracle\.json|ballot_pk\.bin)$'
foreach ($file in $publicFiles) {
    $relative = $file.FullName.Substring($Out.Length).TrimStart('\', '/')
    if ($relative -match $secretNamePattern) {
        throw "sensitive filename found in public evidence: $relative"
    }
}
$publicHashes = @($publicFiles | ForEach-Object {
    [ordered]@{
        path = $_.FullName.Substring($Out.Length).TrimStart('\', '/')
        bytes = $_.Length
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
})

$verificationChecks = @(
    Get-ChildItem -Path $Out -Recurse -File -Filter manifest.json | Where-Object {
        $_.Directory.Name -eq "public"
    } | ForEach-Object {
        $m = Get-Content $_.FullName -Raw | ConvertFrom-Json
        [ordered]@{
            path = $_.FullName.Substring($Out.Length).TrimStart('\', '/')
            accepted = [bool]$m.verification.accept
            oracle_agrees = [bool]$m.oracle_agrees
        }
    }
)
if ($verificationChecks.Count -eq 0 -or @($verificationChecks | Where-Object { -not $_.accepted -or -not $_.oracle_agrees }).Count -gt 0) {
    throw "one or more experiment manifests lack independent verification or oracle agreement"
}

$manifest = [ordered]@{
    schema_version = 1
    status = "complete"
    run_id = $runId
    started_at_utc = $runStartedUtc
    completed_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
    source_commit = $sourceCommit
    source_dirty = $sourceDirty
    source_dirty_paths = $dirtyPaths
    machine = $machine
    cargo_lock_sha256 = $lockHash
    powershell = $PSVersionTable.PSVersion.ToString()
    parameters = [ordered]@{
        n = $N
        repetitions = $Reps
        rtt_ms = $RttMs
        gate_repetitions = $(if ($SchedulerComparison) { 0 } else { $GateReps })
        benchmark_iterations = $(if ($SchedulerComparison) { 0 } else { $BenchIters })
        large = [bool]$Large
        tests = $testsStatus
        scheduler_comparison = [bool]$SchedulerComparison
        scheduler_threads = $(if ($SchedulerComparison) { $SchedulerThreads } else { $null })
        profiles = $runs
    }
    timings_seconds = [ordered]@{
        release_build = $buildSeconds
        tests = $testsSeconds
        experiment_batches = @($runs.Count)
    }
    verification = $verificationChecks
    standalone_verification = [bool]$standalone.accept
    plaintext_oracle_agrees = [bool]$firstManifest.oracle_agrees
    public_artifacts = $publicHashes
    generated_paths = [ordered]@{
        summary = "summary.md"
        results = "results.json"
        logs = "logs/"
        experiments = "exp*/"
    }
}
Write-Utf8NoBom (Join-Path $Out "manifest.json") ($manifest | ConvertTo-Json -Depth 20)

Get-Content (Join-Path $Out "summary.md")
Write-Host "`nResults: $Out\manifest.json, $Out\results.json and $Out\summary.md" -ForegroundColor Green
Write-Host "Each experiment contains public\, private\ and work\ data. Never publish private\; inspect work\ before sharing." -ForegroundColor Yellow
} finally {
    $env:RAYON_NUM_THREADS = $previousRayonThreads
}
