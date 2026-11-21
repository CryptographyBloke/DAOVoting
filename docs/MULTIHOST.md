# Trustee deployment on separate hosts

Use six independent Linux VMs: one public Board coordinator and five Trustees.
An independent Windows controller provisions the test election and runs the
public verifier. The measured topology uses Azure Standard_B2s_v2 VMs (2 vCPU,
8 GiB RAM), Ubuntu 24.04, with Board and two Trustees in Japan East and three
Trustees in Korea Central. B-series CPU credits can affect sustained performance.
These are separate VMs; distinct physical servers or independent operators are
not established. Provisioning uses one administrator and a test-only dealer.

## Hosts and private networking

Create six Ubuntu x64 VMs with SSH public-key authentication, at least 2 vCPU,
8 GiB RAM and 20 GiB free disk. Six VMs provide separate guest kernels and filesystems;
five containers on one host do not reproduce this topology. Put them on a protected
private network; peer nonoverlapping VNets if using multiple Azure regions.
Allow SSH only from the controller's egress address. On the Board, allow TCP 9000
only from the five Trustee private addresses, and deny other access to that port.
Never expose private shares through command-line arguments or public storage.

Use SSH aliases `board`, `trustee0`, ..., `trustee4` in the controller's SSH config.
Each alias needs HostName, User, IdentityFile and StrictHostKeyChecking yes.
Verify host-key fingerprints using the cloud console before connecting. Keep all
SSH private keys on the controller, with Windows ACLs restricted to the owner.
Do not copy administrator keys between VMs. The SSH aliases and private Board
address below are deployment configuration, not values to copy from an old run.

Build the pinned revision on a Linux build machine (the Board may be used):

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev git curl time python3 iputils-ping
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.98.1
. "$HOME/.cargo/env"
git clone https://github.com/CryptographyBloke/DAOVoting.git voting-code
cd voting-code
git checkout <full-source-revision>
CARGO_BUILD_JOBS=2 cargo build --release --locked
sha256sum target/release/wod Cargo.lock
```

Install `time`, `python3` and `iputils-ping` on all Trustees. Copy this same Linux
binary via the controller to `~/voting/bin/wod` on every VM, set it executable,
and compare its SHA-256 on all six hosts. Record `uname -a`, `lscpu`,
`head -1 /proc/meminfo`, guest VM IDs and the build toolchain. The Board needs no
secret material to build public source.

## Fresh poll and isolated provisioning (Windows PowerShell)

Run in a clean committed clone after the release tests pass. Set your private
Board address; every batch and remote directory must be new.

```powershell
$ErrorActionPreference = 'Stop'
$rev = (git rev-parse HEAD).Trim()
$runId = "$(Get-Date -Format 'yyyyMMdd-HHmmss')-$($rev.Substring(0,8))-multihost"
$batch = Join-Path $PWD "results/local/$runId"
$n = 8  # repeat with 64, 256 and 1024; record repetitions independently
$poll = 930080
$boardPrivate = '10.0.0.4'  # replace with your actual private Board address
$dealer = Join-Path $batch 'private/dealer'
$wod = Join-Path $PWD 'target/release/wod.exe'
& $wod setup --dir $dealer --n $n --poll $poll
if ($LASTEXITCODE -ne 0) { throw 'setup failed' }
& $wod vote --dir $dealer
if ($LASTEXITCODE -ne 0) { throw 'proving failed' }
& $wod admit --dir $dealer
if ($LASTEXITCODE -ne 0) { throw 'admission failed' }
$nodes = @('board','trustee0','trustee1','trustee2','trustee3','trustee4')
for ($i=0; $i -lt $nodes.Count; $i++) {
    $bundle = Join-Path $batch "work/$($nodes[$i])"
    $extra = @(); if ($i -gt 0) { $extra = @('--id',($i-1).ToString()) }
    & $wod export-node --dir $dealer --out $bundle @extra
    if ($LASTEXITCODE -ne 0) { throw 'node export failed' }
    $privateFiles = @(Get-ChildItem (Join-Path $bundle 'private') -File)
    $expected = 0; if ($i -gt 0) { $expected = 1 }
    if ($privateFiles.Count -ne $expected) { throw 'secret isolation failed' }
    $remote = "voting/runs/$runId"
    ssh $nodes[$i] "umask 077; test ! -e '$remote' && mkdir -p '$remote/logs'"
    if ($LASTEXITCODE -ne 0) { throw 'remote output exists or SSH failed' }
    scp -r "$bundle/." "$($nodes[$i]):$remote/"
    if ($LASTEXITCODE -ne 0) { throw 'copy failed' }
    ssh $nodes[$i] "chmod 700 '$remote/private'; find '$remote/private' -type f -exec chmod 600 {} +; sha256sum '$remote/public/'*; find '$remote/private' -type f -printf '%f %m\n'"
    if ($LASTEXITCODE -ne 0) { throw 'permission/hash check failed' }
}
```

Compare the public `setup.bin` and pre-claim `ledger.bin` hashes on all nodes
against the controller's copies. Trustee i must have only `private/trustee_i.bin`;
Board must have zero private files. No node receives voters, oracle data or the
Groth16 proving key. The dealer retains all test shares on the controller, so
this experiment establishes per-VM file isolation, not a production DKG ceremony.

## Execute, collect and independently verify

On each Trustee, record `ping -n -c 20 -i 0.1 BOARD_PRIVATE` immediately before
the run. Set `RAYON_NUM_THREADS=2`. On the Board run:

```sh
umask 077
/usr/bin/time -v -o logs/time.txt ~/voting/bin/wod board --dir . --addr BOARD_PRIVATE:9000 --rtt-ms 0 >logs/stats.json 2>logs/stderr.txt
code=$?; printf '%s\n' "$code" >logs/exit.code
```

On each of the five Trustees, from its own fresh run directory, use its own ID:

```sh
umask 077
export RAYON_NUM_THREADS=2
/usr/bin/time -v -o logs/time.txt ~/voting/bin/wod trustee --dir . --id TRUSTEE_ID --addr BOARD_PRIVATE:9000 --rtt-ms 0 >logs/stats.json 2>logs/stderr.txt
code=$?; printf '%s\n' "$code" >logs/exit.code
```

For background execution, upload a short shell file containing those commands
and run `nohup sh start.sh </dev/null >logs/launcher.txt 2>&1 &` after changing
directory. Redirect the entire background job and check all six exit codes;
abort the experiment on nonzero exit or timeout. Never infer success from a log
file's existence. Fetch each host's `logs/`, and only the Board's `public/`, using
SCP. Put the latter in a fresh `work/public-verifier/public/` directory on the
controller, with no `private/` directory. Run:

```powershell
& $wod verify --dir (Join-Path $batch 'work/public-verifier')
if ($LASTEXITCODE -ne 0) { throw 'public replay rejected' }
& $wod oracle --dir $dealer  # only after verification; W remains private
if ($LASTEXITCODE -ne 0) { throw 'oracle failed' }
```

Require verifier `accept`, Board decision and private oracle decision to agree.
Record the agreement Boolean only in public results. Preserve all original stats,
exit codes, RTT logs, machine metadata and SHA-256 hashes in an authoritative
manifest. Do not overwrite manifests when repeating public verification; use a
fresh verifier directory. Repeat fresh setup and ballots for each repetition.

Board `seconds_total` spans START to all Trustee statistics, excluding connection
setup. `seconds_gates` ends at the last gate; `seconds_release` covers final release.
Trustee production, verification and waiting are separate fields. GNU time includes
loading and connection and supplies whole-process peak RSS. Signed message counts,
transcript bytes and application bytes exclude IP/TCP/SSH overhead. Proving and
public verification run separately on the Windows controller; compare different
machine configurations only with explicit labels. Artificial RTT must remain zero.

For failures, disconnect a connected Trustee, alter one signed POST, mismatch one
public setup, or request a different index with a host's own key. Require rejection
and no accepted claim; do not transfer another trustee's secret merely to test a
wrong index. Five-of-five participation has no liveness or fairness guarantee.
After collecting and hashing evidence, deallocate experimental cloud VMs to stop
compute billing; disks and public IPs can still incur charges.
