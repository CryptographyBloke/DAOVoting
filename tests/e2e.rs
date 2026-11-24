//! End-to-end integration test (n = 8): setup, Groth16 ballots, admission,
//! co-located tally and five trustee processes over TCP, independent
//! verification in a separate process, oracle comparison, and rejection of
//! tampered public artifacts.

use std::path::{Path, PathBuf};
use std::process::Command;

fn wod() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wod"))
}

fn json(p: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let t = dst.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &t)
        } else {
            std::fs::copy(e.path(), &t).unwrap();
        }
    }
}

#[test]
fn paired_scheduler_public_replay_and_claim_rejection() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("paired-schedulers");
    if out.exists() {
        std::fs::remove_dir_all(&out).unwrap();
    }
    let output = wod()
        .args([
            "experiment",
            "--n",
            "8",
            "--modes",
            "local",
            "--scheduler",
            "both",
            "--reps",
            "2",
            "--out",
        ])
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = json(&out.join("n8/results.json"));
    let runs = result["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 4);
    assert_eq!(runs[0]["scheduler"], "reference");
    assert_eq!(runs[2]["scheduler"], "dataflow");
    for pair in runs.chunks(2) {
        assert_eq!(pair[0]["paired_input_files"], pair[1]["paired_input_files"]);
        assert_eq!(pair[0]["params"], pair[1]["params"]);
        assert_eq!(pair[0]["decision"], pair[1]["decision"]);
        assert_eq!(pair[0]["tally"]["items"], pair[1]["tally"]["items"]);
    }
    for (i, run) in runs.iter().enumerate() {
        assert_eq!(run["verification"]["accept"], true);
        assert_eq!(run["oracle_agrees"], true);
        assert_eq!(run["verification"]["gates_verified"], 134);
        let source = out.join(format!(
            "n8/rep{}/{}",
            run["rep"],
            run["variant"].as_str().unwrap()
        ));
        for mutation in ["none", "claim", "transcript"] {
            let bad = mutation != "none";
            let dir = out.join(format!("public-replay-{i}-{mutation}"));
            std::fs::create_dir_all(dir.join("public")).unwrap();
            for file in ["setup.bin", "ledger.bin", "transcript.bin"] {
                std::fs::copy(
                    source.join("public").join(file),
                    dir.join("public").join(file),
                )
                .unwrap();
            }
            if mutation == "claim" {
                let path = dir.join("public/ledger.bin");
                let mut events: Vec<wod::ledger::Event> = wod::setup::read_bin(&path).unwrap();
                for event in &mut events {
                    if let wod::ledger::Event::Claim { bit, .. } = event {
                        *bit = !*bit;
                    }
                }
                wod::setup::write_bin(&path, &events).unwrap();
            }
            if mutation == "transcript" {
                let path = dir.join("public/transcript.bin");
                let mut bytes = std::fs::read(&path).unwrap();
                let index = bytes.len() / 2;
                bytes[index] ^= 1;
                std::fs::write(path, bytes).unwrap();
            }
            let result = wod().args(["verify", "--dir"]).arg(&dir).output().unwrap();
            assert_eq!(result.status.success(), !bad);
            assert!(!dir.join("private").exists());
        }
    }
}

#[test]
fn eight_voter_election_local_and_distributed() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("e2e");
    let _ = std::fs::remove_dir_all(&out);
    let st = wod()
        .args([
            "experiment",
            "--n",
            "8",
            "--modes",
            "local,dist",
            "--rtt-ms",
            "0",
            "--reps",
            "1",
            "--out",
        ])
        .arg(&out)
        .status()
        .unwrap();
    assert!(st.success());
    let s = json(&out.join("summary.json"));
    let rows = s["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for r in rows {
        assert_eq!(r["circuit"]["gates"], 134);
        assert_eq!(r["all_accepted"], true);
        assert_eq!(r["all_oracle_agree"], true);
    }
    let saved_manifest_path = out.join("n8/rep0/local/public/manifest.json");
    let saved_manifest = std::fs::read(&saved_manifest_path).unwrap();
    let repeated = wod()
        .args([
            "experiment",
            "--n",
            "8",
            "--modes",
            "local,dist",
            "--rtt-ms",
            "0",
            "--reps",
            "1",
            "--out",
        ])
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        !repeated.status.success(),
        "existing experiment path was reused"
    );
    assert_eq!(
        std::fs::read(saved_manifest_path).unwrap(),
        saved_manifest,
        "refusing a repeated run must preserve the original result"
    );

    // private material never lands in public/
    let pubdir = out.join("n8/rep0/dist-rtt0/public");
    for e in std::fs::read_dir(&pubdir).unwrap() {
        let n = e.unwrap().file_name().to_string_lossy().to_string();
        assert!(
            !n.contains("trustee_") && !n.contains("voters") && !n.contains("oracle"),
            "{n}"
        );
    }

    // tampering with the transcript or the ledger must be rejected
    let good = out.join("n8/rep0/local");
    for (file, at) in [("transcript.bin", 0.6), ("ledger.bin", 0.3)] {
        let bad = out.join(format!("tamper-{file}"));
        copy_dir(&good, &bad);
        let p = bad.join("public").join(file);
        let mut b = std::fs::read(&p).unwrap();
        let i = (b.len() as f64 * at) as usize;
        b[i] ^= 0x01;
        std::fs::write(&p, b).unwrap();
        let st = wod().args(["verify", "--dir"]).arg(&bad).output().unwrap();
        assert!(!st.status.success(), "tampered {file} accepted");
        assert_eq!(json(&p.with_file_name("verify.json"))["accept"], false);
    }

    // Explicit provisioning allowlists: a board has no secrets; each trustee
    // gets precisely its own key, with no voters, oracle or proving files.
    let board_dir = out.join("isolated-board");
    assert!(
        wod()
            .args(["export-node", "--dir"])
            .arg(&good)
            .arg("--out")
            .arg(&board_dir)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(
        std::fs::read_dir(board_dir.join("private"))
            .unwrap()
            .count(),
        0
    );
    for id in 0..5 {
        let node = out.join(format!("isolated-trustee-{id}"));
        assert!(
            wod()
                .args(["export-node", "--dir"])
                .arg(&good)
                .arg("--out")
                .arg(&node)
                .args(["--id", &id.to_string()])
                .output()
                .unwrap()
                .status
                .success()
        );
        assert_eq!(std::fs::read_dir(node.join("private")).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(node.join("work")).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(node.join("public")).unwrap().count(), 2);
    }
    // Compare both endpoints of real TCP connections. Internal EOF channel
    // notifications must never add bytes to the public communication metric.
    let count_dir = out.join("byte-count-board");
    assert!(
        wod()
            .args(["export-node", "--dir"])
            .arg(&good)
            .arg("--out")
            .arg(&count_dir)
            .output()
            .unwrap()
            .status
            .success()
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let count_addr = listener.local_addr().unwrap().to_string();
    let mut counters = Vec::new();
    for id in 0..5 {
        counters.push(
            wod()
                .args(["trustee", "--dir"])
                .arg(out.join(format!("isolated-trustee-{id}")))
                .args(["--id", &id.to_string(), "--addr", &count_addr])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
    }
    let counts = wod::net::run_board(&wod::setup::Paths::new(count_dir), listener, 0).unwrap();
    for (id, child) in counters.into_iter().enumerate() {
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let peer: wod::net::TrusteeStats = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            counts.trustees[id].bytes_sent, peer.bytes_sent,
            "board byte accounting differs from the actual trustee writer"
        );
    }
    let bad_node = out.join("isolated-trustee-0");
    std::fs::copy(
        good.join("private/trustee_1.bin"),
        bad_node.join("private/trustee_0.bin"),
    )
    .unwrap();
    let wrong_key = wod()
        .args(["trustee", "--dir"])
        .arg(&bad_node)
        .args(["--id", "0", "--addr", "127.0.0.1:1"])
        .output()
        .unwrap();
    assert!(!wrong_key.status.success());
    assert!(String::from_utf8_lossy(&wrong_key.stderr).contains("key file belongs"));

    // Once five valid peers have authenticated, losing one must abort, rather
    // than leave the board waiting forever on its retained channel sender.
    use ed25519_dalek::Signer;
    use std::io::{Read, Write};
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let mut child = wod()
        .args(["board", "--dir"])
        .arg(&board_dir)
        .args(["--addr", &addr.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let context = wod::net::Session::load(&wod::setup::Paths::new(&good), false)
        .unwrap()
        .ctx;
    let mut sockets = Vec::new();
    for id in 0..5 {
        let start = Instant::now();
        let mut socket = loop {
            if let Ok(socket) = std::net::TcpStream::connect(addr) {
                break socket;
            }
            assert!(start.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(20));
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut frame = [0u8; 37];
        socket.read_exact(&mut frame).unwrap();
        assert_eq!(&frame[..5], &[0, 0, 0, 33, 0]);
        let key: wod::setup::TrusteeKey =
            wod::setup::read_bin(&good.join(format!("private/trustee_{id}.bin"))).unwrap();
        let digest = wod::group::sha256(&[b"wod/hello/v1", &context, &frame[5..], &[id as u8]]);
        let signature = ed25519_dalek::SigningKey::from_bytes(&key.signing).sign(&digest);
        socket.write_all(&[0, 0, 0, 66, 10, id as u8]).unwrap();
        socket.write_all(&signature.to_bytes()).unwrap();
        sockets.push(socket);
    }
    let mut start_frame = [0u8; 5];
    sockets[0].read_exact(&mut start_frame).unwrap();
    assert_eq!(start_frame, [0, 0, 0, 1, 1]);
    drop(sockets.remove(2));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("board failed to abort after a trustee disconnected");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// T005: the full protocol with message-level batched verification (CPU
/// backend, and the CUDA kernel source compiled for the host when the
/// `cuda-emu` feature is enabled) in the co-located tally, the five TCP
/// trustee processes and the separate public verifier; every run must be
/// accepted and agree with the oracle, and record its backend.
#[test]
fn batched_verification_backends_end_to_end() {
    let mut specs = vec!["cpu"];
    if cfg!(feature = "cuda-emu") {
        specs.push("emu");
    }
    for spec in specs {
        let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("batched-{spec}"));
        if out.exists() {
            std::fs::remove_dir_all(&out).unwrap();
        }
        let output = wod()
            .args([
                "--verify-backend",
                spec,
                "experiment",
                "--n",
                "8",
                "--modes",
                "local,dist",
                "--reps",
                "1",
                "--out",
            ])
            .arg(&out)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result = json(&out.join("n8/results.json"));
        let runs = result["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 2);
        for r in runs {
            assert_eq!(r["verification"]["accept"], true);
            assert_eq!(r["oracle_agrees"], true);
            let vb = r["verification"]["verify_backend"].as_str().unwrap();
            assert!(vb.starts_with(spec), "{vb}");
            assert!(r["verification"]["engine_prof"]["jobs"].as_u64().unwrap() > 1000);
        }
        let dist = runs.iter().find(|r| r["mode"] == "dist").unwrap();
        for t in dist["tally"]["board"]["trustees"].as_array().unwrap() {
            assert!(t["verify_backend"].as_str().unwrap().starts_with(spec));
        }
        let cli_dir = out.join("dist-json");
        copy_dir(&out.join("n8/rep0/base"), &cli_dir);
        let cli = wod()
            .args(["--verify-backend", spec, "tally", "--mode", "dist", "--dir"])
            .arg(&cli_dir)
            .output()
            .unwrap();
        assert!(
            cli.status.success(),
            "{}",
            String::from_utf8_lossy(&cli.stderr)
        );
        let stats: serde_json::Value = serde_json::from_slice(&cli.stdout).unwrap();
        assert_eq!(stats["mode"], "dist");
        assert_eq!(stats["decision"], runs[0]["decision"]);
        assert!(
            wod()
                .args(["verify", "--dir"])
                .arg(&cli_dir)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
}

/// T007: transcript format v2 (lifted points, commitment-form proofs,
/// pre-weighted shares) through the full protocol: co-located tally, five TCP
/// trustee processes, separate public verifier (format read from the
/// `WODT2` header), oracle; plus rejection of a corrupted v2 transcript.
#[test]
fn v2_format_end_to_end() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("v2-format");
    if out.exists() {
        std::fs::remove_dir_all(&out).unwrap();
    }
    let o = wod()
        .args([
            "--format",
            "v2",
            "experiment",
            "--n",
            "8",
            "--modes",
            "local,dist",
            "--reps",
            "1",
            "--out",
        ])
        .arg(&out)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let result = json(&out.join("n8/results.json"));
    let runs = result["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 2);
    for r in runs {
        assert_eq!(r["verification"]["accept"], true);
        assert_eq!(r["oracle_agrees"], true);
        assert!(r["verification"]["engine_prof"]["jobs"].as_u64().unwrap() > 1000);
    }
    let good = out.join("n8/rep0/local");
    assert_eq!(
        &std::fs::read(good.join("public/transcript.bin")).unwrap()[..6],
        b"WODT2\n"
    );
    let bad = out.join("v2-tampered");
    copy_dir(&good, &bad);
    let p = bad.join("public/transcript.bin");
    let mut b = std::fs::read(&p).unwrap();
    let i = b.len() * 3 / 5;
    b[i] ^= 1;
    std::fs::write(&p, b).unwrap();
    let st = wod().args(["verify", "--dir"]).arg(&bad).output().unwrap();
    assert!(!st.status.success());
}

/// T007: certified offload (`cert:<backend>`) on the unchanged v1 format, in
/// the co-located tally, the five trustee processes and the separate verifier.
#[test]
fn certified_offload_end_to_end() {
    let mut specs = vec!["cert:cpu"];
    if cfg!(feature = "cuda-emu") {
        specs.push("cert:emu");
    }
    for spec in specs {
        let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(spec.replace(':', "-"));
        if out.exists() {
            std::fs::remove_dir_all(&out).unwrap();
        }
        let o = wod()
            .args([
                "--verify-backend",
                spec,
                "experiment",
                "--n",
                "8",
                "--modes",
                "local,dist",
                "--reps",
                "1",
                "--out",
            ])
            .arg(&out)
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let result = json(&out.join("n8/results.json"));
        for r in result["runs"].as_array().unwrap() {
            assert_eq!(r["verification"]["accept"], true);
            assert_eq!(r["oracle_agrees"], true);
            assert!(
                r["verification"]["verify_backend"]
                    .as_str()
                    .unwrap()
                    .starts_with("certified(")
            );
        }
    }
}

#[test]
fn secure_lift_formats_public_only_individual_replay() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    for format in ["v3", "v4"] {
        let out =
            PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("secure-{format}-{nonce}"));
        let o = wod()
            .args([
                "--format",
                format,
                "experiment",
                "--n",
                "8",
                "--modes",
                "local,dist",
                "--reps",
                "1",
                "--out",
            ])
            .arg(&out)
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        for r in json(&out.join("n8/results.json"))["runs"]
            .as_array()
            .unwrap()
        {
            assert_eq!(r["verification"]["accept"], true);
            assert_eq!(r["oracle_agrees"], true);
        }
        for mode in ["local", "dist-rtt0"] {
            let original = out.join("n8/rep0").join(mode).join("public");
            let replay = out.join(format!("public-only-{mode}"));
            std::fs::create_dir_all(replay.join("public")).unwrap();
            for file in ["setup.bin", "ledger.bin", "transcript.bin", "claim.json"] {
                std::fs::copy(original.join(file), replay.join("public").join(file)).unwrap();
            }
            let o = wod()
                .args([
                    "--verify-backend",
                    "inline",
                    "--v2-verify",
                    "individual",
                    "verify",
                    "--dir",
                ])
                .arg(&replay)
                .output()
                .unwrap();
            assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
            assert_eq!(json(&replay.join("public/verify.json"))["accept"], true);
            assert!(!replay.join("private").exists());
        }
    }
}
