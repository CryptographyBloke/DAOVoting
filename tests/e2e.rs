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
