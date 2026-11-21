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
}
