//! Poll setup by a **test-only dealer**: committee key sharing, trustee
//! signing keys, registry snapshot and the Groth16 reference string. A
//! deployment replaces it by a DKG and an MPC ceremony (paper Sect. 8).
//!
//! Directory layout of a run:
//! * `public/`  setup, ledger (contract events), transcript, claim, reports
//! * `private/` trustee shares and signing keys, voter credentials and votes,
//!   oracle data — never part of public artifacts
//! * `work/`    the Groth16 proving key (public in practice, large)

use crate::ballot::{self, Registry, Voter};
use crate::group::*;
use crate::shamir;
use anyhow::{Context, Result, ensure};
use ark_bn254::Bn254;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ed25519_dalek::SigningKey;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::path::{Path, PathBuf};

pub const PROTOCOL: &str = "wod/v1 (Li-Li winner-only + CGY CSZ)";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Setup {
    pub protocol: String,
    pub n: usize,
    pub l_vote: usize,
    pub tau: u64,
    pub poll: u64,
    /// trustees `a` and sharing degree `t` (`q_dec = t + 1`)
    pub a: usize,
    pub t: usize,
    #[serde(with = "arkser")]
    pub pk: G,
    #[serde(with = "arkser")]
    pub hi: Vec<G>,
    pub trustee_vks: Vec<[u8; 32]>,
    /// registry snapshot: credential commitments `Poseidon_1(s)` and weights
    #[serde(with = "arkser")]
    pub creds: Vec<Fb>,
    pub weights: Vec<u64>,
    #[serde(with = "arkser")]
    pub root: Fb,
    #[serde(with = "arkser")]
    pub vk: VerifyingKey<Bn254>,
}

impl Setup {
    pub fn hash(&self) -> [u8; 32] {
        sha256(&[b"wod/setup/v1", &bincode::serialize(self).unwrap()])
    }
    pub fn vks(&self) -> Result<Vec<ed25519_dalek::VerifyingKey>> {
        self.trustee_vks
            .iter()
            .map(|k| Ok(ed25519_dalek::VerifyingKey::from_bytes(k)?))
            .collect()
    }
}

#[derive(Serialize, Deserialize)]
pub struct TrusteeKey {
    pub id: usize,
    #[serde(with = "arkser")]
    pub share: F,
    pub signing: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct VoterRecord {
    pub index: usize,
    #[serde(with = "arkser")]
    pub s: Fb,
    pub w: u64,
    pub vote: bool,
}

pub struct Dealt {
    pub setup: Setup,
    pub trustees: Vec<TrusteeKey>,
    pub voters: Vec<VoterRecord>,
}

/// Deals a poll for `weights.len()` voters with the given votes.
pub fn deal<R: RngCore + CryptoRng>(
    weights: &[u64],
    votes: &[bool],
    tau: u64,
    poll: u64,
    a: usize,
    t: usize,
    vk: VerifyingKey<Bn254>,
    rng: &mut R,
) -> Dealt {
    let (sk, shares) = shamir::deal(t, a, rng);
    let sks: Vec<SigningKey> = (0..a).map(|_| SigningKey::generate(rng)).collect();
    let secrets: Vec<Fb> = weights
        .iter()
        .map(|_| Fb::from(rng.r#gen::<u128>()))
        .collect();
    let creds: Vec<Fb> = secrets.iter().map(|s| ballot::poseidon(&[*s])).collect();
    let entries: Vec<(Fb, u64)> = creds.iter().copied().zip(weights.iter().copied()).collect();
    let root = Registry::new(&entries).root();
    let setup = Setup {
        protocol: PROTOCOL.into(),
        n: weights.len(),
        l_vote: ballot::L_VOTE,
        tau,
        poll,
        a,
        t,
        pk: g() * sk,
        hi: shares.iter().map(|s| g() * s).collect(),
        trustee_vks: sks.iter().map(|k| k.verifying_key().to_bytes()).collect(),
        creds,
        weights: weights.to_vec(),
        root,
        vk,
    };
    let trustees = shares
        .into_iter()
        .zip(&sks)
        .enumerate()
        .map(|(id, (share, k))| TrusteeKey {
            id,
            share,
            signing: k.to_bytes(),
        })
        .collect();
    let voters = secrets
        .into_iter()
        .zip(weights)
        .zip(votes)
        .enumerate()
        .map(|(index, ((s, &w), &vote))| VoterRecord { index, s, w, vote })
        .collect();
    Dealt {
        setup,
        trustees,
        voters,
    }
}

impl VoterRecord {
    pub fn voter(&self) -> Voter {
        Voter {
            index: self.index,
            s: self.s,
            w: self.w,
        }
    }
}

pub fn registry(s: &Setup) -> Registry {
    let e: Vec<(Fb, u64)> = s
        .creds
        .iter()
        .copied()
        .zip(s.weights.iter().copied())
        .collect();
    Registry::new(&e)
}

/// Prepare a fresh node directory with an explicit file allowlist. The board
/// receives no private material; a trustee receives exactly its own key file.
/// Credentials, votes, oracle inputs and proving artifacts never enter a node.
pub fn export_node(
    source: &Paths,
    destination: &Paths,
    id: Option<usize>,
) -> Result<serde_json::Value> {
    let setup: Setup = read_bin(&source.public("setup.bin"))?;
    let events: Vec<crate::ledger::Event> = read_bin(&source.public("ledger.bin"))?;
    let events: Vec<_> = events
        .into_iter()
        .filter(|e| !matches!(e, crate::ledger::Event::Claim { .. }))
        .collect();
    let pvk = ark_groth16::prepare_verifying_key(&setup.vk);
    let mut ledger = crate::ledger::Contract::new(&pvk, setup.root, setup.poll, setup.pk, setup.n);
    ledger.replay(&events, true)?;
    ensure!(
        ledger.sealed.is_some(),
        "cannot provision an unsealed board"
    );
    let key = if let Some(id) = id {
        ensure!(id < setup.a, "trustee index out of range");
        let key: TrusteeKey = read_bin(&source.private(&format!("trustee_{id}.bin")))?;
        ensure!(
            key.id == id && g() * key.share == setup.hi[id],
            "trustee share identity mismatch"
        );
        ensure!(
            SigningKey::from_bytes(&key.signing)
                .verifying_key()
                .to_bytes()
                == setup.trustee_vks[id],
            "trustee signing key identity mismatch"
        );
        Some(key)
    } else {
        None
    };
    destination.create()?;
    write_bin(&destination.public("setup.bin"), &setup)?;
    write_bin(&destination.public("ledger.bin"), &events)?;
    if let Some(key) = key {
        write_bin(
            &destination.private(&format!("trustee_{}.bin", key.id)),
            &key,
        )?;
    }
    Ok(
        serde_json::json!({"role":if id.is_some(){"trustee"}else{"board"},"trustee_id":id,
        "setup_hash":hex::encode(setup.hash()),"sealed_commitment":hex::encode(ledger.sealed.unwrap()),
        "private_file_count":usize::from(id.is_some()),"public_files":["setup.bin","ledger.bin"]}),
    )
}

pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Paths {
            root: root.as_ref().to_path_buf(),
        }
    }
    pub fn public(&self, f: &str) -> PathBuf {
        self.root.join("public").join(f)
    }
    pub fn private(&self, f: &str) -> PathBuf {
        self.root.join("private").join(f)
    }
    pub fn work(&self, f: &str) -> PathBuf {
        self.root.join("work").join(f)
    }
    pub fn create(&self) -> Result<()> {
        ensure!(
            !self.root.exists(),
            "refusing to reuse run directory {}",
            self.root.display()
        );
        if let Some(parent) = self.root.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::create_dir(&self.root)
            .with_context(|| format!("create run directory {}", self.root.display()))?;
        for d in ["public", "private", "work"] {
            std::fs::create_dir(self.root.join(d))?;
        }
        Ok(())
    }
}

pub fn write_bin<T: Serialize>(p: &Path, v: &T) -> Result<()> {
    let f = std::io::BufWriter::new(
        std::fs::File::create(p).with_context(|| format!("create {}", p.display()))?,
    );
    bincode::serialize_into(f, v)?;
    Ok(())
}

pub fn read_bin<T: DeserializeOwned>(p: &Path) -> Result<T> {
    let f = std::io::BufReader::new(
        std::fs::File::open(p).with_context(|| format!("open {}", p.display()))?,
    );
    Ok(bincode::deserialize_from(f)?)
}

pub fn write_json<T: Serialize>(p: &Path, v: &T) -> Result<()> {
    std::fs::write(p, serde_json::to_vec_pretty(v)?)
        .with_context(|| format!("write {}", p.display()))
}

pub fn write_pk(p: &Path, pk: &ProvingKey<Bn254>) -> Result<()> {
    let mut f = std::io::BufWriter::new(std::fs::File::create(p)?);
    pk.serialize_uncompressed(&mut f)?;
    Ok(())
}

pub fn read_pk(p: &Path) -> Result<ProvingKey<Bn254>> {
    let f = std::io::BufReader::new(
        std::fs::File::open(p).with_context(|| format!("open {}", p.display()))?,
    );
    Ok(ProvingKey::deserialize_uncompressed_unchecked(f)?)
}
