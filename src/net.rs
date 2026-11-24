//! Distributed execution: an authenticated common-view broadcast board
//! (the public coordinator) and five independent trustee processes over
//! persistent TCP connections.
//!
//! * Trustees authenticate with Ed25519 (challenge–response at connect; every
//!   board message is signed and carries a per-sender counter).
//! * The board checks signatures and counters, assigns the global order,
//!   appends to the transcript and relays each message to every trustee, so
//!   all trustees see the same sequence (common view). It never holds shares.
//! * Each trustee holds only its own share, draws its own randomness,
//!   verifies every other trustee's proofs, and posts its contributions as
//!   one signed batch per scheduling step.
//! * Optional latency injection delays every frame by RTT/2 in each
//!   direction (trustee→board and board→trustee), FIFO and pipelined.
//!
//! Frame: `u32` big-endian length ‖ `u8` kind ‖ payload.

use crate::circuit::Circuit;
use crate::group::sha256;
use crate::ledger::{Contract, Event, sealed_board_hash};
use crate::setup::{Paths, Setup, TrusteeKey, read_bin, write_bin, write_json};
use crate::tally::{Engine, Msg, Public, Trustee};
use crate::transcript;
use crate::verify::context;
use anyhow::{Context, Result, anyhow, bail, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const K_NONCE: u8 = 0;
const K_START: u8 = 1;
const K_ENTRY: u8 = 2;
const K_HELLO: u8 = 10;
const K_POST: u8 = 11;
const K_STATS: u8 = 12;
// Internal channel notification, never a network frame.
const K_CLOSED: u8 = 255;

type Frame = (u8, Arc<Vec<u8>>);

async fn read_frame(r: &mut (impl AsyncReadExt + Unpin)) -> Result<(u8, Vec<u8>)> {
    let n = r.read_u32().await? as usize;
    ensure!((1..1 << 30).contains(&n), "bad frame length");
    let k = r.read_u8().await?;
    let mut buf = vec![0u8; n - 1];
    r.read_exact(&mut buf).await?;
    Ok((k, buf))
}

/// Writer task: delays each frame until `enqueue time + delay`, preserving
/// order and pipelining; flushes when the queue is momentarily empty.
async fn writer(
    w: tokio::net::tcp::OwnedWriteHalf,
    mut rx: mpsc::UnboundedReceiver<(Instant, Frame)>,
    delay: Duration,
) -> Result<u64> {
    let mut w = BufWriter::with_capacity(1 << 20, w);
    let mut bytes = 0u64;
    while let Some((t, (k, p))) = rx.recv().await {
        if !delay.is_zero() {
            tokio::time::sleep_until((t + delay).into()).await;
        }
        w.write_u32(p.len() as u32 + 1).await?;
        w.write_u8(k).await?;
        w.write_all(&p).await?;
        bytes += p.len() as u64 + 5;
        if rx.is_empty() {
            w.flush().await?;
        }
    }
    w.flush().await?;
    w.shutdown().await.ok();
    Ok(bytes)
}

fn hello_digest(ctx: &[u8; 32], nonce: &[u8; 32], id: u8) -> [u8; 32] {
    sha256(&[b"wod/hello/v1", ctx, nonce, &[id]])
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrusteeStats {
    pub id: usize,
    /// verifying + applying received messages
    pub seconds_verify: f64,
    /// producing own contributions (proofs, signatures)
    pub seconds_produce: f64,
    /// blocked waiting for the network
    pub seconds_wait: f64,
    pub seconds_total: f64,
    pub msgs_sent: u64,
    pub bytes_sent: u64,
    pub entries_received: u64,
    pub bytes_received: u64,
    pub peak_rss_bytes: Option<u64>,
    #[serde(default)]
    pub verify_backend: String,
    #[serde(default)]
    pub engine_prof: crate::tally::Prof,
    pub device_times: Option<serde_json::Value>,
    pub verification_telemetry: serde_json::Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BoardStats {
    pub seconds_connect: f64,
    /// Start → last gate output known to the publisher
    pub seconds_gates: f64,
    /// last gate → decision decrypted
    pub seconds_release: f64,
    /// Start → all trustees reported
    pub seconds_total: f64,
    pub messages: u64,
    pub transcript_bytes: u64,
    pub bytes_relayed: u64,
    pub decision: Option<bool>,
    pub transcript_hash: String,
    pub trustees: Vec<TrusteeStats>,
    pub peak_rss_bytes: Option<u64>,
}

/// Loads the public poll state shared by board and trustees.
pub struct Session {
    pub setup: Setup,
    pub events: Vec<Event>,
    pub inputs: Vec<crate::group::Ct>,
    pub commit: [u8; 32],
    pub board_hash: [u8; 32],
    pub ctx: [u8; 32],
}

impl Session {
    /// Rebuilds the sealed board from the contract events (authentic chain
    /// view, assumption A6); `verify_proofs` re-checks every Groth16 proof.
    pub fn load(p: &Paths, verify_proofs: bool) -> Result<Self> {
        let setup: Setup = read_bin(&p.public("setup.bin"))?;
        let events: Vec<Event> = read_bin(&p.public("ledger.bin"))?;
        let pvk = ark_groth16::prepare_verifying_key(&setup.vk);
        let mut c = Contract::new(&pvk, setup.root, setup.poll, setup.pk, setup.n);
        let pre: Vec<Event> = events
            .iter()
            .filter(|e| !matches!(e, Event::Claim { .. }))
            .cloned()
            .collect();
        c.replay(&pre, verify_proofs)?;
        let commit = c.sealed.ok_or(anyhow!("board not sealed"))?;
        let inputs = c.sealed_inputs()?;
        let board_hash = sealed_board_hash(&commit, &inputs);
        let ctx = context(&setup.hash(), &board_hash);
        Ok(Session {
            setup,
            events: pre,
            inputs,
            commit,
            board_hash,
            ctx,
        })
    }
    pub fn public(&self) -> Result<Public> {
        Ok(Public::new(
            self.setup.pk,
            self.setup.hi.clone(),
            self.setup.vks()?,
            self.ctx,
        ))
    }
    pub fn circuit(&self) -> Circuit {
        Circuit::build(self.setup.n, self.setup.l_vote, self.setup.tau)
    }
}

/// Records the outcome claim on the (simulated) contract.
pub fn publish_claim(p: &Paths, s: &Session, h: [u8; 32], bit: bool) -> Result<()> {
    let pvk = ark_groth16::prepare_verifying_key(&s.setup.vk);
    let mut c = Contract::new(&pvk, s.setup.root, s.setup.poll, s.setup.pk, s.setup.n);
    c.replay(&s.events, false)?;
    c.post_claim(s.commit, h, bit)?;
    write_bin(&p.public("ledger.bin"), &c.events)?;
    write_json(
        &p.public("claim.json"),
        &serde_json::json!({"commitment": hex::encode(s.commit), "transcript_hash": hex::encode(h), "decision": bit}),
    )
}

// ---------------------------------------------------------------- board

/// Runs the public coordinator / board until the release is complete and all
/// trustees reported. Writes the transcript and the outcome claim.
pub fn run_board(p: &Paths, listener: std::net::TcpListener, rtt_ms: u64) -> Result<BoardStats> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(board(p, listener, rtt_ms))
}

async fn board(p: &Paths, listener: std::net::TcpListener, rtt_ms: u64) -> Result<BoardStats> {
    let s = Session::load(p, false)?;
    let a = s.setup.a;
    let vks = s.setup.vks()?;
    let delay = Duration::from_micros(rtt_ms * 500);
    listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(listener)?;
    let t_conn = Instant::now();

    let (up_tx, mut up_rx) = mpsc::unbounded_channel::<(usize, u8, Vec<u8>)>();
    let mut outs: Vec<Option<mpsc::UnboundedSender<(Instant, Frame)>>> = vec![None; a];
    let mut wtasks = Vec::new();
    while outs.iter().any(|o| o.is_none()) {
        let (sock, _) = listener.accept().await?;
        sock.set_nodelay(true)?;
        let (mut r, w) = sock.into_split();
        let (tx, rx) = mpsc::unbounded_channel();
        wtasks.push(tokio::spawn(writer(w, rx, delay)));
        let nonce: [u8; 32] = rand::random();
        tx.send((Instant::now(), (K_NONCE, Arc::new(nonce.to_vec()))))?;
        let (k, hello) = read_frame(&mut r).await?;
        ensure!(k == K_HELLO && hello.len() == 65, "bad hello");
        let id = hello[0] as usize;
        ensure!(
            id < a && outs[id].is_none(),
            "unknown or duplicate trustee {id}"
        );
        vks[id].verify(
            &hello_digest(&s.ctx, &nonce, id as u8),
            &Signature::from_slice(&hello[1..])?,
        )?;
        outs[id] = Some(tx);
        let up = up_tx.clone();
        tokio::spawn(async move {
            loop {
                match read_frame(&mut r).await {
                    Ok((k, b)) => {
                        if up.send((id, k, b)).is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = up.send((id, K_CLOSED, Vec::new()));
                        break;
                    }
                }
            }
        });
    }
    let outs: Vec<_> = outs.into_iter().map(|o| o.unwrap()).collect();
    let seconds_connect = t_conn.elapsed().as_secs_f64();

    // publisher replica (no proof checks; the verifier re-checks everything)
    let (pub_tx, pub_rx) = std::sync::mpsc::channel::<Msg>();
    let pp = Arc::new(s.public()?);
    let circ = Arc::new(s.circuit());
    let n_gates = circ.n_gates();
    let mut eng = Engine::new(pp, circ, &s.inputs)?;
    let publisher = std::thread::spawn(move || -> Result<(Option<Instant>, Instant, bool)> {
        let mut t_gates = None;
        for m in pub_rx {
            eng.process(&m, false)?;
            if t_gates.is_none() && eng.gates_done == n_gates {
                t_gates = Some(Instant::now());
            }
            if let Some(b) = eng.result {
                return Ok((t_gates, Instant::now(), b));
            }
        }
        bail!("board closed before the release")
    });

    let mut tw =
        transcript::Writer::create(&p.public("transcript.bin"), &s.setup.hash(), &s.board_hash)?;
    let t0 = Instant::now();
    for o in &outs {
        o.send((t0, (K_START, Arc::new(vec![]))))?;
    }
    let mut ctr = vec![0u64; a];
    let mut stats: Vec<Option<TrusteeStats>> = vec![None; a];
    let mut relayed = 0u64;
    let mut up_bytes = vec![0u64; a];
    while stats.iter().any(|x| x.is_none()) {
        let (id, k, body) = up_rx
            .recv()
            .await
            .ok_or(anyhow!("all trustees disconnected"))?;
        if k != K_CLOSED {
            up_bytes[id] += body.len() as u64 + 5;
        }
        match k {
            K_POST => {
                let m: Msg = bincode::deserialize(&body)?;
                ensure!(m.from as usize == id, "sender mismatch");
                ensure!(m.ctr == ctr[id], "bad counter from trustee {id}");
                m.verify_sig_format(&vks[id], &s.ctx, crate::tally::default_format())?;
                ctr[id] += 1;
                tw.append_frame(&body)?;
                let now = Instant::now();
                let f = Arc::new(body);
                for o in &outs {
                    o.send((now, (K_ENTRY, f.clone())))?;
                    relayed += f.len() as u64 + 5;
                }
                pub_tx.send(m)?;
            }
            K_STATS => stats[id] = Some(serde_json::from_slice(&body)?),
            K_CLOSED if stats[id].is_some() => {}
            K_CLOSED => bail!("trustee {id} disconnected before completing the protocol"),
            _ => bail!("unexpected frame kind {k}"),
        }
    }
    let seconds_total = t0.elapsed().as_secs_f64();
    drop(outs);
    for w in wtasks {
        let _ = w.await;
    }
    let (messages, transcript_bytes) = (tw.msgs, tw.bytes);
    let h = tw.finish()?;
    drop(pub_tx);
    let (t_gates, t_rel, bit) = publisher
        .join()
        .map_err(|_| anyhow!("publisher panicked"))??;
    let t_gates = t_gates.unwrap_or(t_rel);
    publish_claim(p, &s, h, bit)?;
    Ok(BoardStats {
        seconds_connect,
        seconds_gates: (t_gates - t0).as_secs_f64(),
        seconds_release: (t_rel - t_gates).as_secs_f64(),
        seconds_total,
        messages,
        transcript_bytes,
        bytes_relayed: relayed,
        decision: Some(bit),
        transcript_hash: hex::encode(h),
        peak_rss_bytes: crate::experiment::peak_rss_bytes(),
        trustees: stats
            .into_iter()
            .enumerate()
            .map(|(i, x)| TrusteeStats {
                bytes_sent: up_bytes[i],
                bytes_received: relayed / a as u64,
                ..x.unwrap()
            })
            .collect(),
    })
}

// -------------------------------------------------------------- trustee

enum Inbound {
    Start,
    Entry(Vec<u8>),
    Closed,
}

/// Runs one trustee process: connects to the board, then verifies and
/// produces until the decision is released.
pub fn run_trustee(p: &Paths, id: usize, addr: &str, rtt_ms: u64) -> Result<TrusteeStats> {
    let key: TrusteeKey = read_bin(&p.private(&format!("trustee_{id}.bin")))?;
    ensure!(key.id == id, "key file belongs to trustee {}", key.id);
    let s = Session::load(p, false)?;
    ensure!(id < s.setup.a, "trustee index out of range");
    let sk = SigningKey::from_bytes(&key.signing);
    ensure!(
        sk.verifying_key().to_bytes() == s.setup.trustee_vks[id],
        "signing key not registered"
    );
    ensure!(
        crate::group::g() * key.share == s.setup.hi[id],
        "secret share does not match the registered trustee"
    );
    let mut eng = Engine::new(Arc::new(s.public()?), Arc::new(s.circuit()), &s.inputs)?;
    let mut me = Trustee::new(id, key.share, sk.clone());

    let (in_tx, in_rx) = std::sync::mpsc::channel::<Inbound>();
    let (out_tx, out_rx) = mpsc::unbounded_channel::<(Instant, Frame)>();
    let addr = addr.to_string();
    let ctx = s.ctx;
    let delay = Duration::from_micros(rtt_ms * 500);
    let io = std::thread::spawn(move || -> Result<(u64, u64)> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            let mut sock = None;
            for _ in 0..600 {
                if let Ok(c) = TcpStream::connect(&addr).await {
                    sock = Some(c);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let sock = sock.ok_or(anyhow!("cannot reach board at {addr}"))?;
            sock.set_nodelay(true)?;
            let (mut r, mut w) = sock.into_split();
            let (k, nonce) = read_frame(&mut r).await?;
            ensure!(k == K_NONCE && nonce.len() == 32, "bad nonce");
            let mut hello = vec![id as u8];
            hello.extend(
                sk.sign(&hello_digest(&ctx, nonce[..].try_into()?, id as u8))
                    .to_bytes(),
            );
            w.write_u32(hello.len() as u32 + 1).await?;
            w.write_u8(K_HELLO).await?;
            w.write_all(&hello).await?;
            let wt = tokio::spawn(writer(w, out_rx, delay));
            let mut recv = 0u64;
            loop {
                match read_frame(&mut r).await {
                    Ok((K_START, _)) => in_tx.send(Inbound::Start)?,
                    Ok((K_ENTRY, b)) => {
                        recv += b.len() as u64 + 5;
                        in_tx.send(Inbound::Entry(b))?
                    }
                    Ok((k, _)) => bail!("unexpected frame {k}"),
                    Err(_) => break,
                }
            }
            let _ = in_tx.send(Inbound::Closed);
            let sent = wt.await??;
            Ok((sent, recv))
        })
    });

    let mut st = TrusteeStats {
        id,
        ..Default::default()
    };
    let send = |m: Msg, st: &mut TrusteeStats| -> Result<()> {
        st.msgs_sent += 1;
        out_tx.send((Instant::now(), (K_POST, Arc::new(bincode::serialize(&m)?))))?;
        Ok(())
    };
    // wait for Start
    match in_rx.recv()? {
        Inbound::Start => {}
        _ => bail!("expected start"),
    }
    let t_start = Instant::now();
    let t = Instant::now();
    if let Some(m) = me.produce(&eng) {
        send(m, &mut st)?;
    }
    st.seconds_produce += t.elapsed().as_secs_f64();
    while !eng.finished() {
        let t = Instant::now();
        let first = in_rx.recv()?;
        st.seconds_wait += t.elapsed().as_secs_f64();
        let t = Instant::now();
        let mut batch = vec![first];
        batch.extend(in_rx.try_iter());
        for ib in batch {
            match ib {
                Inbound::Entry(b) => {
                    st.entries_received += 1;
                    let m: Msg = bincode::deserialize(&b)?;
                    eng.process(&m, m.from as usize != id).with_context(|| {
                        format!("trustee {id}: invalid message from trustee {}", m.from)
                    })?;
                }
                Inbound::Closed => bail!("board closed the connection"),
                Inbound::Start => {}
            }
        }
        st.seconds_verify += t.elapsed().as_secs_f64();
        if eng.finished() {
            break;
        }
        let t = Instant::now();
        if let Some(m) = me.produce(&eng) {
            send(m, &mut st)?;
        }
        st.seconds_produce += t.elapsed().as_secs_f64();
    }
    st.seconds_total = t_start.elapsed().as_secs_f64();
    st.peak_rss_bytes = crate::experiment::peak_rss_bytes();
    st.verify_backend = crate::batch::default_name();
    st.engine_prof = eng.prof.clone();
    st.device_times = crate::gpu::device_snapshot();
    st.verification_telemetry = crate::batch::default_telemetry();
    out_tx.send((
        Instant::now(),
        (K_STATS, Arc::new(serde_json::to_vec(&st)?)),
    ))?;
    drop(out_tx);
    let (sent, recv) = io.join().map_err(|_| anyhow!("io thread panicked"))??;
    st.bytes_sent = sent;
    st.bytes_received = recv;
    Ok(st)
}
