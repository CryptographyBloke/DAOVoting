//! Public tally transcript `T`: a header binding the setup hash and the
//! sealed-board hash, followed by the board messages in board order
//! (length-prefixed bincode). `H(T) = SHA-256("wod/transcript/v1" ‖ file)`.

use crate::tally::Msg;
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

const MAGIC: &[u8; 6] = b"WODT1\n";
/// Transcript format v2 (T007): lifted points and commitment-form proofs.
const MAGIC_V2: &[u8; 6] = b"WODT2\n";

pub struct Writer {
    w: BufWriter<std::fs::File>,
    h: Sha256,
    pub bytes: u64,
    pub msgs: u64,
}

impl Writer {
    pub fn create(p: &Path, setup_hash: &[u8; 32], board_hash: &[u8; 32]) -> Result<Self> {
        let mut h = Sha256::new();
        h.update(b"wod/transcript/v1");
        let mut w = Writer {
            w: BufWriter::new(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(p)?,
            ),
            h,
            bytes: 0,
            msgs: 0,
        };
        w.raw(if crate::tally::default_v2() {
            MAGIC_V2
        } else {
            MAGIC
        })?;
        w.raw(setup_hash)?;
        w.raw(board_hash)?;
        Ok(w)
    }
    fn raw(&mut self, b: &[u8]) -> Result<()> {
        self.w.write_all(b)?;
        self.h.update(b);
        self.bytes += b.len() as u64;
        Ok(())
    }
    /// Appends an already serialized `Msg`.
    pub fn append_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.raw(&(frame.len() as u32).to_be_bytes())?;
        self.raw(frame)?;
        self.msgs += 1;
        Ok(())
    }
    pub fn append(&mut self, m: &Msg) -> Result<()> {
        self.append_frame(&bincode::serialize(m)?)
    }
    pub fn finish(mut self) -> Result<[u8; 32]> {
        self.w.flush()?;
        Ok(self.h.finalize().into())
    }
}

pub struct Reader {
    r: BufReader<std::fs::File>,
    h: Sha256,
    pub setup_hash: [u8; 32],
    pub board_hash: [u8; 32],
    /// format v2 (header `WODT2`)
    pub v2: bool,
    remaining: u64,
}

impl Reader {
    pub fn open(p: &Path) -> Result<Self> {
        let file = std::fs::File::open(p)?;
        let file_len = file.metadata()?.len();
        ensure!(file_len >= 70, "truncated transcript header");
        let mut r = BufReader::with_capacity(1 << 20, file);
        let mut hdr = [0u8; 70];
        r.read_exact(&mut hdr)?;
        ensure!(
            &hdr[..6] == MAGIC || &hdr[..6] == MAGIC_V2,
            "not a transcript file"
        );
        let mut h = Sha256::new();
        h.update(b"wod/transcript/v1");
        h.update(hdr);
        Ok(Reader {
            r,
            h,
            setup_hash: hdr[6..38].try_into()?,
            board_hash: hdr[38..70].try_into()?,
            v2: &hdr[..6] == MAGIC_V2,
            remaining: file_len - 70,
        })
    }
    /// Next message, or `None` at end of file.
    pub fn next(&mut self) -> Result<Option<Msg>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let mut len = [0u8; 4];
        self.r.read_exact(&mut len)?;
        let n = u32::from_be_bytes(len) as usize;
        ensure!(n < 1 << 30, "frame too large");
        ensure!(
            n as u64 <= self.remaining.saturating_sub(4),
            "truncated transcript frame"
        );
        self.remaining -= 4 + n as u64;
        let mut buf = vec![0u8; n];
        self.r.read_exact(&mut buf)?;
        self.h.update(len);
        self.h.update(&buf);
        Ok(Some(bincode::deserialize(&buf)?))
    }
    /// `H(T)` (valid once `next` returned `None`).
    pub fn hash(self) -> [u8; 32] {
        self.h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn transcript_with_tail(tail: &[u8]) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("wod-transcript-{}-{nonce}.bin", std::process::id()));
        let mut bytes = Vec::from(MAGIC.as_slice());
        bytes.extend_from_slice(&[1; 32]);
        bytes.extend_from_slice(&[2; 32]);
        bytes.extend_from_slice(tail);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn reader_rejects_partial_frame_length_and_body() {
        for n in 1..4 {
            let path = transcript_with_tail(&vec![0; n]);
            assert!(Reader::open(&path).unwrap().next().is_err());
            std::fs::remove_file(path).unwrap();
        }

        let mut tail = 5u32.to_be_bytes().to_vec();
        tail.extend_from_slice(&[1, 2]);
        let path = transcript_with_tail(&tail);
        assert!(Reader::open(&path).unwrap().next().is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn reader_accepts_clean_end_of_transcript() {
        let path = transcript_with_tail(&[]);
        assert!(Reader::open(&path).unwrap().next().unwrap().is_none());
        std::fs::remove_file(path).unwrap();
    }
}
