//! Transaction log replay (.LOG1/.LOG2, new format, Windows 8.1+). Port of proto/hivelog.py.
//!
//! Format reference: Maxim Suhanov, "Windows registry file format specification".

use super::hive::{checksum, BASE};

const PAGE: usize = 512;
const MARVIN_SEED: u64 = 0x82EF_4D88_7A4E_55C5;

fn marvin32(data: &[u8]) -> u64 {
    let (mut lo, mut hi) = (MARVIN_SEED as u32, (MARVIN_SEED >> 32) as u32);
    let block = |lo: &mut u32, hi: &mut u32| {
        *hi ^= *lo;
        *lo = lo.rotate_left(20);
        *lo = lo.wrapping_add(*hi);
        *hi = hi.rotate_left(9);
        *hi ^= *lo;
        *lo = lo.rotate_left(27);
        *lo = lo.wrapping_add(*hi);
        *hi = hi.rotate_left(19);
    };
    let n = data.len() / 4 * 4;
    for w in data[..n].chunks_exact(4) {
        lo = lo.wrapping_add(u32::from_le_bytes(w.try_into().unwrap()));
        block(&mut lo, &mut hi);
    }
    let mut tail = [0u8; 4];
    tail[..data.len() - n].copy_from_slice(&data[n..]);
    tail[data.len() - n] = 0x80;
    lo = lo.wrapping_add(u32::from_le_bytes(tail));
    block(&mut lo, &mut hi);
    block(&mut lo, &mut hi);
    ((hi as u64) << 32) | lo as u64
}

pub struct Entry {
    pub seq: u32,
    pub bins_size: u32,
    pub pages: Vec<(u32, Vec<u8>)>,
}

/// Valid log entries in order; stops at the first damaged one.
pub fn parse_log(d: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    if d.len() < PAGE || &d[..4] != b"regf" {
        return out;
    }
    let u32at = |o: usize| u32::from_le_bytes(d[o..o + 4].try_into().unwrap());
    let mut pos = PAGE;
    while pos + 40 <= d.len() && &d[pos..pos + 4] == b"HvLE" {
        let (size, seq, bins_size, count) = (u32at(pos + 4) as usize, u32at(pos + 12), u32at(pos + 16), u32at(pos + 20) as usize);
        let h1 = u64::from_le_bytes(d[pos + 24..pos + 32].try_into().unwrap());
        let h2 = u64::from_le_bytes(d[pos + 32..pos + 40].try_into().unwrap());
        if size < 40 || size % PAGE != 0 || pos + size > d.len() {
            break;
        }
        let e = &d[pos..pos + size];
        if marvin32(&e[40..]) != h1 || marvin32(&e[..32]) != h2 {
            break;
        }
        if 40 + 8 * count > size {
            break;
        }
        let mut pages = Vec::with_capacity(count);
        let mut dpos = 40 + 8 * count;
        for i in 0..count {
            let off = u32::from_le_bytes(e[40 + 8 * i..44 + 8 * i].try_into().unwrap());
            let sz = u32::from_le_bytes(e[44 + 8 * i..48 + 8 * i].try_into().unwrap()) as usize;
            if dpos + sz > size {
                break;
            }
            pages.push((off, e[dpos..dpos + sz].to_vec()));
            dpos += sz;
        }
        out.push(Entry { seq, bins_size, pages });
        pos += size;
    }
    out
}

#[derive(Debug, Default, Clone)]
pub struct Replay {
    pub seq1: u32,
    pub seq2: u32,
    pub applied: usize,
    pub last_seq: Option<u32>,
    /// dirty primary whose logs don't continue it: changes after seq2 are lost
    pub gap: Option<(u32, u32)>,
}

impl Replay {
    pub fn dirty(&self) -> bool {
        self.seq1 != self.seq2
    }
    pub fn changed(&self) -> bool {
        self.dirty() || self.applied > 0
    }
    pub fn describe(&self) -> String {
        if let Some((want, got)) = self.gap {
            format!("dirty ({}/{}), log entries {}+ don't continue it (expected {}) — using the primary file as is",
                    self.seq1, self.seq2, got, want)
        } else if self.applied > 0 {
            format!("{} log entries replayed (up to {})", self.applied, self.last_seq.unwrap_or(0))
        } else if self.dirty() {
            format!("dirty ({}/{}), nothing to replay", self.seq1, self.seq2)
        } else {
            "clean".into()
        }
    }
}

/// Apply the logs to a copy of the primary file. The first applied entry must continue the
/// primary (seq == seq2), every next one the previous; entries after a gap are never applied
/// (they'd patch pages onto a base they weren't written for).
pub fn replay(hive: &[u8], logs: &[&[u8]]) -> Result<(Vec<u8>, Replay), String> {
    if hive.len() < BASE || &hive[..4] != b"regf" {
        return Err("not a registry hive".into());
    }
    let mut h = hive.to_vec();
    let seq1 = u32::from_le_bytes(h[4..8].try_into().unwrap());
    let seq2 = u32::from_le_bytes(h[8..12].try_into().unwrap());
    let mut r = Replay { seq1, seq2, ..Default::default() };

    let mut parsed: Vec<Vec<Entry>> = logs.iter().map(|l| parse_log(l)).filter(|e| !e.is_empty()).collect();
    parsed.sort_by_key(|e| e[0].seq);
    let mut expected = seq2;
    let mut last: Option<(u32, u32)> = None;
    for log in &parsed {
        for e in log {
            if e.seq < seq2 {
                continue; // already in the primary file
            }
            if e.seq != expected {
                if r.applied == 0 && r.gap.is_none() {
                    r.gap = Some((expected, e.seq));
                }
                break;
            }
            let need = BASE + e.bins_size as usize;
            if h.len() < need {
                h.resize(need, 0);
            }
            for (off, data) in &e.pages {
                let p = BASE + *off as usize;
                if p + data.len() > h.len() {
                    h.resize(p + data.len(), 0);
                }
                h[p..p + data.len()].copy_from_slice(data);
            }
            r.applied += 1;
            last = Some((e.seq, e.bins_size));
            expected = e.seq.wrapping_add(1);
        }
    }
    if r.applied > 0 {
        r.gap = None;
    } else if !r.dirty() {
        r.gap = None; // clean primary: stale logs are normal
    }
    if let Some((seq, bins)) = last {
        r.last_seq = Some(seq);
        let n = seq.wrapping_add(1);
        h[4..8].copy_from_slice(&n.to_le_bytes());
        h[8..12].copy_from_slice(&n.to_le_bytes());
        h[0x28..0x2C].copy_from_slice(&bins.to_le_bytes());
        h.truncate(BASE + bins as usize);
    } else if seq1 != seq2 {
        h[8..12].copy_from_slice(&seq1.to_le_bytes());
    }
    let c = checksum(&h[..BASE]);
    h[0x1FC..0x200].copy_from_slice(&c.to_le_bytes());
    Ok((h, r))
}
