//! Recover deleted keys (+ values) from free cells, and class names from stale nk records
//! in transaction logs. Port of proto/hiveundelete.py.

use std::collections::HashMap;

use super::hive::{decode_name, lower, Value, BASE, SEG};

pub struct Deleted {
    pub path: String,
    pub values: Vec<Value>,
    pub ts: u64,
    pub class: Option<Vec<u8>>,
    pub sd: Option<Vec<u8>>,
    pub flags: u16,
    pub access: u32,
    pub ts_bytes: [u8; 8],
}

pub struct FreeCells<'a> {
    d: &'a [u8],
    alloc: HashMap<u32, usize>,
    free: HashMap<u32, usize>,
}

impl<'a> FreeCells<'a> {
    pub fn new(d: &'a [u8]) -> FreeCells<'a> {
        let mut fc = FreeCells { d, alloc: HashMap::new(), free: HashMap::new() };
        let mut pos = BASE;
        while pos + 32 <= d.len() && &d[pos..pos + 4] == b"hbin" {
            let hsize = fc.u32(pos + 8) as usize;
            if hsize == 0 {
                break;
            }
            let mut c = pos + 32;
            while c + 6 <= (pos + hsize).min(d.len()) {
                let sz = fc.u32(c) as i32;
                if sz == 0 || sz == i32::MIN {
                    break;
                }
                if &d[c + 4..c + 6] == b"nk" {
                    let off = (c - BASE) as u32;
                    if sz > 0 { fc.free.insert(off, c) } else { fc.alloc.insert(off, c) };
                }
                c += sz.unsigned_abs() as usize;
            }
            pos += hsize;
        }
        fc
    }

    fn u32(&self, o: usize) -> u32 {
        self.d.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).unwrap_or(0)
    }

    fn u16(&self, o: usize) -> u16 {
        self.d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).unwrap_or(0)
    }

    fn name(&self, c: usize) -> String {
        let flags = self.u16(c + 6);
        let ln = self.u16(c + 4 + 72) as usize;
        let raw = self.d.get(c + 80..c + 80 + ln).unwrap_or(&[]);
        decode_name(raw, flags & 0x20 != 0)
    }

    /// Path of the key at hive offset `off` ("" for the root), following parent pointers.
    pub fn path(&self, off: u32, depth: u32) -> Option<String> {
        let c = *self.alloc.get(&off).or_else(|| self.free.get(&off))?;
        if depth > 64 {
            return None;
        }
        if self.u16(c + 6) & 0x4 != 0 {
            return Some(String::new());
        }
        let p = self.path(self.u32(c + 4 + 16), depth + 1)?;
        Some(format!("{p}\\{}", self.name(c)))
    }

    /// (cell data, is_free) at hive offset `off`.
    pub fn cell(&self, off: u32) -> Option<(&'a [u8], bool)> {
        let c = BASE.checked_add(off as usize)?;
        if c + 4 > self.d.len() {
            return None;
        }
        let sz = self.u32(c) as i32;
        let size = sz.unsigned_abs() as usize;
        if sz == 0 || c + size > self.d.len() || size < 4 {
            return None;
        }
        Some((&self.d[c + 4..c + size], sz > 0))
    }

    /// Values of the nk record at file offset c; None if any record is broken.
    fn values(&self, c: usize) -> Option<Vec<Value>> {
        let count = self.u32(c + 4 + 36) as usize;
        if count == 0 {
            return Some(Vec::new());
        }
        if count > 4096 {
            return None;
        }
        let (lst, _) = self.cell(self.u32(c + 4 + 40))?;
        if lst.len() < 4 * count {
            return None;
        }
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let (v, _) = self.cell(u32::from_le_bytes(lst[4 * i..4 * i + 4].try_into().unwrap()))?;
            if v.len() < 20 || &v[..2] != b"vk" {
                return None;
            }
            let nlen = u16::from_le_bytes([v[2], v[3]]) as usize;
            let dsize = u32::from_le_bytes(v[4..8].try_into().unwrap());
            let doff = u32::from_le_bytes(v[8..12].try_into().unwrap());
            let typ = u32::from_le_bytes(v[12..16].try_into().unwrap());
            let flags = u16::from_le_bytes([v[16], v[17]]);
            let name = decode_name(v.get(20..20 + nlen)?, flags & 1 != 0);
            let size = (dsize & 0x7FFF_FFFF) as usize;
            let data = if dsize & 0x8000_0000 != 0 {
                doff.to_le_bytes()[..size.min(4)].to_vec()
            } else if size == 0 {
                Vec::new()
            } else {
                let (dc, _) = self.cell(doff)?;
                if dc.len() >= 8 && &dc[..2] == b"db" {
                    let nseg = u16::from_le_bytes([dc[2], dc[3]]) as usize;
                    let (sl, _) = self.cell(u32::from_le_bytes(dc[4..8].try_into().unwrap()))?;
                    if sl.len() < 4 * nseg {
                        return None;
                    }
                    let mut data = Vec::new();
                    for j in 0..nseg {
                        let (seg, _) = self.cell(u32::from_le_bytes(sl[4 * j..4 * j + 4].try_into().unwrap()))?;
                        data.extend_from_slice(&seg[..seg.len().min(SEG)]);
                    }
                    data.truncate(size);
                    data
                } else {
                    if dc.len() < size {
                        return None;
                    }
                    dc[..size].to_vec()
                }
            };
            out.push(Value { name, typ, data });
        }
        Some(out)
    }

    /// lowercase path -> newest intact copy of each deleted key with a resolvable path.
    pub fn deleted_keys(&self) -> HashMap<String, Deleted> {
        let mut out: HashMap<String, Deleted> = HashMap::new();
        for (&off, &c) in &self.free {
            let Some(p) = self.path(off, 0) else { continue };
            if p.is_empty() {
                continue;
            }
            let Some(vals) = self.values(c) else { continue };
            let ts_bytes: [u8; 8] = match self.d.get(c + 8..c + 16) {
                Some(b) => b.try_into().unwrap(),
                None => continue,
            };
            let ts = u64::from_le_bytes(ts_bytes);
            let low = lower(&p);
            if out.get(&low).map(|x| ts <= x.ts).unwrap_or(false) {
                continue;
            }
            let flags = self.u16(c + 6);
            let access = self.u32(c + 16);
            let (skoff, cloff) = (self.u32(c + 4 + 44), self.u32(c + 4 + 48));
            let cllen = self.u16(c + 4 + 74) as usize;
            let mut class = None;
            if cllen > 0 && cloff != u32::MAX {
                if let Some((cc, _)) = self.cell(cloff) {
                    if cc.len() >= cllen {
                        class = Some(cc[..cllen].to_vec());
                    }
                }
            }
            let mut sd = None;
            if let Some((sk, _)) = self.cell(skoff) {
                if sk.len() >= 20 && &sk[..2] == b"sk" {
                    let n = u32::from_le_bytes(sk[16..20].try_into().unwrap()) as usize;
                    if 20 + n <= sk.len() {
                        sd = Some(sk[20..20 + n].to_vec());
                    }
                }
            }
            out.insert(low, Deleted { path: p, values: vals, ts, class, sd, flags, access, ts_bytes });
        }
        out
    }

    /// Class names from stale nk records in transaction logs. An old nk still knows its parent
    /// and the offset of its class-name cell, which often survives as a free cell.
    /// Returns lowercase path -> class bytes.
    pub fn classes_from_logs(&self, logs: &[&[u8]]) -> HashMap<String, Vec<u8>> {
        let mut out = HashMap::new();
        for l in logs {
            let mut i = 0;
            while i + 2 <= l.len() {
                if &l[i..i + 2] != b"nk" {
                    i += 1;
                    continue;
                }
                let nk = i;
                i += 2;
                if nk + 76 > l.len() {
                    break;
                }
                let nlen = u16::from_le_bytes([l[nk + 72], l[nk + 73]]) as usize;
                let cllen = u16::from_le_bytes([l[nk + 74], l[nk + 75]]) as usize;
                if cllen == 0 || nlen == 0 || nlen >= 256 || nk + 76 + nlen > l.len() {
                    continue;
                }
                let flags = u16::from_le_bytes([l[nk + 2], l[nk + 3]]);
                let raw = &l[nk + 76..nk + 76 + nlen];
                let name = if flags & 0x20 != 0 {
                    if !raw.is_ascii() { continue; }
                    String::from_utf8_lossy(raw).to_string()
                } else {
                    if nlen % 2 != 0 { continue; }
                    let w: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    match String::from_utf16(&w) { Ok(s) => s, Err(_) => continue }
                };
                let parent = u32::from_le_bytes(l[nk + 16..nk + 20].try_into().unwrap());
                let Some(pp) = self.path(parent, 0) else { continue };
                let cloff = u32::from_le_bytes(l[nk + 48..nk + 52].try_into().unwrap());
                let Some((cell, _)) = self.cell(cloff) else { continue };
                if cell.len() < cllen {
                    continue;
                }
                out.insert(lower(&format!("{pp}\\{name}")), cell[..cllen].to_vec());
            }
        }
        out
    }
}
