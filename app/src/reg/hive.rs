//! Registry hive files: read into a tree, write a fresh compact hive.
//!
//! Port of proto/hivecompact.py. Reading never touches the file through Windows (no
//! RegLoadKey), so a broken hive can't be "repaired" behind our back by the WinPE kernel.

use std::collections::HashMap;

pub const BASE: usize = 4096;
pub const SEG: usize = 16344;
const LEAF_MAX: usize = 1000;

#[derive(Clone, Debug)]
pub struct Value {
    pub name: String,
    pub typ: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct Key {
    pub name: String,
    pub flags: u16,
    pub ts: [u8; 8],
    pub access: u32,
    pub class: Option<Vec<u8>>,
    pub sd: Vec<u8>,
    pub values: Vec<Value>,
    /// lowercase name -> key
    pub subs: HashMap<String, Key>,
    /// came back by undelete or from the WIM in this run
    pub restored: bool,
    /// created from the WIM in this run (the machine's own copy wins later)
    pub from_wim: bool,
}

pub fn lower(s: &str) -> String {
    s.to_lowercase()
}

fn parts(path: &str) -> impl Iterator<Item = &str> {
    path.split('\\').filter(|p| !p.is_empty())
}

impl Key {
    /// Empty key with metadata (sd, class, flags…) taken from `like`.
    pub fn new_like(name: &str, like: &Key) -> Key {
        Key {
            name: name.to_string(),
            flags: like.flags & !0x2C,
            ts: like.ts,
            access: like.access,
            class: like.class.clone(),
            sd: like.sd.clone(),
            restored: true,
            ..Default::default()
        }
    }

    pub fn get(&self, path: &str) -> Option<&Key> {
        let mut k = self;
        for p in parts(path) {
            k = k.subs.get(&lower(p))?;
        }
        Some(k)
    }

    pub fn get_mut(&mut self, path: &str) -> Option<&mut Key> {
        let mut k = self;
        for p in parts(path) {
            k = k.subs.get_mut(&lower(p))?;
        }
        Some(k)
    }

    pub fn value(&self, name: &str) -> Option<&Value> {
        self.values.iter().find(|v| v.name.eq_ignore_ascii_case(name))
    }

    pub fn dword(&self, name: &str) -> Option<u32> {
        let v = self.value(name)?;
        Some(u32::from_le_bytes(v.data.get(..4)?.try_into().ok()?))
    }

    pub fn string(&self, name: &str) -> Option<String> {
        let v = self.value(name)?;
        let w: Vec<u16> = v.data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let n = w.iter().position(|&c| c == 0).unwrap_or(w.len());
        Some(String::from_utf16_lossy(&w[..n]))
    }

    pub fn set_value(&mut self, name: &str, typ: u32, data: Vec<u8>) {
        self.values.retain(|v| !v.name.eq_ignore_ascii_case(name));
        self.values.push(Value { name: name.to_string(), typ, data });
    }

    pub fn count(&self) -> usize {
        1 + self.subs.values().map(|c| c.count()).sum::<usize>()
    }

    /// Name of the current control set ("ControlSet001") for a SYSTEM hive.
    pub fn current_control_set(&self) -> Option<String> {
        let n = self.get("Select")?.dword("Current")?;
        Some(format!("ControlSet{n:03}"))
    }
}

pub fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16().chain(std::iter::once(0)).flat_map(|c| c.to_le_bytes()).collect()
}

// ------------------------------------------------------------------ reading

fn rd16(d: &[u8], o: usize) -> Result<u16, String> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or_else(|| format!("offset {o:#x} out of range"))
}

fn rd32(d: &[u8], o: usize) -> Result<u32, String> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).ok_or_else(|| format!("offset {o:#x} out of range"))
}

pub fn decode_name(raw: &[u8], compressed: bool) -> String {
    if compressed {
        raw.iter().map(|&b| b as char).collect()
    } else {
        let w: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&w)
    }
}

pub struct Reader<'a> {
    pub d: &'a [u8],
    pub root: u32,
    /// keys that couldn't be read (path, error); they're left out of the tree
    pub errors: Vec<(String, String)>,
}

impl<'a> Reader<'a> {
    pub fn new(d: &'a [u8]) -> Result<Reader<'a>, String> {
        if d.len() < BASE || &d[..4] != b"regf" {
            return Err("not a registry hive".into());
        }
        Ok(Reader { d, root: rd32(d, 0x24)?, errors: Vec::new() })
    }

    /// (start of cell data, cell data size)
    fn cell(&self, off: u32) -> Result<(usize, usize), String> {
        let c = BASE + off as usize;
        let sz = rd32(self.d, c)? as i32;
        let size = (sz.unsigned_abs() as usize).saturating_sub(4);
        if c + 4 + size > self.d.len() {
            return Err(format!("cell {off:#x} out of range"));
        }
        Ok((c + 4, size))
    }

    fn subkey_offsets(&self, off: u32, depth: u32) -> Result<Vec<u32>, String> {
        if depth > 8 {
            return Err("subkey index too deep".into());
        }
        let (c, _) = self.cell(off)?;
        let sig = self.d.get(c..c + 2).ok_or("short cell")?;
        let n = rd16(self.d, c + 2)? as usize;
        match sig {
            b"lf" | b"lh" => (0..n).map(|i| rd32(self.d, c + 4 + 8 * i)).collect(),
            b"li" => (0..n).map(|i| rd32(self.d, c + 4 + 4 * i)).collect(),
            b"ri" => {
                let mut out = Vec::new();
                for i in 0..n {
                    out.extend(self.subkey_offsets(rd32(self.d, c + 4 + 4 * i)?, depth + 1)?);
                }
                Ok(out)
            }
            _ => Err(format!("bad subkey list {:?}", String::from_utf8_lossy(sig))),
        }
    }

    fn value_data(&self, size: usize, off: u32) -> Result<Vec<u8>, String> {
        let (c, csz) = self.cell(off)?;
        if self.d.get(c..c + 2) == Some(b"db") && size > SEG {
            let nseg = rd16(self.d, c + 2)? as usize;
            let (lc, _) = self.cell(rd32(self.d, c + 4)?)?;
            let mut out = Vec::with_capacity(size);
            for i in 0..nseg {
                let (sc, ssz) = self.cell(rd32(self.d, lc + 4 * i)?)?;
                out.extend_from_slice(&self.d[sc..sc + ssz.min(SEG)]);
            }
            out.truncate(size);
            return Ok(out);
        }
        Ok(self.d[c..c + size.min(csz.max(size)).min(self.d.len() - c)].to_vec())
    }

    /// One key without its subkeys; returns (key, subkey offsets).
    pub fn key_shallow(&self, off: u32) -> Result<(Key, Vec<u32>), String> {
        let d = self.d;
        let (c, _) = self.cell(off)?;
        if d.get(c..c + 2) != Some(b"nk") {
            return Err(format!("no nk at {off:#x}"));
        }
        let flags = rd16(d, c + 2)?;
        let ts: [u8; 8] = d[c + 4..c + 12].try_into().unwrap();
        let access = rd32(d, c + 12)?;
        let (nsub, sublist) = (rd32(d, c + 20)?, rd32(d, c + 28)?);
        let (nval, vallist) = (rd32(d, c + 36)? as usize, rd32(d, c + 40)?);
        let (skoff, classoff) = (rd32(d, c + 44)?, rd32(d, c + 48)?);
        let (namelen, classlen) = (rd16(d, c + 72)? as usize, rd16(d, c + 74)? as usize);
        let raw = d.get(c + 76..c + 76 + namelen).ok_or("name out of range")?;
        let name = decode_name(raw, flags & 0x20 != 0);
        let mut class = None;
        if classlen > 0 && classoff != u32::MAX {
            let (cc, _) = self.cell(classoff)?;
            class = Some(d.get(cc..cc + classlen).ok_or("class out of range")?.to_vec());
        }
        let (sc, _) = self.cell(skoff)?;
        let sdlen = rd32(d, sc + 16)? as usize;
        let sd = d.get(sc + 20..sc + 20 + sdlen).ok_or("sd out of range")?.to_vec();
        let mut values = Vec::with_capacity(nval);
        if nval > 0 {
            let (vc, _) = self.cell(vallist)?;
            for i in 0..nval {
                let (v, _) = self.cell(rd32(d, vc + 4 * i)?)?;
                let vnl = rd16(d, v + 2)? as usize;
                let dsize = rd32(d, v + 4)?;
                let doff = rd32(d, v + 8)?;
                let vtype = rd32(d, v + 12)?;
                let vflags = rd16(d, v + 16)?;
                let vraw = d.get(v + 20..v + 20 + vnl).ok_or("value name out of range")?;
                let vname = decode_name(vraw, vflags & 1 != 0);
                let size = (dsize & 0x7FFF_FFFF) as usize;
                let data = if dsize & 0x8000_0000 != 0 {
                    doff.to_le_bytes()[..size.min(4)].to_vec()
                } else if size == 0 {
                    Vec::new()
                } else {
                    self.value_data(size, doff)?
                };
                values.push(Value { name: vname, typ: vtype, data });
            }
        }
        let subs = if nsub > 0 { self.subkey_offsets(sublist, 0)? } else { Vec::new() };
        Ok((Key { name, flags, ts, access, class, sd, values, ..Default::default() }, subs))
    }

    fn load(&mut self, off: u32, path: &str, depth: u32) -> Result<Key, String> {
        if depth > 512 {
            return Err("key nesting too deep".into());
        }
        let (mut k, subs) = self.key_shallow(off)?;
        let here = format!("{path}\\{}", k.name);
        for s in subs {
            match self.load(s, &here, depth + 1) {
                Ok(c) => {
                    k.subs.insert(lower(&c.name), c);
                }
                Err(e) => self.errors.push((here.clone(), e)),
            }
        }
        Ok(k)
    }

    /// Whole tree from the root key.
    pub fn tree(&mut self) -> Result<Key, String> {
        self.load(self.root, "", 0)
    }

    /// Key at `path` (no subkeys loaded), following the tree without loading it.
    pub fn find(&self, path: &str) -> Option<Key> {
        let mut off = self.root;
        let (mut k, mut subs) = self.key_shallow(off).ok()?;
        for p in parts(path) {
            let mut next = None;
            for s in &subs {
                if let Ok((c, cs)) = self.key_shallow(*s) {
                    if c.name.eq_ignore_ascii_case(p) {
                        next = Some((*s, c, cs));
                        break;
                    }
                }
            }
            let (o, c, cs) = next?;
            off = o;
            k = c;
            subs = cs;
        }
        let _ = off;
        k.subs = subs.iter().filter_map(|s| self.key_shallow(*s).ok())
            .map(|(c, _)| (lower(&c.name), c)).collect();
        Some(k)
    }
}

// ------------------------------------------------------------------ writing

/// RtlUpcaseUnicodeChar-like: only 1:1 mappings ('ß' stays 'ß').
fn up(c: char) -> char {
    let mut it = c.to_uppercase();
    let a = it.next().unwrap_or(c);
    if it.next().is_none() { a } else { c }
}

fn upname(s: &str) -> String {
    s.chars().map(up).collect()
}

fn lh_hash(name: &str) -> u32 {
    name.chars().fold(0u32, |h, c| h.wrapping_mul(37).wrapping_add(up(c) as u32))
}

fn enc_name(name: &str) -> (Vec<u8>, bool) {
    if name.chars().all(|c| (c as u32) < 0x100) {
        (name.chars().map(|c| c as u8).collect(), true)
    } else {
        (name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect(), false)
    }
}

struct Writer {
    bins: Vec<u8>,
    hbin_end: usize,
    sks: Vec<(u32, u32)>, // (offset, refcount), in creation order
    sk_index: HashMap<Vec<u8>, usize>,
    keys: usize,
}

impl Writer {
    fn alloc(&mut self, payload: &[u8]) -> u32 {
        let size = (payload.len() + 4 + 7) & !7;
        if self.bins.len() + size > self.hbin_end {
            self.new_hbin(size);
        }
        let off = self.bins.len() as u32;
        self.bins.extend_from_slice(&(-(size as i32)).to_le_bytes());
        self.bins.extend_from_slice(payload);
        self.bins.resize(off as usize + size, 0);
        off
    }

    fn close_hbin(&mut self) {
        if self.bins.len() < self.hbin_end {
            let rest = self.hbin_end - self.bins.len();
            self.bins.extend_from_slice(&(rest as i32).to_le_bytes());
            self.bins.resize(self.hbin_end, 0);
        }
    }

    fn new_hbin(&mut self, need: usize) {
        self.close_hbin();
        let hsize = 4096usize.max((need + 32 + 4095) / 4096 * 4096);
        let start = self.bins.len();
        self.hbin_end = start + hsize;
        self.bins.extend_from_slice(b"hbin");
        self.bins.extend_from_slice(&(start as u32).to_le_bytes());
        self.bins.extend_from_slice(&(hsize as u32).to_le_bytes());
        self.bins.resize(start + 32, 0);
    }

    fn patch(&mut self, off: u32, at: usize, bytes: &[u8]) {
        let p = off as usize + 4 + at;
        self.bins[p..p + bytes.len()].copy_from_slice(bytes);
    }

    fn write_value(&mut self, v: &Value) -> u32 {
        let (nraw, comp) = enc_name(&v.name);
        let size = v.data.len();
        let (dsize, doff) = if size <= 4 {
            let mut b = [0u8; 4];
            b[..size].copy_from_slice(&v.data);
            (size as u32 | 0x8000_0000, u32::from_le_bytes(b))
        } else if size <= SEG {
            (size as u32, self.alloc(&v.data))
        } else {
            // full-size segments, like Windows
            let segs: Vec<u32> = v.data.chunks(SEG).map(|ch| {
                let mut s = ch.to_vec();
                s.resize(SEG, 0);
                self.alloc(&s)
            }).collect();
            let list: Vec<u8> = segs.iter().flat_map(|s| s.to_le_bytes()).collect();
            let lst = self.alloc(&list);
            let mut db = b"db".to_vec();
            db.extend_from_slice(&(segs.len() as u16).to_le_bytes());
            db.extend_from_slice(&lst.to_le_bytes());
            (size as u32, self.alloc(&db))
        };
        let mut vk = b"vk".to_vec();
        vk.extend_from_slice(&(nraw.len() as u16).to_le_bytes());
        vk.extend_from_slice(&dsize.to_le_bytes());
        vk.extend_from_slice(&doff.to_le_bytes());
        vk.extend_from_slice(&v.typ.to_le_bytes());
        vk.extend_from_slice(&(comp as u16).to_le_bytes());
        vk.extend_from_slice(&0u16.to_le_bytes());
        vk.extend_from_slice(&nraw);
        self.alloc(&vk)
    }

    fn write_list(&mut self, entries: &[(String, u32)]) -> u32 {
        let leaf = |w: &mut Writer, chunk: &[(String, u32)]| {
            let mut body = b"lh".to_vec();
            body.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
            for (name, off) in chunk {
                body.extend_from_slice(&off.to_le_bytes());
                body.extend_from_slice(&lh_hash(name).to_le_bytes());
            }
            w.alloc(&body)
        };
        if entries.len() <= LEAF_MAX {
            return leaf(self, entries);
        }
        let leaves: Vec<u32> = entries.chunks(LEAF_MAX).map(|c| leaf(self, c)).collect();
        let mut ri = b"ri".to_vec();
        ri.extend_from_slice(&(leaves.len() as u16).to_le_bytes());
        for l in leaves {
            ri.extend_from_slice(&l.to_le_bytes());
        }
        self.alloc(&ri)
    }

    fn write_key(&mut self, k: &Key, parent: u32) -> (String, u32) {
        self.keys += 1;
        let (nraw, comp) = enc_name(&k.name);
        let flags = (k.flags & !0x20 & !0x02) | if comp { 0x20 } else { 0 }; // drop volatile/exit bits
        let mut placeholder = b"nk".to_vec();
        placeholder.resize(76, 0);
        placeholder.extend_from_slice(&nraw);
        let nk = self.alloc(&placeholder);
        let si = match self.sk_index.get(&k.sd) {
            Some(&i) => i,
            None => {
                let mut sk = b"sk".to_vec();
                sk.resize(16, 0);
                sk.extend_from_slice(&(k.sd.len() as u32).to_le_bytes());
                sk.extend_from_slice(&k.sd);
                let off = self.alloc(&sk);
                self.sks.push((off, 0));
                self.sk_index.insert(k.sd.clone(), self.sks.len() - 1);
                self.sks.len() - 1
            }
        };
        self.sks[si].1 += 1;
        let cls_off = match &k.class {
            Some(c) if !c.is_empty() => self.alloc(c),
            _ => u32::MAX,
        };
        let vals: Vec<u32> = k.values.iter().map(|v| self.write_value(v)).collect();
        let val_list = if vals.is_empty() { u32::MAX } else {
            let b: Vec<u8> = vals.iter().flat_map(|v| v.to_le_bytes()).collect();
            self.alloc(&b)
        };
        let mut children: Vec<(String, u32)> = k.subs.values().map(|c| self.write_key(c, nk)).collect();
        children.sort_by_cached_key(|(n, _)| upname(n));
        let sub_list = if children.is_empty() { u32::MAX } else { self.write_list(&children) };
        let max_sub = children.iter().map(|(n, _)| n.chars().count() * 2).max().unwrap_or(0) as u32;
        let max_vn = k.values.iter().map(|v| v.name.chars().count() * 2).max().unwrap_or(0) as u32;
        let max_vd = k.values.iter().map(|v| v.data.len()).max().unwrap_or(0) as u32;
        let cls_len = k.class.as_ref().map(|c| c.len()).unwrap_or(0) as u16;
        let mut h = Vec::with_capacity(76);
        h.extend_from_slice(b"nk");
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(&k.ts);
        for x in [k.access, parent, children.len() as u32, 0, sub_list, u32::MAX, vals.len() as u32,
                  val_list, self.sks[si].0, cls_off, max_sub, 0, max_vn, max_vd, 0] {
            h.extend_from_slice(&x.to_le_bytes());
        }
        h.extend_from_slice(&(nraw.len() as u16).to_le_bytes());
        h.extend_from_slice(&cls_len.to_le_bytes());
        self.patch(nk, 0, &h);
        (k.name.clone(), nk)
    }
}

pub fn checksum(base: &[u8]) -> u32 {
    let mut x = 0u32;
    for i in (0..508).step_by(4) {
        x ^= u32::from_le_bytes(base[i..i + 4].try_into().unwrap());
    }
    match x {
        u32::MAX => 0xFFFF_FFFE,
        0 => 1,
        x => x,
    }
}

/// Write `root` as a fresh, compact hive. `base_block` is the original's first 4 KiB.
/// Returns (file bytes, key count, security descriptor count).
pub fn write(root: &Key, base_block: &[u8]) -> (Vec<u8>, usize, usize) {
    let mut w = Writer { bins: Vec::new(), hbin_end: 0, sks: Vec::new(), sk_index: HashMap::new(), keys: 0 };
    w.new_hbin(0);
    let (_, root_off) = w.write_key(root, u32::MAX);
    // circular sk list + refcounts
    let n = w.sks.len();
    for i in 0..n {
        let (off, refs) = w.sks[i];
        let prev = w.sks[(i + n - 1) % n].0;
        let next = w.sks[(i + 1) % n].0;
        let mut b = Vec::new();
        for x in [prev, next, refs] {
            b.extend_from_slice(&x.to_le_bytes());
        }
        w.patch(off, 4, &b);
    }
    w.close_hbin();

    let mut base = base_block[..BASE].to_vec();
    let s1 = u32::from_le_bytes(base[4..8].try_into().unwrap());
    let s2 = u32::from_le_bytes(base[8..12].try_into().unwrap());
    let seq = s1.max(s2).wrapping_add(1);
    base[4..8].copy_from_slice(&seq.to_le_bytes());
    base[8..12].copy_from_slice(&seq.to_le_bytes());
    base[0x24..0x28].copy_from_slice(&root_off.to_le_bytes());
    base[0x28..0x2C].copy_from_slice(&(w.bins.len() as u32).to_le_bytes());
    base[0x90..0x94].copy_from_slice(&0u32.to_le_bytes()); // no pending transactions
    let c = checksum(&base);
    base[0x1FC..0x200].copy_from_slice(&c.to_le_bytes());
    let keys = w.keys;
    base.extend_from_slice(&w.bins);
    (base, keys, n)
}
