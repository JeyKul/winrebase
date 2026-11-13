//! Offline registry repair, independent of Windows APIs (runs in WinPE and on Linux).

pub mod capauthz;
pub mod hive;
pub mod log;
pub mod repair;
pub mod undelete;

pub use repair::{DeviceReset, Options, Profile, Report};

pub struct Outcome {
    pub replay: log::Replay,
    pub report: Option<Report>,
    /// new hive file, if anything changed
    pub output: Option<Vec<u8>>,
    pub keys: usize,
    /// keys that couldn't be read (left out, the WIM merge adds them back if it has them)
    pub unreadable: Vec<(String, String)>,
}

/// Replay the logs of `primary`; with `wim` (the same hive from the WIM) also repair it.
pub fn process(primary: &[u8], logs: &[&[u8]], wim: Option<&[u8]>, opts: &Options) -> Result<Outcome, String> {
    let (replayed, replay) = log::replay(primary, logs)?;
    let Some(wim) = wim else {
        let output = replay.changed().then(|| replayed);
        return Ok(Outcome { replay, report: None, output, keys: 0, unreadable: Vec::new() });
    };
    let mut wr = hive::Reader::new(wim)?;
    let wtree = wr.tree()?;
    let mut vr = hive::Reader::new(&replayed)?;
    let mut tree = vr.tree()?;
    let unreadable = std::mem::take(&mut vr.errors);
    let report = repair::repair(&mut tree, &replayed, logs, &wtree, opts);
    let mut keys = 0;
    let output = if report.actions() > 0 || replay.changed() || !unreadable.is_empty() {
        let (bytes, n, _) = hive::write(&tree, &replayed[..hive::BASE]);
        keys = n;
        Some(bytes)
    } else {
        None
    };
    Ok(Outcome { replay, report: Some(report), output, keys, unreadable })
}

#[cfg(test)]
mod tests {
    use super::hive::{self, Key, Reader, Value};
    use super::*;

    fn key(name: &str) -> Key {
        // minimal valid self-relative security descriptor
        Key { name: name.into(), sd: vec![1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], ..Default::default() }
    }

    fn sample() -> Key {
        let mut root = key("ROOT");
        root.flags = 0x2C;
        let mut a = key("Software");
        a.values.push(Value { name: "small".into(), typ: 4, data: 7u32.to_le_bytes().to_vec() });
        a.values.push(Value { name: "big".into(), typ: 3, data: (0..40_000u32).map(|i| i as u8).collect() });
        a.values.push(Value { name: "Ünïcode ключ".into(), typ: 1, data: hive::utf16z("x") });
        a.class = Some(b"c\0l\0s\0".to_vec());
        for i in 0..2500 {
            a.subs.insert(format!("k{i}"), key(&format!("K{i}")));
        }
        root.subs.insert("software".into(), a);
        root
    }

    fn base() -> Vec<u8> {
        let mut b = vec![0u8; hive::BASE];
        b[..4].copy_from_slice(b"regf");
        b
    }

    #[test]
    fn write_read_roundtrip() {
        let t = sample();
        let (bytes, n, _) = hive::write(&t, &base());
        assert_eq!(n, 2502);
        let mut r = Reader::new(&bytes).unwrap();
        let back = r.tree().unwrap();
        assert!(r.errors.is_empty());
        let a = back.get("SOFTWARE").unwrap();
        assert_eq!(a.subs.len(), 2500);
        assert_eq!(a.dword("small"), Some(7));
        assert_eq!(a.value("big").unwrap().data, t.get("software").unwrap().value("big").unwrap().data);
        assert!(a.value("Ünïcode ключ").is_some());
        assert_eq!(a.class.as_deref(), Some(&b"c\0l\0s\0"[..]));
        // checksum and clean sequence numbers
        assert_eq!(bytes[4..8], bytes[8..12]);
        assert_eq!(u32::from_le_bytes(bytes[0x1FC..0x200].try_into().unwrap()), hive::checksum(&bytes));
    }

    #[test]
    fn replay_refuses_gap() {
        let (mut bytes, _, _) = hive::write(&sample(), &base());
        bytes[4..8].copy_from_slice(&457u32.to_le_bytes()); // dirty: 457/456
        bytes[8..12].copy_from_slice(&456u32.to_le_bytes());
        let (out, r) = log::replay(&bytes, &[]).unwrap();
        assert!(r.dirty() && r.applied == 0);
        assert_eq!(out[4..8], out[8..12]);
    }

    #[test]
    fn healthy_hive_needs_nothing() {
        let t = sample();
        let (bytes, _, _) = hive::write(&t, &base());
        let opts = Options { drive: "C:".into(), installed_mums: None, device_reset: DeviceReset::Auto, profiles: vec![], exists: None, app_manifests: vec![], reset_servicing: false, vbs_off: false };
        let o = process(&bytes, &[], Some(&bytes), &opts).unwrap();
        assert_eq!(o.report.unwrap().actions(), 0);
        assert!(o.output.is_none());
    }

    #[test]
    fn missing_keys_come_from_wim() {
        let wim = sample();
        let mut vm = sample();
        vm.get_mut("Software").unwrap().subs.remove("k42");
        let (wb, _, _) = hive::write(&wim, &base());
        let (vb, _, _) = hive::write(&vm, &base());
        let opts = Options { drive: "C:".into(), installed_mums: None, device_reset: DeviceReset::Auto, profiles: vec![], exists: None, app_manifests: vec![], reset_servicing: false, vbs_off: false };
        let o = process(&vb, &[], Some(&wb), &opts).unwrap();
        assert_eq!(o.report.unwrap().keys_from_wim, 1);
        let out = o.output.unwrap();
        let back = Reader::new(&out).unwrap().tree().unwrap();
        assert!(back.get(r"Software\K42").is_some());
    }
}
