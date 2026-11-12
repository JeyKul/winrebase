//! Offline registry repair, independent of Windows APIs (runs in WinPE and on Linux).

pub mod hive;
pub mod log;
pub mod repair;
pub mod undelete;

pub use repair::{DeviceReset, Options, Report};

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
