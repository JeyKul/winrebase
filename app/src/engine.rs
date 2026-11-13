//! Analysis and repair. Rules match the Linux prototype (proto/), see docs/FINDINGS.md.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use crate::reg::{self, hive::{Key, Reader}};
use crate::wim::{Entry, Image, Wim};
use crate::win;

pub enum Ev {
    Log(String),
    /// overall fraction 0..1, status text
    Progress(f64, String),
}

pub type Sink = Box<dyn Fn(Ev) + Send>;

pub struct Out {
    sink: Sink,
    log_file: Option<std::fs::File>,
}

impl Out {
    pub fn new(sink: Sink) -> Out {
        let path = format!("{}winrebase.log", win::system_drive());
        let log_file = std::fs::OpenOptions::new().create(true).append(true).open(path).ok();
        Out { sink, log_file }
    }
    pub fn log(&mut self, s: impl Into<String>) {
        let s = s.into();
        if let Some(f) = &mut self.log_file {
            use std::io::Write;
            let _ = writeln!(f, "{s}");
        }
        (self.sink)(Ev::Log(s));
    }
    pub fn progress(&self, frac: f64, text: impl Into<String>) {
        (self.sink)(Ev::Progress(frac.clamp(0.0, 1.0), text.into()));
    }
}

/// Estimated time left from fraction done in the current phase.
fn eta(start: Instant, frac: f64) -> String {
    if frac < 0.02 {
        return String::new();
    }
    let left = start.elapsed().as_secs_f64() * (1.0 - frac) / frac;
    if left < 60.0 { format!(" — about {}s left", left as u64) } else { format!(" — about {} min left", (left / 60.0).ceil() as u64) }
}

// ------------------------------------------------------------------ discovery

#[derive(Clone, Debug)]
pub struct Install {
    pub root: String, // "C:\\"
    pub build: u32,
    pub ubr: u32,
    pub edition: String,
    pub name: String,
}

impl Install {
    pub fn label(&self) -> String {
        format!("{}  {}  ({})  {}.{}", &self.root[..2], self.name, self.edition, self.build, self.ubr)
    }
}

pub fn find_installs() -> Vec<Install> {
    let mut out = Vec::new();
    for d in win::drives() {
        let sw = format!("{d}Windows\\System32\\config\\SOFTWARE");
        if !win::exists(&sw) {
            continue;
        }
        let mut i = Install { root: d.clone(), build: 0, ubr: 0, edition: "?".into(), name: "Windows".into() };
        if let Some(k) = read_key(&sw, r"Microsoft\Windows NT\CurrentVersion") {
            i.build = k.string("CurrentBuild").and_then(|s| s.parse().ok()).unwrap_or(0);
            i.ubr = k.dword("UBR").unwrap_or(0);
            i.edition = k.string("EditionID").unwrap_or_default();
            i.name = k.string("ProductName").unwrap_or_default();
            if i.build >= 22000 {
                i.name = i.name.replace("Windows 10", "Windows 11");
            }
        }
        out.push(i);
    }
    out
}

#[derive(Clone, Debug)]
pub struct Source {
    pub path: String,
    pub image: Image,
}

impl Source {
    pub fn matches(&self, i: &Install) -> bool {
        self.image.build == i.build && self.image.spbuild == i.ubr
            && self.image.edition.eq_ignore_ascii_case(&i.edition)
    }
    pub fn label(&self, i: Option<&Install>) -> String {
        let m = match i {
            Some(i) if self.matches(i) => "  ✔ match",
            Some(_) => "  ✘ different build/edition",
            None => "",
        };
        format!("{}  [{}] {}  {}.{}{}", self.path, self.image.index, self.image.name,
                self.image.build, self.image.spbuild, m)
    }
}

/// Look for install.wim/esd and *.wim/*.esd in drive roots, \sources and one folder deep.
pub fn find_sources(out: &mut Out) -> Vec<Source> {
    let mut files = Vec::new();
    let mut isos = Vec::new();
    for d in win::drives() {
        let mut dirs = vec![d.clone(), format!("{d}sources\\")];
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                let skip = ["Windows", "Program Files", "Program Files (x86)", "ProgramData", "Users",
                            "$Recycle.Bin", "System Volume Information", "Recovery"];
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false)
                    && !skip.iter().any(|s| s.eq_ignore_ascii_case(&n)) {
                    dirs.push(format!("{d}{n}\\"));
                }
            }
        }
        for dir in dirs {
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    let n = e.file_name().to_string_lossy().to_lowercase();
                    if (n.ends_with(".wim") || n.ends_with(".esd")) && n != "boot.wim" && n != "winre.wim" {
                        files.push(format!("{dir}{}", e.file_name().to_string_lossy()));
                    }
                    if n.ends_with(".iso") {
                        isos.push(format!("{dir}{}", e.file_name().to_string_lossy()));
                    }
                }
            }
        }
    }
    for iso in isos {
        match mount_iso(&iso) {
            Ok((d, new)) => {
                if new {
                    out.log(format!("  mounted {iso} as {}", &d[..2]));
                }
                files.extend(images_on(&d));
            }
            Err(e) => out.log(format!("  can't mount {iso}: {e}")),
        }
    }
    files.sort();
    files.dedup();
    let mut out_v = Vec::new();
    for f in files {
        match Wim::open(&f) {
            Ok(w) => {
                for image in w.images() {
                    out_v.push(Source { path: f.clone(), image });
                }
            }
            Err(e) => out.log(format!("  skipped {f}: {e}")),
        }
    }
    out_v
}

/// Mounted .iso files (path -> drive root), so a second search doesn't attach them again.
static MOUNTED: std::sync::Mutex<Vec<(String, String)>> = std::sync::Mutex::new(Vec::new());

/// Attach an .iso; returns (drive root, newly mounted).
pub fn mount_iso(path: &str) -> Result<(String, bool), String> {
    let mut m = MOUNTED.lock().unwrap();
    if let Some((_, d)) = m.iter().find(|(p, _)| p.eq_ignore_ascii_case(path)) {
        return Ok((d.clone(), false));
    }
    let d = win::mount_iso(path)?;
    m.push((path.to_string(), d.clone()));
    Ok((d, true))
}

/// install.wim/esd of a Windows ISO (or any *.wim/*.esd in its root and \sources).
pub fn images_on(drive: &str) -> Vec<String> {
    let mut out = Vec::new();
    for dir in [drive.to_string(), format!("{drive}sources\\")] {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_lowercase();
                if (n.ends_with(".wim") || n.ends_with(".esd")) && n != "boot.wim" && n != "winre.wim" {
                    out.push(format!("{dir}{}", e.file_name().to_string_lossy()));
                }
            }
        }
    }
    out
}

// ------------------------------------------------------------------ rules

/// Live state Windows rewrites itself; never repaired from the WIM.
fn excluded(p: &str) -> bool {
    const PREFIX: &[&str] = &[
        "system32\\config\\", "system32\\catroot2\\", "system32\\logfiles\\", "logs\\", "panther\\",
        "temp\\", "prefetch\\", "softwaredistribution\\", "serviceprofiles\\", "system32\\smi\\store\\",
        "system32\\wbem\\repository\\", "winsxs\\filemaps\\", "servicing\\sessions\\", "setup\\state\\",
        "system32\\sru\\", "system32\\winevt\\logs\\",
    ];
    const EXACT: &[&str] = &[
        "winsxs\\migration.xml", "winsxs\\pending.xml", "system32\\recovery\\reagent.xml",
        "system32\\perfc007.dat", "system32\\perfc009.dat", "system32\\perfh007.dat",
        "system32\\perfh009.dat", "system32\\perfd007.dat", "system32\\perfd009.dat",
        "system32\\perfi007.dat", "system32\\perfi009.dat",
    ];
    PREFIX.iter().any(|x| p.starts_with(x)) || EXACT.contains(&p) || p.ends_with(".log") || p.ends_with(".etl")
}

/// Hives restored from the WIM only when the file is gone completely.
const RESTORABLE_HIVES: &[&str] = &[
    "system32\\config\\components", "system32\\config\\elam", "system32\\config\\drivers",
    "system32\\config\\bcd-template", "system32\\config\\default",
];

/// Files Windows moves after setup: WIM path -> volume-relative new location.
const KNOWN_MOVES: &[(&str, &str)] = &[("system32\\recovery\\winre.wim", "Recovery\\WindowsRE\\Winre.wim")];

// ------------------------------------------------------------------ plan

#[derive(Default)]
pub struct Plan {
    pub root: String,
    pub image: i32,
    pub wim_path: String,
    pub full_mode: bool,
    pub unmatched: bool,
    pub mkdirs: Vec<(String, Vec<u8>)>,
    pub delete: Vec<String>,
    pub extract: Vec<String>,
    pub links: Vec<(String, String)>, // (new, existing) relative to root
    pub extract_bytes: u64,
    pub hives_replace: Vec<String>,
    /// hives that will be rewritten
    pub reg_changes: Vec<String>,
    pub device_reset: bool,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.mkdirs.is_empty() && self.extract.is_empty() && self.links.is_empty() && self.reg_changes.is_empty()
    }
}

fn log_registry(items: &[RegItem], out: &mut Out) {
    for it in items {
        if it.summary.is_empty() {
            out.log(format!("  {:<10} ok", it.hive));
            continue;
        }
        out.log(format!("  {:<10} {}", it.hive, it.summary[0]));
        for s in &it.summary[1..] {
            out.log(format!("  {:<10} {s}", ""));
        }
    }
}

struct Ctx {
    cbs: Option<HashSet<String>>,
    owned: Option<HashSet<String>>, // components with an owner (c! value)
    comp_keys: Option<HashSet<String>>,
}

fn load_ctx(root: &str, out: &mut Out) -> Ctx {
    let mut c = Ctx { cbs: None, owned: None, comp_keys: None };
    let sw = format!("{root}Windows\\System32\\config\\SOFTWARE");
    match read_key(&sw, r"Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages") {
        Some(k) => {
            let s: HashSet<String> = k.subs.keys().cloned().collect();
            out.log(format!("  servicing database: {} packages", s.len()));
            c.cbs = Some(s);
        }
        None => out.log("  SOFTWARE hive not readable — package rules off"),
    }
    let cp = format!("{root}Windows\\System32\\config\\COMPONENTS");
    if win::exists(&cp) {
        match read_key(&cp, r"DerivedData\Components") {
            Some(k) => {
                let mut keys = HashSet::new();
                let mut owned = HashSet::new();
                for (l, sub) in &k.subs {
                    if sub.values.iter().any(|v| v.name.starts_with("c!")) {
                        owned.insert(l.clone());
                    }
                    keys.insert(l.clone());
                }
                out.log(format!("  component store: {} components, {} installed", keys.len(), owned.len()));
                c.owned = Some(owned);
                c.comp_keys = Some(keys);
            }
            None => out.log("  COMPONENTS hive not readable"),
        }
    } else {
        out.log("  COMPONENTS hive is missing");
    }
    c
}

// ------------------------------------------------------------------ registry

/// Hive file + its logs, logs replayed in memory. Read only, never through RegLoadKey (the
/// WinPE kernel would write to the broken hive).
fn read_hive(path: &str) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
    let primary = std::fs::read(path).ok()?;
    let logs: Vec<Vec<u8>> = ["LOG1", "LOG2"].iter()
        .filter_map(|e| std::fs::read(format!("{path}.{e}")).ok()).collect();
    Some((primary, logs))
}

/// One key (values + direct subkeys, shallow) of an offline hive.
fn read_key(path: &str, key: &str) -> Option<Key> {
    let (primary, logs) = read_hive(path)?;
    let lr: Vec<&[u8]> = logs.iter().map(|l| l.as_slice()).collect();
    let (bytes, _) = reg::log::replay(&primary, &lr).ok()?;
    Reader::new(&bytes).ok()?.find(key)
}

/// Hives repaired against the WIM, and hives that only get their logs replayed.
const WIM_HIVES: &[&str] = &["SYSTEM", "SOFTWARE", "DEFAULT"];
const LOG_HIVES: &[&str] = &["SECURITY", "SAM", "COMPONENTS", "DRIVERS", "ELAM", "BBI"];

pub struct RegItem {
    pub hive: String,
    pub summary: Vec<String>,
    pub changes: bool,
}

/// Registered package manifests (ProgramData\\Microsoft\\Windows\\AppRepository\\<full name>.xml).
fn read_app_manifests(root: &str) -> Vec<(String, String)> {
    let Ok(rd) = std::fs::read_dir(format!("{root}ProgramData\\Microsoft\\Windows\\AppRepository")) else { return Vec::new() };
    rd.flatten().filter_map(|e| {
        let n = e.file_name().to_string_lossy().to_string();
        let stem = n.strip_suffix(".xml")?.to_string();
        let b = std::fs::read(e.path()).ok()?;
        Some((stem, String::from_utf8_lossy(&b).to_string()))
    }).collect()
}

/// Profile folders with a user hive, and the account each belongs to.
fn find_profiles(root: &str, drive: &str, out: &mut Out) -> Vec<reg::Profile> {
    let mut v = Vec::new();
    let Ok(rd) = std::fs::read_dir(format!("{root}Users")) else { return v };
    for e in rd.flatten() {
        let Ok(meta) = e.metadata() else { continue };
        if !meta.is_dir() {
            continue;
        }
        let name = e.file_name().to_string_lossy().to_string();
        let Ok(d) = std::fs::read(e.path().join("NTUSER.DAT")) else { continue };
        let Some(sid) = reg::repair::user_hive_sid(&d) else { continue };
        let created = meta.created().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs()).unwrap_or(u64::MAX);
        out.log(format!("  profile {name}: {}", reg::repair::sid_string(&sid)));
        v.push(reg::Profile { path: format!("{drive}\\Users\\{name}"), sid, created });
    }
    v
}

fn installed_mums(root: &str) -> Option<HashSet<String>> {
    let rd = std::fs::read_dir(format!("{root}Windows\\servicing\\Packages")).ok()?;
    Some(rd.flatten().filter_map(|e| {
        let n = e.file_name().to_string_lossy().to_lowercase();
        n.strip_suffix(".mum").map(|x| x.to_string())
    }).collect())
}

/// Check (apply = false) or repair (apply = true) the registry hives of `root`.
pub fn registry(root: &str, wim_path: &str, image: i32, unmatched: bool, device_reset: bool, apply: bool,
                out: &mut Out) -> Result<Vec<RegItem>, String> {
    let cfg = format!("{root}Windows\\System32\\config\\");
    let work = format!("{}winrebase\\wim\\", win::system_drive());
    if !unmatched {
        out.progress(0.0, "Reading registry hives from the WIM…");
        let paths: Vec<String> = WIM_HIVES.iter().map(|h| format!("Windows\\System32\\config\\{h}")).collect();
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).map_err(|e| format!("{work}: {e}"))?;
        Wim::open(wim_path)?.extract(image, &work, &paths, &mut |_, _| {})
            .map_err(|e| format!("extracting the registry hives from the WIM: {e}"))?;
    } else {
        out.log("  unmatched WIM: registry is only checked for damaged logs, not compared");
    }
    let drive = read_key(&format!("{cfg}SOFTWARE"), r"Microsoft\Windows NT\CurrentVersion")
        .and_then(|k| k.string("SystemRoot")).and_then(|s| s.get(..2).map(|x| x.to_uppercase()))
        .unwrap_or_else(|| "C:".into());
    let profiles = find_profiles(root, &drive, out);
    let (r2, d2) = (root.to_string(), drive.clone());
    let exists = std::sync::Arc::new(move |p: &str| {
        // "C:\Program Files\…" as the installation sees it -> this drive
        match p.get(..2) {
            Some(d) if d.eq_ignore_ascii_case(&d2) => win::exists(&format!("{}{}", r2, p[2..].trim_start_matches('\\'))),
            _ => true,
        }
    });
    let app_manifests = read_app_manifests(root);
    let opts = reg::Options {
        app_manifests,
        exists: Some(exists),
        profiles,
        drive,
        installed_mums: installed_mums(root),
        device_reset: if device_reset { reg::DeviceReset::Always } else { reg::DeviceReset::Auto },
    };
    let backup = format!("{root}Windows\\winrebase-backup\\{}\\config\\", stamp());
    let all: Vec<(&str, bool)> = WIM_HIVES.iter().map(|h| (*h, !unmatched))
        .chain(LOG_HIVES.iter().map(|h| (*h, false))).collect();
    let mut items = Vec::new();
    for (n, (hive, compare)) in all.iter().enumerate() {
        out.progress(0.1 + 0.85 * n as f64 / all.len() as f64, format!("Registry: {hive}…"));
        let path = format!("{cfg}{hive}");
        let mut item = RegItem { hive: hive.to_string(), summary: Vec::new(), changes: false };
        let Some((primary, logs)) = read_hive(&path) else {
            if win::exists(&path) || *compare {
                item.summary.push("can't be read".into());
                items.push(item);
            }
            continue;
        };
        let wim = if *compare { std::fs::read(format!("{work}Windows\\System32\\config\\{hive}")).ok() } else { None };
        let lr: Vec<&[u8]> = logs.iter().map(|l| l.as_slice()).collect();
        let o = match reg::process(&primary, &lr, wim.as_deref(), &opts) {
            Ok(o) => o,
            Err(e) => {
                item.summary.push(format!("can't be processed: {e}"));
                items.push(item);
                continue;
            }
        };
        if o.replay.changed() {
            item.summary.push(format!("logs: {}", o.replay.describe()));
        }
        if !o.unreadable.is_empty() {
            item.summary.push(format!("{} damaged keys left out", o.unreadable.len()));
        }
        if let Some(r) = &o.report {
            if r.undeleted > 0 { item.summary.push(format!("{} deleted keys recovered", r.undeleted)); }
            if r.keys_from_wim + r.values_from_wim > 0 {
                item.summary.push(format!("{} keys / {} values added from the WIM", r.keys_from_wim, r.values_from_wim));
            }
            for l in &r.lost_state { item.summary.push(format!("lost database restored: {l}")); }
            if let Some(p) = r.hw_profile { item.summary.push(format!("hardware profile {p:04} rebuilt")); }
            if r.driver_keys_rebuilt > 0 { item.summary.push(format!("{} driver keys rebuilt", r.driver_keys_rebuilt)); }
            if r.devices_reinstall > 0 { item.summary.push(format!("{} devices reinstalled on next boot", r.devices_reinstall)); }
            if r.device_reset { item.summary.push("clean device start: Windows detects all hardware again".into()); }
            if r.classes_from_logs > 0 { item.summary.push(format!("{} class names recovered (Lsa boot key)", r.classes_from_logs)); }
            if r.appx_entries > 0 { item.summary.push(format!("{} per-user app registrations rebuilt", r.appx_entries)); }
            if r.capauthz_entries > 0 { item.summary.push(format!("{} app capability entries rebuilt", r.capauthz_entries)); }
            if r.profiles_fixed > 0 { item.summary.push(format!("{} user profile entries repaired", r.profiles_fixed)); }
            if let Some(n) = &r.computer_name { item.summary.push(format!("computer name restored: {n}")); }
        }
        item.changes = o.output.is_some();
        if apply {
            if let Some(bytes) = &o.output {
                write_hive(&path, bytes, &backup, hive)?;
                item.summary.push(format!("written ({} MB), original in {backup}", bytes.len() / 1_000_000));
                if let Some(r) = &o.report {
                    let rep: String = r.log.iter().map(|(k, p, d)| format!("{k}\t{p}\t{d}\r\n")).collect();
                    let _ = std::fs::write(format!("{backup}{hive}.repair.txt"), rep);
                }
            }
        }
        items.push(item);
    }
    let _ = std::fs::remove_dir_all(&work);
    out.progress(1.0, "Registry done");
    Ok(items)
}

/// Back up hive + logs, write the new hive next to it, swap it in, empty the logs.
fn write_hive(path: &str, bytes: &[u8], backup: &str, hive: &str) -> Result<(), String> {
    std::fs::create_dir_all(backup).map_err(|e| format!("backup folder: {e}"))?;
    for ext in ["", ".LOG1", ".LOG2"] {
        let f = format!("{path}{ext}");
        if win::exists(&f) {
            std::fs::copy(&f, format!("{backup}{hive}{ext}")).map_err(|e| format!("backup {f}: {e}"))?;
        }
    }
    let tmp = format!("{path}.winrebase-new");
    std::fs::write(&tmp, bytes).map_err(|e| format!("write {tmp}: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("replace {path}: {e}"))?;
    for ext in [".LOG1", ".LOG2"] {
        let f = format!("{path}{ext}");
        if win::exists(&f) {
            std::fs::OpenOptions::new().write(true).truncate(true).open(&f)
                .map_err(|e| format!("empty {f}: {e}"))?;
        }
    }
    Ok(())
}

fn stamp() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    format!("{y:04}{m:02}{d:02}-{:02}{:02}{:02}", rem / 3600, rem / 60 % 60, rem % 60)
}

pub fn analyze(root: &str, src: &Source, unmatched: bool, device_reset: bool, out: &mut Out) -> Result<Plan, String> {
    let t0 = Instant::now();
    out.progress(0.0, "Reading WIM…");
    out.log(format!("Source: {}", src.label(None)));
    let wim = Wim::open(&src.path)?;
    let entries = wim.list(src.image.index, "\\Windows")?;
    out.log(format!("  {} entries under \\Windows in the image", entries.len()));

    out.log("Reading servicing state of the installation…");
    let ctx = load_ctx(root, out);

    // existing paths on disk
    out.progress(0.02, "Checking which files exist…");
    let mut by_path: HashMap<String, &Entry> = HashMap::new();
    let mut groups: HashMap<u64, Vec<&Entry>> = HashMap::new();
    for e in &entries {
        by_path.insert(e.path.to_lowercase(), e);
        if !e.is_dir() && e.nlinks > 1 {
            groups.entry(e.link_group).or_default().push(e);
        }
    }
    let disk: HashMap<String, Option<(u32, u64)>> = entries.iter()
        .map(|e| (e.path.to_lowercase(), win::file_info(&format!("{root}{}", e.path))))
        .collect();

    // massive damage: rules that rely on WinSxS / COMPONENTS can't be trusted
    let sxs_dirs: Vec<&Entry> = entries.iter()
        .filter(|e| e.is_dir() && e.path.to_lowercase().starts_with("windows\\winsxs\\")
                && e.path.matches('\\').count() == 2)
        .collect();
    let sxs_missing = sxs_dirs.iter().filter(|e| disk[&e.path.to_lowercase()].is_none()).count();
    let full_mode = unmatched || ctx.owned.is_none()
        || (sxs_dirs.len() > 0 && sxs_missing * 2 > sxs_dirs.len());
    if full_mode {
        out.log(format!("Full restore mode ({}): every Windows file from the WIM is restored.",
                        if unmatched { "unmatched WIM allowed" }
                        else if ctx.owned.is_none() { "component store unreadable" }
                        else { "more than half of WinSxS is gone" }));
    }

    // hash files that exist with the right size
    let to_hash: u64 = entries.iter()
        .filter(|e| !e.is_dir() && !e.is_reparse())
        .filter(|e| matches!(disk[&e.path.to_lowercase()], Some((a, s)) if a & 0x10 == 0 && s == e.size))
        .map(|e| e.size).sum();
    let mut hasher = win::Hasher::new();
    let mut hashed = 0u64;
    let th = Instant::now();
    let mut last = Instant::now();
    let mut good: HashSet<String> = HashSet::new();
    let mut need: Vec<&Entry> = Vec::new();
    let mut skipped: HashMap<&'static str, usize> = HashMap::new();

    for e in &entries {
        if e.is_dir() || e.is_reparse() {
            continue;
        }
        let rel = e.path.to_lowercase();
        let wrel = rel.trim_start_matches("windows\\").to_string();
        let on_disk = disk[&rel];
        let mut same = false;
        if let Some((a, s)) = on_disk {
            if a & 0x10 == 0 && s == e.size {
                let path = format!("{root}{}", e.path);
                let mut cb = |n: u64| {
                    hashed += n;
                    if last.elapsed().as_millis() > 250 {
                        last = Instant::now();
                        let f = if to_hash > 0 { hashed as f64 / to_hash as f64 } else { 1.0 };
                        out.progress(0.05 + 0.90 * f, format!("Comparing files with the WIM… {:.0}%{}", f * 100.0, eta(th, f)));
                    }
                };
                same = e.size == 0 || hasher.sha1(&path, &mut cb).map(|h| h == e.sha1).unwrap_or(false);
            }
        }
        if same {
            good.insert(rel);
            continue;
        }
        // decide whether this difference is damage
        if excluded(&wrel) {
            let hive_gone = on_disk.is_none() && RESTORABLE_HIVES.contains(&wrel.as_str());
            // unmatched: WinSxS comes from the WIM, so its component database must too
            let components = unmatched && wrel == "system32\\config\\components";
            if !(hive_gone || components) {
                *skipped.entry("live state (excluded)").or_default() += 1;
                continue;
            }
        }
        if let Some((_, to)) = KNOWN_MOVES.iter().find(|(f, _)| *f == wrel) {
            if win::exists(&format!("{root}{to}")) {
                *skipped.entry("moved by Windows").or_default() += 1;
                continue;
            }
        }
        let parts: Vec<&str> = wrel.split('\\').collect();
        if !unmatched && parts.len() == 3 && parts[0] == "servicing" && parts[1] == "packages" {
            let pkg = parts[2].rsplit_once('.').map(|x| x.0).unwrap_or(parts[2]);
            if let Some(cbs) = &ctx.cbs {
                if !cbs.contains(pkg) {
                    *skipped.entry("package removed by Windows").or_default() += 1;
                    continue;
                }
            }
        }
        if !full_mode {
            if parts.len() >= 3 && parts[0] == "winsxs" {
                let dir = format!("windows\\winsxs\\{}", parts[1]);
                if by_path.get(&dir).is_some() && disk.get(&dir).map(|d| d.is_none()).unwrap_or(false) {
                    *skipped.entry("component removed by Windows").or_default() += 1;
                    continue;
                }
            }
            if let (Some(owned), Some(g)) = (&ctx.owned, groups.get(&e.link_group).filter(|_| e.nlinks > 1)) {
                let comps: Vec<String> = g.iter()
                    .filter_map(|x| {
                        let l = x.path.to_lowercase();
                        let p: Vec<&str> = l.split('\\').collect();
                        (p.len() >= 4 && p[1] == "winsxs").then(|| p[2].to_string())
                    }).collect();
                if !comps.is_empty() && !comps.iter().any(|c| owned.contains(c)) {
                    *skipped.entry("component not installed (staged)").or_default() += 1;
                    continue;
                }
            }
        }
        need.push(e);
    }

    // turn needed files into actions
    let mut plan = Plan { root: root.to_string(), image: src.image.index, wim_path: src.path.clone(),
                          full_mode, unmatched, ..Default::default() };
    for e in &need {
        let rel = e.path.to_lowercase();
        if disk[&rel].is_some() {
            plan.delete.push(e.path.clone());
        }
        let twin = (e.nlinks > 1).then(|| groups.get(&e.link_group)).flatten()
            .and_then(|g| g.iter().find(|x| good.contains(&x.path.to_lowercase())));
        match twin {
            Some(t) => plan.links.push((e.path.clone(), t.path.clone())),
            None => {
                plan.extract.push(e.path.clone());
                plan.extract_bytes += e.size;
                if rel.starts_with("windows\\system32\\config\\") {
                    plan.hives_replace.push(e.path.clone());
                }
            }
        }
    }
    // directories that are gone (parents first)
    let mut dirs: Vec<&Entry> = entries.iter()
        .filter(|e| e.is_dir() && disk[&e.path.to_lowercase()].is_none())
        .filter(|e| {
            let w = e.path.to_lowercase();
            let w = w.trim_start_matches("windows\\");
            !excluded(&format!("{w}\\"))
        })
        .filter(|e| {
            if full_mode { return true; }
            let l = e.path.to_lowercase();
            let p: Vec<&str> = l.split('\\').collect();
            // folders of removed components stay removed
            !(p.len() >= 3 && p[1] == "winsxs" && disk.get(&format!("windows\\winsxs\\{}", p[2]))
                .map(|d| d.is_none()).unwrap_or(false) && p.len() > 2)
        })
        .collect();
    // in normal mode, missing component folders are only created when a file needs them
    if !full_mode {
        let needed: HashSet<String> = need.iter()
            .flat_map(|e| {
                let mut v = Vec::new();
                let mut p = e.path.to_lowercase();
                while let Some((parent, _)) = p.rsplit_once('\\') {
                    v.push(parent.to_string());
                    p = parent.to_string();
                }
                v
            }).collect();
        dirs.retain(|d| {
            let l = d.path.to_lowercase();
            needed.contains(&l) || !l.starts_with("windows\\winsxs\\")
        });
    }
    dirs.sort_by_key(|e| e.path.matches('\\').count());
    plan.mkdirs = dirs.iter().map(|e| (e.path.clone(), e.sd.clone())).collect();

    out.progress(1.0, "Analysis done");
    if plan.full_mode {
        out.log("  (full restore mode)");
    }
    out.log(format!("Analysis took {:.0}s.", t0.elapsed().as_secs_f64()));
    out.log(format!("  files identical to the WIM: {}", good.len()));
    for (r, n) in &skipped {
        out.log(format!("  not touched — {r}: {n}"));
    }
    out.log(format!("  to restore: {} files ({:.1} GB) from the WIM, {} re-linked to intact copies, {} folders",
                    plan.extract.len(), plan.extract_bytes as f64 / 1e9, plan.links.len(), plan.mkdirs.len()));
    out.log(format!("  of these, {} replace damaged files", plan.delete.len()));
    let mut top: HashMap<String, usize> = HashMap::new();
    for p in plan.extract.iter().chain(plan.links.iter().map(|x| &x.0)) {
        let k: Vec<&str> = p.split('\\').take(3).collect();
        *top.entry(k.join("\\")).or_default() += 1;
    }
    let mut top: Vec<_> = top.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1));
    for (k, n) in top.iter().take(12) {
        out.log(format!("     {n:7}  {k}"));
    }
    drop(wim);

    out.log("Checking the registry…");
    let items = registry(root, &src.path, src.image.index, unmatched, device_reset, false, out)?;
    log_registry(&items, out);
    plan.reg_changes = items.iter().filter(|i| i.changes).map(|i| i.hive.clone()).collect();
    plan.device_reset = device_reset;
    out.log(format!("  hives to repair: {}", if plan.reg_changes.is_empty() { "none".into() } else { plan.reg_changes.join(", ") }));
    Ok(plan)
}

// ------------------------------------------------------------------ repair

pub fn repair(plan: &Plan, out: &mut Out) -> Result<(), String> {
    let root = &plan.root;
    let t0 = Instant::now();
    let mut errors = 0usize;

    out.log(format!("Creating {} folders…", plan.mkdirs.len()));
    for (p, sd) in &plan.mkdirs {
        if let Err(e) = win::mkdir_sd(&format!("{root}{p}"), sd) {
            errors += 1;
            if errors < 20 { out.log(format!("  ! {e}")); }
        }
    }

    out.log(format!("Removing {} damaged files…", plan.delete.len()));
    for p in &plan.delete {
        if let Err(e) = win::delete_file(&format!("{root}{p}")) {
            errors += 1;
            if errors < 20 { out.log(format!("  ! {e}")); }
        }
    }

    if !plan.extract.is_empty() {
        out.log(format!("Extracting {} files from the WIM…", plan.extract.len()));
        let wim = Wim::open(&plan.wim_path)?;
        let te = Instant::now();
        let mut last = Instant::now();
        let mut cb = |done: u64, total: u64| {
            if last.elapsed().as_millis() > 250 {
                last = Instant::now();
                let f = if total > 0 { done as f64 / total as f64 } else { 0.0 };
                out.progress(0.05 + 0.85 * f, format!("Restoring files… {:.0}%{}", f * 100.0, eta(te, f)));
            }
        };
        wim.extract(plan.image, root, &plan.extract, &mut cb)?;
    }

    out.log(format!("Re-linking {} files to intact copies…", plan.links.len()));
    for (new, existing) in &plan.links {
        if let Err(e) = win::hardlink(&format!("{root}{new}"), &format!("{root}{existing}")) {
            errors += 1;
            if errors < 20 { out.log(format!("  ! {e}")); }
        }
    }
    if !plan.reg_changes.is_empty() {
        out.log("Repairing the registry…");
        match registry(root, &plan.wim_path, plan.image, plan.unmatched, plan.device_reset, true, out) {
            Ok(items) => log_registry(&items, out),
            Err(e) => {
                errors += 1;
                out.log(format!("  ! registry: {e}"));
            }
        }
    }
    out.progress(0.92, "Checking boot files…");
    boot_check(plan, out);

    out.progress(1.0, "Done");
    out.log(format!("Repair finished in {:.0}s with {errors} error(s).", t0.elapsed().as_secs_f64()));
    if errors > 0 {
        out.log("Some steps failed — see above. Run Analyze again to see what is left.");
    }
    Ok(())
}

/// Make sure the EFI system partition has Windows boot files; rebuild with bcdboot if not
/// (always in unmatched mode).
fn boot_check(plan: &Plan, out: &mut Out) {
    let windir = format!("{}Windows", plan.root);
    let Some(letter) = win::free_drive_letter() else {
        out.log("  no free drive letter for the EFI partition — skipped boot check");
        return;
    };
    let (rc, _) = win::run("mountvol", &[&letter, "/S"]);
    if rc != 0 {
        out.log("  no EFI system partition found (BIOS system?) — running bcdboot for BIOS");
        let (rc, o) = win::run("bcdboot", &[&windir, "/f", "BIOS"]);
        out.log(format!("  bcdboot: {} {o}", if rc == 0 { "ok" } else { "failed" }));
        return;
    }
    let esp = format!("{letter}\\");
    let ok = win::exists(&format!("{esp}EFI\\Microsoft\\Boot\\BCD"))
        && win::exists(&format!("{esp}EFI\\Microsoft\\Boot\\bootmgfw.efi"));
    if ok && !plan.unmatched {
        out.log("  EFI boot files present");
    } else {
        out.log(format!("  {} — rebuilding boot files with bcdboot",
                        if ok { "unmatched WIM" } else { "EFI boot files missing" }));
        let (rc, o) = win::run("bcdboot", &[&windir, "/s", &letter, "/f", "UEFI"]);
        out.log(format!("  bcdboot: {} {o}", if rc == 0 { "ok" } else { "failed" }));
    }
    win::run("mountvol", &[&letter, "/D"]);
}
