//! Analysis and repair. Rules match the Linux prototype (proto/), see docs/FINDINGS.md.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use crate::wim::{Entry, Image, Wim};
use crate::win::{self, Hive};

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
        if let Ok(h) = Hive::load("WR_PROBE", &sw) {
            if let Some(k) = h.key("Microsoft\\Windows NT\\CurrentVersion") {
                i.build = k.string("CurrentBuild").and_then(|s| s.parse().ok()).unwrap_or(0);
                i.ubr = k.dword("UBR").unwrap_or(0);
                i.edition = k.string("EditionID").unwrap_or_default();
                i.name = k.string("ProductName").unwrap_or_default();
                if i.build >= 22000 {
                    i.name = i.name.replace("Windows 10", "Windows 11");
                }
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
                }
            }
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
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.mkdirs.is_empty() && self.extract.is_empty() && self.links.is_empty()
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
    match Hive::load("WR_SOFTWARE", &sw) {
        Ok(h) => {
            if let Some(k) = h.key("Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages") {
                let s: HashSet<String> = k.subkeys().into_iter().map(|x| x.to_lowercase()).collect();
                out.log(format!("  servicing database: {} packages", s.len()));
                c.cbs = Some(s);
            }
        }
        Err(e) => out.log(format!("  SOFTWARE hive not loadable ({e}) — package rules off")),
    }
    let cp = format!("{root}Windows\\System32\\config\\COMPONENTS");
    if win::exists(&cp) {
        match Hive::load("WR_COMPONENTS", &cp) {
            Ok(h) => {
                if let Some(k) = h.key("DerivedData\\Components") {
                    let mut keys = HashSet::new();
                    let mut owned = HashSet::new();
                    for name in k.subkeys() {
                        let l = name.to_lowercase();
                        if let Some(s) = k.sub(&name) {
                            if s.value_names().iter().any(|v| v.starts_with("c!")) {
                                owned.insert(l.clone());
                            }
                        }
                        keys.insert(l);
                    }
                    out.log(format!("  component store: {} components, {} installed", keys.len(), owned.len()));
                    c.owned = Some(owned);
                    c.comp_keys = Some(keys);
                }
            }
            Err(e) => out.log(format!("  COMPONENTS hive not loadable ({e})")),
        }
    } else {
        out.log("  COMPONENTS hive is missing");
    }
    c
}

pub fn analyze(root: &str, src: &Source, unmatched: bool, out: &mut Out) -> Result<Plan, String> {
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
