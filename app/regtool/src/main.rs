//! regtool HIVE OUT [--wim WIM_HIVE] [--log FILE]... [--mums SHA1LIST] [--devreset auto|always|never]
//!
//! Runs the WinPE app's registry repair on the host, for testing against copied hives.

#[path = "../../src/reg/mod.rs"]
mod reg;

use std::collections::HashSet;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (mut wim, mut logs, mut mums, mut reset) = (None, Vec::new(), None, reg::DeviceReset::Auto);
    let mut pos = Vec::new();
    let mut i = 0;
    while i < a.len() {
        match a[i].as_str() {
            "--wim" => { i += 1; wim = Some(std::fs::read(&a[i]).expect("wim hive")); }
            "--log" => { i += 1; if let Ok(d) = std::fs::read(&a[i]) { logs.push(d); } }
            "--mums" => {
                i += 1;
                let s = std::fs::read_to_string(&a[i]).expect("mums");
                mums = Some(s.lines().filter_map(|l| {
                    let l = l.to_lowercase();
                    let p = l.find("./servicing/packages/")?;
                    l[p + 21..].strip_suffix(".mum").map(|x| x.to_string())
                }).collect::<HashSet<_>>());
            }
            "--devreset" => {
                i += 1;
                reset = match a[i].as_str() { "always" => reg::DeviceReset::Always, "never" => reg::DeviceReset::Never, _ => reg::DeviceReset::Auto };
            }
            x => pos.push(x.to_string()),
        }
        i += 1;
    }
    let primary = std::fs::read(&pos[0]).expect("hive");
    let lr: Vec<&[u8]> = logs.iter().map(|l| l.as_slice()).collect();
    let opts = reg::Options { drive: "C:".into(), installed_mums: mums, device_reset: reset };
    let t = std::time::Instant::now();
    let o = reg::process(&primary, &lr, wim.as_deref(), &opts).expect("process");
    println!("replay: {}", o.replay.describe());
    if !o.unreadable.is_empty() {
        println!("unreadable keys: {}", o.unreadable.len());
    }
    if let Some(r) = &o.report {
        println!("undeleted {}, from WIM {} keys / {} values, lost state {:?}, hw profile {:?}, driver keys {}, reinstall {}, device reset {}, classes from logs {}",
                 r.undeleted, r.keys_from_wim, r.values_from_wim, r.lost_state, r.hw_profile,
                 r.driver_keys_rebuilt, r.devices_reinstall, r.device_reset, r.classes_from_logs);
        if let Some(rep) = pos.get(2) {
            let s: String = r.log.iter().map(|(k, p, d)| format!("{k}\t{p}\t{d}\n")).collect();
            std::fs::write(rep, s).unwrap();
        }
    }
    match o.output {
        Some(b) => { std::fs::write(&pos[1], &b).unwrap(); println!("wrote {} bytes, {} keys", b.len(), o.keys); }
        None => println!("nothing to do"),
    }
    println!("{:.1}s", t.elapsed().as_secs_f64());
}
