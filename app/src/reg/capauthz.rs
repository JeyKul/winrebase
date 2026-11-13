//! Rebuild SOFTWARE\Microsoft\SecurityManager\CapAuthz\ApplicationsEx entries.
//!
//! Windows builds a packaged app's token from this entry (package SID + capability SIDs).
//! When it's gone the app doesn't start: Start menu, Settings, Terminal ("Das System kann
//! auf die Datei nicht zugreifen", AppModel-Runtime 206 GetPackageToken). Re-registering a
//! package rewrites it for Store apps but not for system apps, and it isn't in the WIM.
//!
//! Everything in it is derived from names (verified against a healthy install, 99 packages):
//! - PackageSid   = S-1-15-2-<first 7 DWORDs of SHA-256(lowercase family name, UTF-16LE)>
//! - capability   = S-1-15-3-<RID> for the 12 well-known ones, else
//!                  S-1-15-3-1024-<8 DWORDs of SHA-256(UPPERCASE name, UTF-16LE)>
//! - CapSids      = declared (Device)Capability names (+ cellularData/wifiData when internet
//!                  access is declared) + the package's own S-1-15-3-<package hash>
//! - DeviceCapSids = S-1-15-3-<GUID> from DeviceAccess\CapabilityMappings\<capability>\{GUID}
//! - CustomCapSids = hashed uap4:CustomCapability names
//! - blob = count (u32) + SIDs + as many zero bytes as the SIDs take
//!
//! Source of the declarations: ProgramData\Microsoft\Windows\AppRepository\<full name>.xml,
//! the registered copy of each manifest (outside \Windows, survives a broken install).

use std::collections::HashMap;

use super::hive::{lower, utf16z, Key};

const WELL_KNOWN: &[(&str, u32)] = &[
    ("internetclient", 1), ("internetclientserver", 2), ("privatenetworkclientserver", 3),
    ("pictureslibrary", 4), ("videoslibrary", 5), ("musiclibrary", 6), ("documentslibrary", 7),
    ("enterpriseauthentication", 8), ("sharedusercertificates", 9), ("removablestorage", 10),
    ("appointments", 11), ("contacts", 12),
];
/// declared, but never part of the token
const NOT_GRANTED: &[&str] = &["unvirtualizedresources"];

// ------------------------------------------------------------------ SHA-256

pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

// ------------------------------------------------------------------ SIDs

/// Binary SID with authority 15 (APP_PACKAGE_AUTHORITY).
fn sid15(subs: &[u32]) -> Vec<u8> {
    let mut b = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, 15];
    for s in subs {
        b.extend_from_slice(&s.to_le_bytes());
    }
    b
}

fn sid_text(subs: &[u32]) -> String {
    let s: Vec<String> = subs.iter().map(|x| x.to_string()).collect();
    format!("S-1-15-{}", s.join("-"))
}

fn hash_dwords(text: &str, n: usize) -> Vec<u32> {
    let w: Vec<u8> = text.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let h = sha256(&w);
    (0..n).map(|i| u32::from_le_bytes(h[4 * i..4 * i + 4].try_into().unwrap())).collect()
}

fn capability_sid(name: &str) -> Vec<u8> {
    let l = lower(name);
    if let Some((_, rid)) = WELL_KNOWN.iter().find(|(n, _)| *n == l) {
        return sid15(&[3, *rid]);
    }
    let mut subs = vec![3, 1024];
    subs.extend(hash_dwords(&name.to_uppercase(), 8));
    sid15(&subs)
}

fn blob(sids: &[Vec<u8>]) -> Vec<u8> {
    let mut b = (sids.len() as u32).to_le_bytes().to_vec();
    let mut n = 0;
    for s in sids {
        b.extend_from_slice(s);
        n += s.len();
    }
    b.resize(b.len() + n, 0);
    b
}

// ------------------------------------------------------------------ manifest

/// Name attributes of <…Capability …> tags: (device/plain capabilities, custom capabilities).
fn capabilities(xml: &str) -> (Vec<String>, Vec<String>) {
    let (mut caps, mut custom) = (Vec::new(), Vec::new());
    let mut rest = xml;
    while let Some(i) = rest.find('<') {
        rest = &rest[i + 1..];
        let end = rest.find('>').unwrap_or(rest.len());
        let tag = &rest[..end];
        let tname = tag.split(|c: char| c.is_whitespace() || c == '/').next().unwrap_or("");
        let local = tname.rsplit(':').next().unwrap_or("");
        let list = match local {
            "Capability" | "DeviceCapability" => &mut caps,
            "CustomCapability" => &mut custom,
            _ => continue,
        };
        if let Some(p) = tag.find(" Name=\"").or_else(|| tag.find("\tName=\"")).or_else(|| tag.find("\nName=\"")) {
            let v = &tag[p + 7..];
            if let Some(q) = v.find('"') {
                let n = v[..q].to_string();
                if !list.iter().any(|x: &String| x.eq_ignore_ascii_case(&n)) {
                    list.push(n);
                }
            }
        }
    }
    (caps, custom)
}

/// Values of the ApplicationsEx entry for package `full_name` with manifest `xml`.
pub fn entry(full_name: &str, xml: &str, device_map: &HashMap<String, Vec<[u32; 4]>>) -> Vec<(String, u32, Vec<u8>)> {
    let parts: Vec<&str> = full_name.split('_').collect();
    let family = format!("{}_{}", parts[0], parts.last().unwrap_or(&""));
    let pkg = hash_dwords(&lower(&family), 7);
    let mut psid = vec![2];
    psid.extend(&pkg);

    let (mut caps, custom) = capabilities(xml);
    caps.retain(|c| !NOT_GRANTED.contains(&lower(c).as_str()));
    if caps.iter().any(|c| c.eq_ignore_ascii_case("internetClient") || c.eq_ignore_ascii_case("internetClientServer")) {
        for c in ["cellularData", "wifiData"] {
            if !caps.iter().any(|x| x.eq_ignore_ascii_case(c)) {
                caps.push(c.into());
            }
        }
    }
    let mut cap_sids: Vec<Vec<u8>> = caps.iter().map(|c| capability_sid(c)).collect();
    let mut own = vec![3];
    own.extend(&pkg);
    cap_sids.push(sid15(&own));
    let dev: Vec<Vec<u8>> = caps.iter()
        .flat_map(|c| device_map.get(&lower(c)).cloned().unwrap_or_default())
        .map(|g| { let mut s = vec![3]; s.extend(g); sid15(&s) })
        .collect();
    let cust: Vec<Vec<u8>> = custom.iter().map(|c| capability_sid(c)).collect();

    let dword = |x: u32| x.to_le_bytes().to_vec();
    let mut v = vec![
        // Settings is the one package with type 2 on a healthy 26100/26200 install
        ("AppPackageType".to_string(), 4, dword(if lower(parts[0]) == "windows.immersivecontrolpanel" { 2 } else { 0 })),
        ("PackageSid".to_string(), 1, utf16z(&sid_text(&psid))),
        ("EnterpriseID".to_string(), 4, dword(0)),
        ("CapSids".to_string(), 3, blob(&cap_sids)),
    ];
    if !dev.is_empty() {
        v.push(("DeviceCapSids".into(), 3, blob(&dev)));
    }
    if !cust.is_empty() {
        v.push(("CustomCapSids".into(), 3, blob(&cust)));
    }
    v.push(("ApplicationFlags".into(), 4, dword(0)));
    v
}

/// DeviceAccess\CapabilityMappings\<capability>\{GUID} -> GUID as 4 DWORDs (SID layout).
pub fn device_map(software: &Key) -> HashMap<String, Vec<[u32; 4]>> {
    let mut m: HashMap<String, Vec<[u32; 4]>> = HashMap::new();
    if let Some(cm) = software.get(r"Microsoft\Windows\CurrentVersion\DeviceAccess\CapabilityMappings") {
        for (cap, k) in &cm.subs {
            for g in k.subs.values() {
                if let Some(d) = guid_dwords(&g.name) {
                    m.entry(cap.clone()).or_default().push(d);
                }
            }
        }
    }
    m
}

fn guid_dwords(s: &str) -> Option<[u32; 4]> {
    let h: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if h.len() != 32 {
        return None;
    }
    let hex = |a: usize, n: usize| u64::from_str_radix(&h[a..a + n], 16).ok();
    let d1 = hex(0, 8)? as u32;
    let d2 = hex(8, 4)? as u32;
    let d3 = hex(12, 4)? as u32;
    let mut b = [0u8; 8];
    for (i, x) in b.iter_mut().enumerate() {
        *x = hex(16 + 2 * i, 2)? as u8;
    }
    Some([d1, d2 | (d3 << 16), u32::from_le_bytes(b[..4].try_into().unwrap()), u32::from_le_bytes(b[4..].try_into().unwrap())])
}

/// Is this AppRepository file a main package (not a resource split or a bundle)?
pub fn is_main_package(full_name: &str) -> bool {
    let l = lower(full_name);
    !l.contains("_neutral_split.") && !l.contains("_neutral_~_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known() {
        let h = sha256(b"abc");
        assert_eq!(h[..4], [0xba, 0x78, 0x16, 0xbf]);
        assert_eq!(h[28..], [0xf2, 0x00, 0x15, 0xad]);
    }

    #[test]
    fn start_menu_package_sid() {
        // from a healthy Windows 11 26200 install
        let v = entry("Microsoft.Windows.StartMenuExperienceHost_10.0.26100.4768_neutral_neutral_cw5n1h2txyewy",
                      "<Capabilities><Capability Name=\"internetClient\"/><wincap:Capability Name=\"shellexperience\"/></Capabilities>",
                      &HashMap::new());
        let psid = &v.iter().find(|x| x.0 == "PackageSid").unwrap().2;
        assert_eq!(*psid, utf16z("S-1-15-2-515815643-2845804217-1874292103-218650560-777617685-4287762684-137415000"));
        let caps = &v.iter().find(|x| x.0 == "CapSids").unwrap().2;
        assert_eq!(caps[..4], 5u32.to_le_bytes()); // internetClient, shellexperience, cellularData, wifiData, own
        assert_eq!(caps[4..20], sid15(&[3, 1])[..]);
    }

    #[test]
    fn guid_layout() {
        // {C1D23ACC-752B-43E5-8448-8D0E519CD6D6} -> S-1-15-3-3251780300-1139111211-244140164-3604388945
        assert_eq!(guid_dwords("{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}"), Some([3251780300, 1139111211, 244140164, 3604388945]));
    }
}
