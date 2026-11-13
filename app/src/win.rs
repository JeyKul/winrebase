//! Small Win32 helpers: strings, files, hashing, drives, ISO mounting, processes.

use std::collections::HashMap;
use std::ptr;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Cryptography::*;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::*;

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// # Safety
/// `p` must be null or point to a NUL-terminated UTF-16 string.
pub unsafe fn from_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }
}

pub fn from_wide_buf(b: &[u16]) -> String {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf16_lossy(&b[..n])
}

/// (attributes, size) or None if the path doesn't exist.
pub fn file_info(path: &str) -> Option<(u32, u64)> {
    let mut d: WIN32_FILE_ATTRIBUTE_DATA = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        GetFileAttributesExW(wide(path).as_ptr(), GetFileExInfoStandard, &mut d as *mut _ as *mut _)
    };
    if ok == 0 {
        return None;
    }
    Some((d.dwFileAttributes, ((d.nFileSizeHigh as u64) << 32) | d.nFileSizeLow as u64))
}

pub fn exists(path: &str) -> bool {
    file_info(path).is_some()
}

fn open_backup(path: &str, access: u32) -> Option<HANDLE> {
    let h = unsafe {
        CreateFileW(wide(path).as_ptr(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    ptr::null(), OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT,
                    ptr::null_mut())
    };
    if h == INVALID_HANDLE_VALUE { None } else { Some(h) }
}

/// SHA-1 hasher shared across files; caches by NTFS file id so hard links are read once.
pub struct Hasher {
    alg: BCRYPT_ALG_HANDLE,
    buf: Vec<u8>,
    cache: HashMap<(u32, u64), [u8; 20]>,
}

unsafe impl Send for Hasher {}

impl Hasher {
    pub fn new() -> Hasher {
        let mut alg = ptr::null_mut();
        unsafe { BCryptOpenAlgorithmProvider(&mut alg, BCRYPT_SHA1_ALGORITHM, ptr::null(), 0) };
        Hasher { alg, buf: vec![0; 1 << 20], cache: HashMap::new() }
    }

    /// Hash a file; `on_bytes` is called with the number of bytes read (for progress).
    pub fn sha1(&mut self, path: &str, on_bytes: &mut dyn FnMut(u64)) -> Option<[u8; 20]> {
        let h = open_backup(path, FILE_GENERIC_READ)?;
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let key = if unsafe { GetFileInformationByHandle(h, &mut info) } != 0 {
            Some((info.dwVolumeSerialNumber,
                  ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64))
        } else { None };
        if let Some(k) = key {
            if let Some(d) = self.cache.get(&k) {
                unsafe { CloseHandle(h) };
                return Some(*d);
            }
        }
        let mut hh = ptr::null_mut();
        let mut out = [0u8; 20];
        let mut ok = true;
        unsafe {
            BCryptCreateHash(self.alg, &mut hh, ptr::null_mut(), 0, ptr::null(), 0, 0);
            loop {
                let mut n = 0u32;
                if ReadFile(h, self.buf.as_mut_ptr(), self.buf.len() as u32, &mut n, ptr::null_mut()) == 0 {
                    ok = false;
                    break;
                }
                if n == 0 {
                    break;
                }
                BCryptHashData(hh, self.buf.as_ptr(), n, 0);
                on_bytes(n as u64);
            }
            BCryptFinishHash(hh, out.as_mut_ptr(), 20, 0);
            BCryptDestroyHash(hh);
            CloseHandle(h);
        }
        if !ok {
            return None;
        }
        if let Some(k) = key {
            self.cache.insert(k, out);
        }
        Some(out)
    }
}

/// Delete a file regardless of its ACL and read-only flag (needs SeRestorePrivilege).
pub fn delete_file(path: &str) -> Result<(), String> {
    let h = open_backup(path, DELETE).ok_or_else(|| format!("open {path}: {}", last_error()))?;
    let info = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    let ok = unsafe {
        SetFileInformationByHandle(h, FileDispositionInfoEx, &info as *const _ as *const _,
                                   std::mem::size_of_val(&info) as u32)
    };
    unsafe { CloseHandle(h) };
    if ok == 0 { Err(format!("delete {path}: {}", last_error())) } else { Ok(()) }
}

/// Create a directory with the given self-relative security descriptor.
pub fn mkdir_sd(path: &str, sd: &[u8]) -> Result<(), String> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: if sd.is_empty() { ptr::null_mut() } else { sd.as_ptr() as *mut _ },
        bInheritHandle: 0,
    };
    if unsafe { CreateDirectoryW(wide(path).as_ptr(), &sa) } == 0 {
        let e = unsafe { GetLastError() };
        if e != ERROR_ALREADY_EXISTS {
            return Err(format!("mkdir {path}: {}", last_error()));
        }
    }
    Ok(())
}

pub fn hardlink(new: &str, existing: &str) -> Result<(), String> {
    if unsafe { CreateHardLinkW(wide(new).as_ptr(), wide(existing).as_ptr(), ptr::null()) } == 0 {
        return Err(format!("link {new} -> {existing}: {}", last_error()));
    }
    Ok(())
}

pub fn last_error() -> String {
    std::io::Error::last_os_error().to_string()
}

// ---------------------------------------------------------------- drives

/// Drive roots like "C:\\", excluding the WinPE system drive.
pub fn drives() -> Vec<String> {
    let mask = unsafe { windows_sys::Win32::Storage::FileSystem::GetLogicalDrives() };
    let sys = system_drive();
    (0..26u8)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| format!("{}:\\", (b'A' + i) as char))
        .filter(|d| !d.eq_ignore_ascii_case(&sys))
        .collect()
}

/// Drive of the running system (X:\ in WinPE).
pub fn system_drive() -> String {
    let mut b = [0u16; 260];
    let n = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW(b.as_mut_ptr(), 260)
    };
    let s = String::from_utf16_lossy(&b[..n as usize]);
    s.get(..3).unwrap_or("X:\\").to_string()
}

pub fn free_drive_letter() -> Option<String> {
    let mask = unsafe { GetLogicalDrives() };
    (b'S'..=b'W').chain(b'M'..=b'R').find(|c| mask & (1 << (c - b'A')) == 0)
        .map(|c| format!("{}:", c as char))
}

pub fn run(cmd: &str, args: &[&str]) -> (i32, String) {
    use std::os::windows::process::CommandExt;
    match std::process::Command::new(cmd).args(args).creation_flags(0x0800_0000).output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).to_string();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.code().unwrap_or(-1), s.trim().to_string())
        }
        Err(e) => (-1, e.to_string()),
    }
}

// ---------------------------------------------------------------- ISO images

/// Attach an .iso read-only (VirtDisk, loaded at runtime so the tool still starts on a WinPE
/// without it) and return the drive root it gets, e.g. "E:\\".
/// Open an .iso with VirtDisk (ACCESS_READ = attach read-only | detach | get info).
fn open_iso(path: &str) -> Result<(HANDLE, windows_sys::Win32::Foundation::HMODULE), String> {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    #[repr(C)]
    struct StorageType { device_id: u32, vendor_id: windows_sys::core::GUID }
    type OpenFn = unsafe extern "system" fn(*const StorageType, *const u16, i32, i32, *const u8, *mut HANDLE) -> u32;
    unsafe {
        let lib = LoadLibraryW(wide("virtdisk.dll").as_ptr());
        if lib.is_null() {
            return Err("virtdisk.dll is not available in this WinPE".into());
        }
        let open = GetProcAddress(lib, b"OpenVirtualDisk\0".as_ptr()).ok_or("OpenVirtualDisk missing")?;
        let open: OpenFn = std::mem::transmute(open);
        let st = StorageType {
            device_id: 1, // VIRTUAL_STORAGE_TYPE_DEVICE_ISO
            vendor_id: windows_sys::core::GUID::from_u128(0xec984aec_a0f9_47e9_901f_71415a66345b),
        };
        let mut h: HANDLE = ptr::null_mut();
        let r = open(&st, wide(path).as_ptr(), 0x000d_0000 /* ACCESS_READ */, 0, ptr::null(), &mut h);
        if r != 0 {
            return Err(format!("OpenVirtualDisk: {}", std::io::Error::from_raw_os_error(r as i32)));
        }
        Ok((h, lib))
    }
}

pub fn mount_iso(path: &str) -> Result<String, String> {
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
    type AttachFn = unsafe extern "system" fn(HANDLE, *const u8, i32, u32, *const u32, *const u8) -> u32;

    let before = unsafe { GetLogicalDrives() };
    unsafe {
        let (h, lib) = open_iso(path)?;
        let Some(attach) = GetProcAddress(lib, b"AttachVirtualDisk\0".as_ptr()) else {
            CloseHandle(h);
            return Err("AttachVirtualDisk missing".into());
        };
        let attach: AttachFn = std::mem::transmute(attach);
        let params = [1u32, 0u32]; // ATTACH_VIRTUAL_DISK_VERSION_1
        // READ_ONLY | PERMANENT_LIFETIME (stays attached after the handle is closed)
        let r = attach(h, ptr::null(), 1 | 4, 0, params.as_ptr(), ptr::null());
        CloseHandle(h);
        if r != 0 {
            return Err(format!("AttachVirtualDisk: {}", std::io::Error::from_raw_os_error(r as i32)));
        }
    }
    // the mount manager assigns a letter shortly after
    for _ in 0..50 {
        let now = unsafe { GetLogicalDrives() };
        let new = now & !before;
        if new != 0 {
            let i = new.trailing_zeros() as u8;
            return Ok(format!("{}:\\", (b'A' + i) as char));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Err("attached, but no drive letter appeared".into())
}

/// Detach an .iso attached by `mount_iso` (frees its drive letter).
pub fn unmount_iso(path: &str) -> Result<(), String> {
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
    type DetachFn = unsafe extern "system" fn(HANDLE, u32, u32) -> u32;
    unsafe {
        let (h, lib) = open_iso(path)?;
        let Some(detach) = GetProcAddress(lib, b"DetachVirtualDisk\0".as_ptr()) else {
            CloseHandle(h);
            return Err("DetachVirtualDisk missing".into());
        };
        let detach: DetachFn = std::mem::transmute(detach);
        let r = detach(h, 0, 0);
        CloseHandle(h);
        if r != 0 {
            return Err(format!("DetachVirtualDisk: {}", std::io::Error::from_raw_os_error(r as i32)));
        }
    }
    Ok(())
}
