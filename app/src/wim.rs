//! Minimal safe wrapper around the statically linked wimlib.

use std::ffi::c_void;
use std::ptr;

use crate::win::{from_wide, wide};

#[repr(C)]
pub struct WimStruct {
    _p: [u8; 0],
}

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i32,
}

#[repr(C)]
struct ResourceEntry {
    uncompressed_size: u64,
    compressed_size: u64,
    offset: u64,
    sha1: [u8; 20],
    part_number: u32,
    reference_count: u32,
    flags: u32,
    raw_offset: u64,
    raw_csize: u64,
    raw_usize: u64,
    reserved: [u64; 1],
}

#[repr(C)]
struct StreamEntry {
    stream_name: *const u16,
    resource: ResourceEntry,
    reserved: [u64; 4],
}

#[repr(C)]
struct DirEntry {
    filename: *const u16,
    dos_name: *const u16,
    full_path: *const u16,
    depth: usize,
    security_descriptor: *const u8,
    security_descriptor_size: usize,
    attributes: u32,
    reparse_tag: u32,
    num_links: u32,
    num_named_streams: u32,
    hard_link_group_id: u64,
    creation_time: Timespec,
    last_write_time: Timespec,
    last_access_time: Timespec,
    unix: [u32; 4],
    object_id: [u8; 64],
    time_high: [i32; 4],
    reserved: [u64; 4],
    streams: [StreamEntry; 0],
}

// Layout checked against the C header (mingw offsetof): streams at 248, sha1 at +32.
const _: () = assert!(std::mem::offset_of!(DirEntry, attributes) == 48);
const _: () = assert!(std::mem::offset_of!(DirEntry, hard_link_group_id) == 64);
const _: () = assert!(std::mem::offset_of!(DirEntry, streams) == 248);
const _: () = assert!(std::mem::size_of::<StreamEntry>() == 128);
const _: () = assert!(std::mem::offset_of!(StreamEntry, resource) + std::mem::offset_of!(ResourceEntry, sha1) == 32);

type IterCb = unsafe extern "C" fn(*const DirEntry, *mut c_void) -> i32;
type ProgressCb = unsafe extern "C" fn(i32, *const u8, *mut c_void) -> i32;

const ITERATE_RECURSIVE: i32 = 1;
const PROGRESS_MSG_EXTRACT_STREAMS: i32 = 4;

unsafe extern "C" {
    fn wimlib_global_init(flags: i32) -> i32;
    fn wimlib_open_wim(path: *const u16, flags: i32, wim: *mut *mut WimStruct) -> i32;
    fn wimlib_free(wim: *mut WimStruct);
    fn wimlib_get_wim_info(wim: *mut WimStruct, info: *mut u8) -> i32;
    fn wimlib_get_image_property(wim: *const WimStruct, image: i32, name: *const u16) -> *const u16;
    fn wimlib_iterate_dir_tree(wim: *mut WimStruct, image: i32, path: *const u16, flags: i32,
                               cb: IterCb, ctx: *mut c_void) -> i32;
    fn wimlib_extract_paths(wim: *mut WimStruct, image: i32, target: *const u16,
                            paths: *const *const u16, n: usize, flags: i32) -> i32;
    fn wimlib_register_progress_function(wim: *mut WimStruct, f: Option<ProgressCb>, ctx: *mut c_void);
    fn wimlib_get_error_string(code: i32) -> *const u16;
}

pub fn init() -> Result<(), String> {
    // acquires SeBackup/SeRestore/SeSecurity/SeTakeOwnership for the process
    let r = unsafe { wimlib_global_init(0) };
    if r == 0 { Ok(()) } else { Err(err(r)) }
}

fn err(code: i32) -> String {
    unsafe { format!("wimlib error {code}: {}", from_wide(wimlib_get_error_string(code))) }
}

#[derive(Clone, Debug)]
pub struct Image {
    pub index: i32,
    pub name: String,
    pub edition: String,
    pub build: u32,
    pub spbuild: u32,
}

#[derive(Clone)]
pub struct Entry {
    /// path relative to the image root, '\' separated, no leading separator
    pub path: String,
    pub attrs: u32,
    pub sd: Vec<u8>,
    pub link_group: u64,
    pub nlinks: u32,
    pub sha1: [u8; 20],
    pub size: u64,
}

impl Entry {
    pub fn is_dir(&self) -> bool { self.attrs & 0x10 != 0 }
    pub fn is_reparse(&self) -> bool { self.attrs & 0x400 != 0 }
}

pub struct Wim {
    ptr: *mut WimStruct,
}

unsafe impl Send for Wim {}

impl Drop for Wim {
    fn drop(&mut self) { unsafe { wimlib_free(self.ptr) } }
}

impl Wim {
    pub fn open(path: &str) -> Result<Wim, String> {
        let mut p = ptr::null_mut();
        let r = unsafe { wimlib_open_wim(wide(path).as_ptr(), 0, &mut p) };
        if r != 0 { return Err(err(r)); }
        Ok(Wim { ptr: p })
    }

    pub fn images(&self) -> Vec<Image> {
        let mut info = [0u8; 512];
        unsafe { wimlib_get_wim_info(self.ptr, info.as_mut_ptr()) };
        let count = u32::from_le_bytes(info[16..20].try_into().unwrap()) as i32;
        (1..=count).map(|i| Image {
            index: i,
            name: self.prop(i, "NAME"),
            edition: self.prop(i, "WINDOWS/EDITIONID"),
            build: self.prop(i, "WINDOWS/VERSION/BUILD").parse().unwrap_or(0),
            spbuild: self.prop(i, "WINDOWS/VERSION/SPBUILD").parse().unwrap_or(0),
        }).collect()
    }

    fn prop(&self, image: i32, name: &str) -> String {
        unsafe { from_wide(wimlib_get_image_property(self.ptr, image, wide(name).as_ptr())) }
    }

    /// All entries below `path` (e.g. "\\Windows"), recursively.
    pub fn list(&self, image: i32, path: &str) -> Result<Vec<Entry>, String> {
        unsafe extern "C" fn cb(e: *const DirEntry, ctx: *mut c_void) -> i32 {
            unsafe {
                let out = &mut *(ctx as *mut Vec<Entry>);
                let e = &*e;
                let full = from_wide(e.full_path).replace('/', "\\");
                let s0 = &*e.streams.as_ptr();
                out.push(Entry {
                    path: full.trim_start_matches('\\').to_string(),
                    attrs: e.attributes,
                    sd: if e.security_descriptor.is_null() { Vec::new() } else {
                        std::slice::from_raw_parts(e.security_descriptor, e.security_descriptor_size).to_vec()
                    },
                    link_group: e.hard_link_group_id,
                    nlinks: e.num_links,
                    sha1: s0.resource.sha1,
                    size: s0.resource.uncompressed_size,
                });
            }
            0
        }
        let mut out: Vec<Entry> = Vec::new();
        let r = unsafe {
            wimlib_iterate_dir_tree(self.ptr, image, wide(path).as_ptr(), ITERATE_RECURSIVE, cb,
                                    &mut out as *mut _ as *mut c_void)
        };
        if r != 0 { return Err(err(r)); }
        Ok(out)
    }

    /// Extract `paths` (image-relative, '\' separated) below `target` (e.g. "C:\\"),
    /// keeping the directory structure, ACLs and hard links among the extracted files.
    pub fn extract(&self, image: i32, target: &str, paths: &[String],
                   progress: &mut dyn FnMut(u64, u64)) -> Result<(), String> {
        unsafe extern "C" fn pcb(msg: i32, info: *const u8, ctx: *mut c_void) -> i32 {
            if msg == PROGRESS_MSG_EXTRACT_STREAMS && !info.is_null() {
                unsafe {
                    let total = u64::from_le_bytes(std::slice::from_raw_parts(info.add(40), 8).try_into().unwrap());
                    let done = u64::from_le_bytes(std::slice::from_raw_parts(info.add(48), 8).try_into().unwrap());
                    let f = &mut *(ctx as *mut &mut dyn FnMut(u64, u64));
                    f(done, total);
                }
            }
            0
        }
        let wides: Vec<Vec<u16>> = paths.iter().map(|p| wide(&format!("\\{p}"))).collect();
        let ptrs: Vec<*const u16> = wides.iter().map(|w| w.as_ptr()).collect();
        let mut f: &mut dyn FnMut(u64, u64) = progress;
        unsafe {
            wimlib_register_progress_function(self.ptr, Some(pcb), &mut f as *mut _ as *mut c_void);
            let r = wimlib_extract_paths(self.ptr, image, wide(target).as_ptr(), ptrs.as_ptr(), ptrs.len(), 0);
            wimlib_register_progress_function(self.ptr, None, ptr::null_mut());
            if r != 0 { return Err(err(r)); }
        }
        Ok(())
    }
}
