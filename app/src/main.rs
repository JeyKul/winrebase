#![windows_subsystem = "windows"]
//! winrebase — minimal native GUI for WinPE.

mod engine;
mod reg;
mod wim;
mod win;

use std::cell::RefCell;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::Dialogs::*;
use windows_sys::Win32::UI::Controls::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use engine::{Ev, Install, Out, Plan, Source};
use win::{from_wide_buf, wide};

const ID_INSTALL: i32 = 101;
const ID_WIM: i32 = 102;
const ID_BROWSE: i32 = 103;
const ID_SEARCH: i32 = 104;
const ID_UNMATCHED: i32 = 105;
const ID_ANALYZE: i32 = 106;
const ID_REPAIR: i32 = 107;
const ID_LOG: i32 = 108;
const ID_PROGRESS: i32 = 109;
const ID_STATUS: i32 = 110;
const ID_DEVRESET: i32 = 111;

const WM_ENGINE: u32 = WM_APP + 1;
const WM_SEARCHED: u32 = WM_APP + 2;
const WM_FINISHED: u32 = WM_APP + 3;

#[derive(Default)]
struct Ui {
    main: isize,
    ctl: std::collections::HashMap<i32, isize>,
    installs: Vec<Install>,
    sources: Vec<Source>,
    plan: Option<Plan>,
    busy: bool,
    dpi: i32,
}

thread_local! {
    static UI: RefCell<Ui> = RefCell::new(Ui::default());
}

fn h(id: i32) -> HWND {
    UI.with(|u| *u.borrow().ctl.get(&id).unwrap_or(&0)) as HWND
}

fn s(px: i32) -> i32 {
    UI.with(|u| px * u.borrow().dpi / 96)
}

fn send(hwnd: HWND, msg: u32, w: usize, l: isize) -> isize {
    unsafe { SendMessageW(hwnd, msg, w, l) }
}

fn post(main: isize, msg: u32, payload: Box<dyn std::any::Any + Send>) {
    let p = Box::into_raw(Box::new(payload));
    unsafe { PostMessageW(main as HWND, msg, 0, p as isize) };
}

fn append_log(text: &str) {
    let log = h(ID_LOG);
    let len = unsafe { GetWindowTextLengthW(log) } as usize;
    send(log, EM_SETSEL, len, len as isize);
    let t = wide(&format!("{}\r\n", text.replace('\n', "\r\n")));
    send(log, EM_REPLACESEL, 0, t.as_ptr() as isize);
}

fn set_status(frac: f64, text: &str) {
    send(h(ID_PROGRESS), PBM_SETPOS, (frac * 1000.0) as usize, 0);
    unsafe { SetWindowTextW(h(ID_STATUS), wide(text).as_ptr()) };
}

fn set_busy(busy: bool) {
    UI.with(|u| u.borrow_mut().busy = busy);
    for id in [ID_INSTALL, ID_WIM, ID_BROWSE, ID_SEARCH, ID_UNMATCHED, ID_DEVRESET, ID_ANALYZE] {
        unsafe { EnableWindow(h(id), (!busy) as i32) };
    }
    let can_repair = !busy && UI.with(|u| u.borrow().plan.as_ref().map(|p| !p.is_empty()).unwrap_or(false));
    unsafe { EnableWindow(h(ID_REPAIR), can_repair as i32) };
}

fn combo_sel(id: i32) -> Option<usize> {
    let i = send(h(id), CB_GETCURSEL, 0, 0);
    (i >= 0).then_some(i as usize)
}

fn checked(id: i32) -> bool {
    send(h(id), BM_GETCHECK, 0, 0) == BST_CHECKED as isize
}

/// Sink for engine events from a worker thread.
fn sink(main: isize) -> engine::Sink {
    Box::new(move |ev: Ev| post(main, WM_ENGINE, Box::new(ev)))
}

// ------------------------------------------------------------------ actions

/// Worker thread with a big stack (registry trees are walked recursively).
fn worker(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new().stack_size(256 << 20).spawn(f).expect("worker thread");
}

fn start_search() {
    set_busy(true);
    append_log("Searching for Windows installations and WIM/ESD files…");
    let main = UI.with(|u| u.borrow().main);
    worker(move || {
        let mut out = Out::new(sink(main));
        let installs = engine::find_installs();
        let sources = engine::find_sources(&mut out);
        post(main, WM_SEARCHED, Box::new((installs, sources)));
    });
}

fn fill_sources() {
    let wimc = h(ID_WIM);
    send(wimc, CB_RESETCONTENT, 0, 0);
    let inst = combo_sel(ID_INSTALL).and_then(|i| UI.with(|u| u.borrow().installs.get(i).cloned()));
    let sources = UI.with(|u| u.borrow().sources.clone());
    let mut best = None;
    for (i, src) in sources.iter().enumerate() {
        let t = wide(&src.label(inst.as_ref()));
        send(wimc, CB_ADDSTRING, 0, t.as_ptr() as isize);
        if best.is_none() && inst.as_ref().map(|x| src.matches(x)).unwrap_or(false) {
            best = Some(i);
        }
    }
    if let Some(b) = best.or((!sources.is_empty()).then_some(0)) {
        send(wimc, CB_SETCURSEL, b, 0);
    }
}

fn browse() {
    let mut buf = vec![0u16; 1024];
    let filter = wide("Windows images and ISOs (*.wim;*.esd;*.iso)\0*.wim;*.esd;*.iso\0All files\0*.*\0");
    let mut ofn: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    ofn.hwndOwner = UI.with(|u| u.borrow().main) as HWND;
    ofn.lpstrFilter = filter.as_ptr();
    ofn.lpstrFile = buf.as_mut_ptr();
    ofn.nMaxFile = buf.len() as u32;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    if unsafe { GetOpenFileNameW(&mut ofn) } == 0 {
        return;
    }
    let path = from_wide_buf(&buf);
    if path.to_lowercase().ends_with(".iso") {
        match engine::mount_iso(&path) {
            Ok((d, _)) => {
                append_log(&format!("Mounted {path} as {}", &d[..2]));
                let imgs = engine::images_on(&d);
                if imgs.is_empty() {
                    append_log("  no install.wim/install.esd on it");
                }
                for p in imgs {
                    add_image(&p);
                }
            }
            Err(e) => append_log(&format!("Can't mount {path}: {e}")),
        }
        return;
    }
    add_image(&path);
}

fn add_image(path: &str) {
    let path = path.to_string();
    match wim::Wim::open(&path) {
        Ok(w) => {
            let imgs = w.images();
            append_log(&format!("Added {path} ({} images)", imgs.len()));
            UI.with(|u| {
                let mut u = u.borrow_mut();
                u.sources.retain(|s| s.path != path);
                for image in imgs {
                    u.sources.insert(0, Source { path: path.clone(), image });
                }
            });
            fill_sources();
        }
        Err(e) => append_log(&format!("Can't open {path}: {e}")),
    }
}

fn selection() -> Option<(Install, Source, bool)> {
    let inst = combo_sel(ID_INSTALL).and_then(|i| UI.with(|u| u.borrow().installs.get(i).cloned()));
    let src = combo_sel(ID_WIM).and_then(|i| UI.with(|u| u.borrow().sources.get(i).cloned()));
    let (Some(inst), Some(src)) = (inst, src) else {
        append_log("Select a Windows installation and a WIM/ESD first.");
        return None;
    };
    let unmatched = checked(ID_UNMATCHED);
    if !src.matches(&inst) && !unmatched {
        append_log(&format!(
            "The image ({} {}.{}) doesn't match the installation ({} {}.{}). Use a WIM/ESD of the same \
             build (e.g. from uupdump.net) or tick \"Allow unmatched WIM/ESD\".",
            src.image.edition, src.image.build, src.image.spbuild, inst.edition, inst.build, inst.ubr));
        return None;
    }
    Some((inst, src, unmatched))
}

fn start_analyze() {
    let Some((inst, src, unmatched)) = selection() else { return };
    let device_reset = checked(ID_DEVRESET);
    UI.with(|u| u.borrow_mut().plan = None);
    set_busy(true);
    append_log("");
    append_log(&format!("=== Analyze {} ===", inst.label()));
    let main = UI.with(|u| u.borrow().main);
    worker(move || {
        let mut out = Out::new(sink(main));
        let r = engine::analyze(&inst.root, &src, unmatched, device_reset, &mut out);
        if let Err(e) = &r {
            out.log(format!("Analysis failed: {e}"));
        }
        post(main, WM_FINISHED, Box::new(r.ok()));
    });
}

fn start_repair() {
    let Some(plan) = UI.with(|u| u.borrow_mut().plan.take()) else { return };
    let msg = format!(
        "Repair {} now?\n\n{} files restored from the image, {} re-linked, {} folders created, \
         {} damaged files replaced.\nRegistry hives repaired: {}.{}{}\n\nThe originals of changed hives are kept in \
         \\Windows\\winrebase-backup. Make sure you have a backup if the data matters.",
        &plan.root[..2], plan.extract.len(), plan.links.len(), plan.mkdirs.len(), plan.delete.len(),
        if plan.reg_changes.is_empty() { "none".to_string() } else { plan.reg_changes.join(", ") },
        if plan.device_reset { "\nClean device start: Windows detects all hardware again on the next boot." } else { "" },
        if plan.unmatched { "\n\nUNMATCHED IMAGE: Windows files are replaced with the image's versions \
                              and the boot files are rebuilt." } else { "" });
    let r = unsafe {
        MessageBoxW(UI.with(|u| u.borrow().main) as HWND, wide(&msg).as_ptr(), wide("winrebase").as_ptr(),
                    MB_OKCANCEL | MB_ICONWARNING)
    };
    if r != IDOK {
        UI.with(|u| u.borrow_mut().plan = Some(plan));
        return;
    }
    set_busy(true);
    append_log("");
    append_log("=== Repair ===");
    let main = UI.with(|u| u.borrow().main);
    worker(move || {
        let mut out = Out::new(sink(main));
        if let Err(e) = engine::repair(&plan, &mut out) {
            out.log(format!("Repair failed: {e}"));
        }
        out.log("Run Analyze again to verify, then reboot.");
        post(main, WM_FINISHED, Box::new(None::<Plan>));
    });
}

// ------------------------------------------------------------------ window

fn create_controls(hwnd: HWND) {
    let inst = unsafe { GetModuleHandleW(null_mut()) };
    let font = unsafe {
        CreateFontW(-s(15), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, wide("Segoe UI").as_ptr())
    };
    let mono = unsafe {
        CreateFontW(-s(13), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, wide("Consolas").as_ptr())
    };
    let mk = |class: &str, text: &str, style: u32, ex: u32, id: i32, f| {
        let c = unsafe {
            CreateWindowExW(ex, wide(class).as_ptr(), wide(text).as_ptr(), WS_CHILD | WS_VISIBLE | style,
                            0, 0, 10, 10, hwnd, id as isize as HMENU, inst, null_mut())
        };
        send(c, WM_SETFONT, f as usize, 1);
        UI.with(|u| u.borrow_mut().ctl.insert(id, c as isize));
    };
    mk("STATIC", "Windows installation:", 0, 0, 201, font);
    mk("COMBOBOX", "", CBS_DROPDOWNLIST as u32 | WS_VSCROLL | WS_TABSTOP, 0, ID_INSTALL, font);
    mk("STATIC", "Select WIM or ESD:", 0, 0, 202, font);
    mk("COMBOBOX", "", CBS_DROPDOWNLIST as u32 | WS_VSCROLL | WS_TABSTOP, 0, ID_WIM, font);
    mk("BUTTON", "Browse…", BS_PUSHBUTTON as u32 | WS_TABSTOP, 0, ID_BROWSE, font);
    mk("BUTTON", "Search", BS_PUSHBUTTON as u32 | WS_TABSTOP, 0, ID_SEARCH, font);
    mk("STATIC", "Recommended: Search finds images on all drives and picks the one matching the installation.",
       0, 0, 203, font);
    mk("BUTTON", "Allow unmatched WIM/ESD (last resort: replaces Windows files and rebuilds boot files)",
       BS_AUTOCHECKBOX as u32 | WS_TABSTOP, 0, ID_UNMATCHED, font);
    mk("BUTTON", "Clean device start (Windows detects all hardware again — automatic when the device registry is damaged)",
       BS_AUTOCHECKBOX as u32 | WS_TABSTOP, 0, ID_DEVRESET, font);
    mk("BUTTON", "Analyze", BS_PUSHBUTTON as u32 | WS_TABSTOP, 0, ID_ANALYZE, font);
    mk("BUTTON", "Repair", BS_PUSHBUTTON as u32 | WS_TABSTOP, 0, ID_REPAIR, font);
    mk("EDIT", "", ES_MULTILINE as u32 | ES_READONLY as u32 | ES_AUTOVSCROLL as u32 | WS_VSCROLL,
       WS_EX_CLIENTEDGE, ID_LOG, mono);
    mk("msctls_progress32", "", 0, 0, ID_PROGRESS, font);
    mk("STATIC", "Ready", 0, 0, ID_STATUS, font);
    send(h(ID_PROGRESS), PBM_SETRANGE32, 0, 1000);
    send(h(ID_LOG), EM_SETLIMITTEXT, 0, 0);
    unsafe { EnableWindow(h(ID_REPAIR), 0) };
}

fn layout(w: i32, hgt: i32) {
    let m = s(12);
    let lw = s(150);
    let bw = s(80);
    let row = s(28);
    let place = |id: i32, x: i32, y: i32, cw: i32, ch: i32| unsafe {
        MoveWindow(h(id), x, y, cw, ch, 1);
    };
    let mut y = m;
    place(201, m, y + s(4), lw, s(20));
    place(ID_INSTALL, m + lw, y, w - 2 * m - lw, s(300));
    y += row + s(6);
    place(202, m, y + s(4), lw, s(20));
    place(ID_WIM, m + lw, y, w - 2 * m - lw - 2 * (bw + s(6)), s(300));
    place(ID_BROWSE, w - m - 2 * bw - s(6), y - s(1), bw, s(26));
    place(ID_SEARCH, w - m - bw, y - s(1), bw, s(26));
    y += row;
    place(203, m + lw, y, w - 2 * m - lw, s(20));
    y += s(26);
    place(ID_UNMATCHED, m, y, w - 2 * m, s(22));
    y += s(24);
    place(ID_DEVRESET, m, y, w - 2 * m, s(22));
    y += s(30);
    place(ID_ANALYZE, m, y, s(110), s(30));
    place(ID_REPAIR, m + s(120), y, s(110), s(30));
    y += s(40);
    let bottom = hgt - m - s(22) - s(6) - s(18);
    place(ID_LOG, m, y, w - 2 * m, bottom - y - s(6));
    place(ID_PROGRESS, m, bottom, w - 2 * m, s(22));
    place(ID_STATUS, m, bottom + s(26), w - 2 * m, s(18));
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => {
            UI.with(|u| u.borrow_mut().main = hwnd as isize);
            create_controls(hwnd);
            0
        }
        WM_SIZE => {
            layout((lp & 0xFFFF) as i32, ((lp >> 16) & 0xFFFF) as i32);
            0
        }
        WM_GETMINMAXINFO => {
            let mmi = unsafe { &mut *(lp as *mut MINMAXINFO) };
            mmi.ptMinTrackSize = POINT { x: s(640), y: s(420) };
            0
        }
        WM_COMMAND => {
            let id = (wp & 0xFFFF) as i32;
            let code = ((wp >> 16) & 0xFFFF) as u32;
            match (id, code) {
                (ID_SEARCH, _) => start_search(),
                (ID_BROWSE, _) => browse(),
                (ID_ANALYZE, _) => start_analyze(),
                (ID_REPAIR, _) => start_repair(),
                (ID_INSTALL, CBN_SELCHANGE) => {
                    UI.with(|u| u.borrow_mut().plan = None);
                    fill_sources();
                    set_busy(false);
                }
                (ID_WIM, CBN_SELCHANGE) | (ID_UNMATCHED, _) => {
                    UI.with(|u| u.borrow_mut().plan = None);
                    set_busy(false);
                }
                _ => {}
            }
            0
        }
        WM_ENGINE => {
            let b = unsafe { Box::from_raw(lp as *mut Box<dyn std::any::Any + Send>) };
            if let Ok(ev) = b.downcast::<Ev>() {
                match *ev {
                    Ev::Log(t) => append_log(&t),
                    Ev::Progress(f, t) => set_status(f, &t),
                }
            }
            0
        }
        WM_SEARCHED => {
            let b = unsafe { Box::from_raw(lp as *mut Box<dyn std::any::Any + Send>) };
            if let Ok(r) = b.downcast::<(Vec<Install>, Vec<Source>)>() {
                let (installs, sources) = *r;
                let ic = h(ID_INSTALL);
                send(ic, CB_RESETCONTENT, 0, 0);
                for i in &installs {
                    append_log(&format!("  Windows found: {}", i.label()));
                    send(ic, CB_ADDSTRING, 0, wide(&i.label()).as_ptr() as isize);
                }
                if installs.is_empty() {
                    append_log("  No Windows installation found.");
                } else {
                    send(ic, CB_SETCURSEL, 0, 0);
                }
                append_log(&format!("  {} images found in WIM/ESD files.", sources.len()));
                UI.with(|u| {
                    let mut u = u.borrow_mut();
                    u.installs = installs;
                    u.sources = sources;
                });
                fill_sources();
            }
            set_status(0.0, "Ready");
            set_busy(false);
            0
        }
        WM_FINISHED => {
            let b = unsafe { Box::from_raw(lp as *mut Box<dyn std::any::Any + Send>) };
            if let Ok(p) = b.downcast::<Option<Plan>>() {
                if let Some(p) = *p {
                    if p.is_empty() {
                        append_log("Nothing to repair — Windows files and registry match the image.");
                    } else {
                        append_log("Click Repair to apply.");
                    }
                    UI.with(|u| u.borrow_mut().plan = Some(p));
                }
            }
            set_busy(false);
            0
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
    }
}

/// Never vanish silently: report panics (any thread) in a message box and a file on X:.
fn crash_hook() {
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("winrebase crashed:\n\n{info}\n\n{}", std::backtrace::Backtrace::force_capture());
        let _ = std::fs::write(format!("{}winrebase-crash.txt", win::system_drive()), &msg);
        unsafe {
            MessageBoxW(null_mut(), wide(&msg.chars().take(1500).collect::<String>()).as_ptr(),
                        wide("winrebase").as_ptr(), MB_ICONERROR);
        }
    }));
}

fn main() {
    crash_hook();
    unsafe {
        let icc = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES,
        };
        InitCommonControlsEx(&icc);
        let hdc = GetDC(null_mut());
        let dpi = GetDeviceCaps(hdc, LOGPIXELSY as i32);
        ReleaseDC(null_mut(), hdc);
        UI.with(|u| u.borrow_mut().dpi = if dpi > 0 { dpi } else { 96 });

        if let Err(e) = wim::init() {
            MessageBoxW(null_mut(), wide(&e).as_ptr(), wide("winrebase").as_ptr(), MB_ICONERROR);
        }

        let inst = GetModuleHandleW(null_mut());
        let class = wide("winrebase");
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: inst,
            hIcon: LoadIconW(null_mut(), IDI_APPLICATION),
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hbrBackground: (COLOR_BTNFACE + 1) as usize as HBRUSH,
            lpszMenuName: std::ptr::null(),
            lpszClassName: class.as_ptr(),
            hIconSm: null_mut(),
        };
        RegisterClassExW(&wc);
        let hwnd = CreateWindowExW(0, class.as_ptr(), wide("winrebase — Windows repair").as_ptr(),
                                   WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT,
                                   s(820), s(600), null_mut(), null_mut(), inst, std::ptr::null());
        ShowWindow(hwnd, SW_SHOW);
        start_search();

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(hwnd, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}
