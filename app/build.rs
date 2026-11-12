use std::{env, path::PathBuf, process::Command};

fn main() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // wimlib, built as a static MinGW library (third_party/wimlib-win64)
    let wim = root.join("../third_party/wimlib-win64/lib");
    println!("cargo:rustc-link-search=native={}", wim.display());
    println!("cargo:rustc-link-lib=static=wim");
    println!("cargo:rustc-link-lib=ntdll");
    println!("cargo:rerun-if-changed=res/app.rc");
    println!("cargo:rerun-if-changed=res/app.manifest");

    // manifest (common controls v6, DPI aware) as a linked resource
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("app.res.o");
    let ok = Command::new("x86_64-w64-mingw32-windres")
        .args(["-O", "coff", "-o"]).arg(&out).arg(root.join("res/app.rc"))
        .current_dir(root.join("res"))
        .status().expect("windres");
    assert!(ok.success(), "windres failed");
    println!("cargo:rustc-link-arg={}", out.display());
    println!("cargo:rustc-link-arg=-mwindows");
}
