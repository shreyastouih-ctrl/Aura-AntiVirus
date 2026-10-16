// Embeds the auraAV shield icon into the Windows executable so Explorer, the
// taskbar and shortcuts show it. No-op on non-Windows targets or if windres
// is unavailable (the build still succeeds).
fn main() {
    println!("cargo:rerun-if-changed=../../packaging/assets/auraav.ico");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let ico = manifest.join("../../packaging/assets/auraav.ico");
    if !ico.exists() {
        println!("cargo:warning=packaging/assets/auraav.ico missing; exe icon not embedded");
        return;
    }

    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let rc = out.join("auraav.rc");
    let obj = out.join("auraav.res.o");

    if std::fs::write(&rc, format!("1 ICON \"{}\"\n", ico.display())).is_err() {
        return;
    }

    let windres = std::env::var("WINDRES").unwrap_or_else(|_| "x86_64-w64-mingw32-windres".into());
    let ok = std::process::Command::new(&windres)
        .arg("-i")
        .arg(&rc)
        .arg("-o")
        .arg(&obj)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if ok {
        println!("cargo:rustc-link-arg={}", obj.display());
    } else {
        println!("cargo:warning=windres not found; auraav-gui.exe icon not embedded");
    }
}
