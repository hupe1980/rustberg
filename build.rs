//! Embeds the built console (`ui/dist`) when the `ui` feature is on.
//!
//! Without a bundle, a build that ships (`RUSTBERG_REQUIRE_CONSOLE=1`: release workflow, image)
//! fails; any other build warns and serves a page saying how to build it, so CI stays Node-free.

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var_os("CARGO_FEATURE_UI").is_none() {
        return;
    }
    println!("cargo:rerun-if-changed=ui/dist");
    println!("cargo:rerun-if-env-changed=RUSTBERG_REQUIRE_CONSOLE");

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dist = root.join("ui/dist");
    let mut files: Vec<String> = std::fs::read_dir(&dist)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.path().is_file())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|name| !name.ends_with(".map"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();

    if files.is_empty() {
        let how = "build it first (`just ui`), or build without it \
                   (`--no-default-features --features cli,tls,storage-all`)";
        if std::env::var_os("RUSTBERG_REQUIRE_CONSOLE").is_some_and(|v| v == "1") {
            panic!("the `ui` feature is on and ui/dist is empty: {how}");
        }
        println!("cargo:warning=the console is not built, so /ui explains how: {how}");
    }

    let mut src = String::from(
        "/// The built console, as (file name, bytes). Empty when it was not built.\n\
         pub static BUNDLE: &[(&str, &[u8])] = &[\n",
    );
    for file in &files {
        src.push_str(&format!(
            "    ({file:?}, include_bytes!({:?})),\n",
            dist.join(file).display().to_string()
        ));
    }
    src.push_str("];\n");

    let out = Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("console_bundle.rs");
    std::fs::write(out, src).expect("write the console bundle");
}
