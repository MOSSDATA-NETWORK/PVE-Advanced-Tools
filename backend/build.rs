//! Builds the web UI (backend/static, written by `npm run build` in frontend/) into the binary,
//! so a release binary carries its own UI and an in-app update replaces both together.
//! Without backend/static the table is empty and the server falls back to STATIC_DIR on disk.
use std::{env, fs, path::Path};

fn main() {
    // a directory here is scanned recursively; while it is missing the script reruns on every build
    println!("cargo:rerun-if-changed=static");
    let root = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("static");
    let mut files = Vec::new();
    if root.is_dir() {
        collect(&root, &root, &mut files);
    }
    files.sort();
    let mut out = String::from("pub static FILES: &[(&str, &[u8])] = &[\n");
    for rel in &files {
        let abs = root.join(rel);
        let abs = abs.to_str().expect("web UI path is not UTF-8");
        out.push_str(&format!("    ({:?}, include_bytes!({:?})),\n", rel, abs));
    }
    out.push_str("];\n");
    fs::write(Path::new(&env::var("OUT_DIR").unwrap()).join("web_ui.rs"), out).unwrap();
}

/// Regular files only: symlinks are skipped so nothing outside static/ can be built in.
fn collect(root: &Path, dir: &Path, files: &mut Vec<String>) {
    for entry in fs::read_dir(dir).expect("read web UI directory") {
        let path = entry.expect("read web UI entry").path();
        let meta = fs::symlink_metadata(&path).expect("stat web UI entry");
        if meta.is_dir() {
            collect(root, &path, files);
        } else if meta.is_file() {
            let rel = path.strip_prefix(root).unwrap();
            files.push(rel.to_str().expect("web UI file name is not UTF-8").replace('\\', "/"));
        }
    }
}
