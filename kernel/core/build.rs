use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    const SOURCE: &str = "src/freestanding.rs";
    println!("cargo:rerun-if-changed={SOURCE}");

    let source = fs::read_to_string(SOURCE).expect("read freestanding kernel source");
    let mut generated = String::with_capacity(source.len());
    for line in source.lines() {
        if line.trim_start().starts_with("#![") {
            continue;
        }
        generated.push_str(line);
        generated.push('\n');
    }

    let destination =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("freestanding.rs");
    fs::write(destination, generated).expect("write generated freestanding source");
}
