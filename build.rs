use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const BPF_SOURCE: &str = "bpf/timing.bpf.c";

fn main() {
    println!("cargo:rerun-if-changed={}", BPF_SOURCE);
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let skel_path = out_dir.join("timing.skel.rs");

    SkeletonBuilder::new()
        .source(BPF_SOURCE)
        .build_and_generate(&skel_path)
        .expect("Failed to build and generate BPF timing skeleton");
}
