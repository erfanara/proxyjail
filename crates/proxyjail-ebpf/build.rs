use std::{env, path::PathBuf};

use libbpf_cargo::SkeletonBuilder;

fn main() {
    let out_dir = PathBuf::from(
        env::var_os("OUT_DIR").expect("OUT_DIR must be set")
    );

    let out = out_dir.join("redirect_cgroup.skel.rs");

    SkeletonBuilder::new()
        .source("bpf/redirect_cgroup.bpf.c")
        .build_and_generate(&out)
        .expect("failed to build BPF program and generate skeleton");

    println!("cargo:rerun-if-changed=bpf/redirect_cgroup.bpf.c");
    println!("cargo:rerun-if-changed=bpf/bpf_sockopt_helpers.h");
}