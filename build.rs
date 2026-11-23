// Feature `cuda-emu`: compile the CUDA kernel source `src/gpu/bjj.cu` as host
// C++ so its arithmetic can be tested against arkworks without a GPU.
// Without that feature this script does nothing.
fn main() {
    // NVRTC compilation overflows the Windows executable's default stack.
    // Reserve virtual address space only; default CPU builds are unchanged.
    if std::env::var("TARGET")
        .unwrap_or_default()
        .ends_with("windows-msvc")
        && std::env::var_os("CARGO_FEATURE_GPU").is_some()
    {
        println!("cargo:rustc-link-arg=/STACK:16777216");
    }
    println!("cargo:rerun-if-changed=src/gpu/bjj.cu");
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "cuda-emu")]
    {
        let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let src = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("src/gpu/bjj.cu");
        let wrapper = out.join("bjj_host.cpp");
        let inc = src.display().to_string().replace('\\', "/");
        std::fs::write(&wrapper, format!("#include \"{inc}\"\n")).unwrap();
        cc::Build::new()
            .cpp(true)
            .file(&wrapper)
            .opt_level(3)
            .compile("bjj_host");
    }
}
