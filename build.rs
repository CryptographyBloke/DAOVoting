// Feature `cuda-emu`: compile the CUDA kernel source `src/gpu/bjj.cu` as host
// C++ so its arithmetic can be tested against arkworks without a GPU.
// Without that feature this script does nothing.
fn main() {
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
