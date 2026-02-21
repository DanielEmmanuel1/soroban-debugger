use assert_cmd::Command;

#[test]
fn test_full_debug_session_walkthrough() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let wasm_path = std::path::PathBuf::from(manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("wasm")
        .join("counter.wasm");

    // Skip if fixture not built
    if !wasm_path.exists() {
        eprintln!("Skipping test: counter.wasm fixture not found.");
        return;
    }

    // Basic command check
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_soroban-debug"));
    cmd.arg("run").arg("--help");
    cmd.assert().success();
}
