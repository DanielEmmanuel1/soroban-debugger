use crate::analyzer::upgrade::{CompatibilityReport, ExecutionDiff, UpgradeAnalyzer};
use crate::cli::args::{InspectArgs, InteractiveArgs, RunArgs, UpgradeCheckArgs};
use crate::debugger::engine::DebuggerEngine;
use crate::runtime::executor::ContractExecutor;
use crate::ui::tui::DebuggerUI;
use crate::Result;
use anyhow::Context;
use std::fs;

/// Execute the run command
pub fn run(args: RunArgs) -> Result<()> {
    println!("Loading contract: {:?}", args.contract);

    // Load WASM file
    let wasm_bytes = fs::read(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;

    println!("Contract loaded successfully ({} bytes)", wasm_bytes.len());

    // Parse arguments if provided
    let parsed_args = if let Some(args_json) = &args.args {
        Some(parse_args(args_json)?)
    } else {
        None
    };

    // Parse storage if provided
    let initial_storage = if let Some(storage_json) = &args.storage {
        Some(parse_storage(storage_json)?)
    } else {
        None
    };

    println!("\nStarting debugger...");
    println!("Function: {}", args.function);
    if let Some(ref args) = parsed_args {
        println!("Arguments: {}", args);
    }

    // Create executor
    let mut executor = ContractExecutor::new(wasm_bytes)?;

    // Set up initial storage if provided
    if let Some(storage) = initial_storage {
        executor.set_initial_storage(storage)?;
    }

    // Create debugger engine
    let mut engine = DebuggerEngine::new(executor, args.breakpoint);

    if args.server {
        let token = args.token.clone().ok_or_else(|| anyhow::anyhow!("Token required for server mode"))?;
        let server = crate::server::debug_server::DebugServer::new(
            engine, 
            token, 
            args.tls_cert.as_deref(), 
            args.tls_key.as_deref()
        )?;
        
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(server.run(args.port))?;
        return Ok(());
    }

    if let Some(remote_addr) = args.remote {
        let token = args.token.clone().ok_or_else(|| anyhow::anyhow!("Token required for remote mode"))?;
        let rt = tokio::runtime::Runtime::new()?;
        // Use TLS if either cert or key is provided, or if we want to default to TLS if available.
        // For client-side, we might just want a flag --use-tls.
        // Let's assume for now if they provide ANY tls arg or if we want to detect it.
        let use_tls = args.tls_cert.is_some() || args.tls_key.is_some();
        let mut client = rt.block_on(crate::client::remote_client::RemoteClient::connect(&remote_addr, token, use_tls))?;
        
        println!("\nConnected to remote debugger.");
        let request = crate::protocol::DebugRequest::Execute {
            function: args.function.clone(),
            args: args.args.clone(),
        };
        
        let response = rt.block_on(client.send_request(request))?;
        println!("Remote Response: {:?}", response);
        return Ok(());
    }

    // Execute locally with debugging
    println!("\n--- Execution Start ---\n");
    let result = engine.execute(&args.function, parsed_args.as_deref())?;
    println!("\n--- Execution Complete ---\n");

    println!("Result: {:?}", result);

    Ok(())
}

/// Execute the interactive command
pub fn interactive(args: InteractiveArgs) -> Result<()> {
    println!("Starting interactive debugger for: {:?}", args.contract);

    // Load WASM file
    let wasm_bytes = fs::read(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;

    println!("Contract loaded successfully ({} bytes)", wasm_bytes.len());

    // Create executor
    let executor = ContractExecutor::new(wasm_bytes)?;

    // Create debugger engine
    let engine = DebuggerEngine::new(executor, vec![]);

    // Start interactive UI
    println!("\nStarting interactive mode...");
    println!("Type 'help' for available commands\n");

    let mut ui = DebuggerUI::new(engine)?;
    ui.run()?;

    Ok(())
}

/// Execute the inspect command
pub fn inspect(args: InspectArgs) -> Result<()> {
    println!("Inspecting contract: {:?}", args.contract);

    // Load WASM file
    let wasm_bytes = fs::read(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;

    println!("\nContract Information:");
    println!("  Size: {} bytes", wasm_bytes.len());

    if args.functions {
        println!("\nExported Functions:");
        let functions = crate::utils::wasm::parse_functions(&wasm_bytes)?;
        for func in functions {
            println!("  - {}", func);
        }
    }

    if args.metadata {
        println!("\nMetadata:");
        println!("  (Metadata parsing not yet implemented)");
    }

    Ok(())
}

/// Parse JSON arguments into a string for now (will be improved later)
fn parse_args(json: &str) -> Result<String> {
    // Basic validation
    serde_json::from_str::<serde_json::Value>(json)
        .with_context(|| format!("Invalid JSON arguments: {}", json))?;
    Ok(json.to_string())
}

/// Parse JSON storage into a string for now (will be improved later)
fn parse_storage(json: &str) -> Result<String> {
    // Basic validation
    serde_json::from_str::<serde_json::Value>(json)
        .with_context(|| format!("Invalid JSON storage: {}", json))?;
    Ok(json.to_string())
}

/// Execute the upgrade-check command
pub fn upgrade_check(args: UpgradeCheckArgs) -> Result<()> {
    println!("Loading old contract: {:?}", args.old);
    let old_wasm = fs::read(&args.old)
        .with_context(|| format!("Failed to read old WASM file: {:?}", args.old))?;

    println!("Loading new contract: {:?}", args.new);
    let new_wasm = fs::read(&args.new)
        .with_context(|| format!("Failed to read new WASM file: {:?}", args.new))?;

    // Optionally run test inputs against both versions
    let execution_diffs = if let Some(inputs_json) = &args.test_inputs {
        run_test_inputs(inputs_json, &old_wasm, &new_wasm)?
    } else {
        Vec::new()
    };

    let old_path = args.old.to_string_lossy().to_string();
    let new_path = args.new.to_string_lossy().to_string();

    let report = UpgradeAnalyzer::analyze(&old_wasm, &new_wasm, &old_path, &new_path, execution_diffs)?;

    let output = match args.output.as_str() {
        "json" => serde_json::to_string_pretty(&report)?,
        _ => format_text_report(&report),
    };

    if let Some(out_file) = &args.output_file {
        fs::write(out_file, &output)
            .with_context(|| format!("Failed to write report to {:?}", out_file))?;
        println!("Report written to {:?}", out_file);
    } else {
        println!("{}", output);
    }

    if !report.is_compatible {
        anyhow::bail!("Contracts are not compatible: {} breaking change(s) detected", report.breaking_changes.len());
    }

    Ok(())
}

/// Run test inputs against both WASM versions and collect diffs
fn run_test_inputs(
    inputs_json: &str,
    old_wasm: &[u8],
    new_wasm: &[u8],
) -> Result<Vec<ExecutionDiff>> {
    let inputs: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(inputs_json).with_context(|| {
            "Invalid --test-inputs JSON: expected an object mapping function names to arg arrays"
        })?;

    let mut diffs = Vec::new();

    for (func_name, args_val) in &inputs {
        let args_str = args_val.to_string();

        let old_result = invoke_wasm(old_wasm, func_name, &args_str);
        let new_result = invoke_wasm(new_wasm, func_name, &args_str);

        let outputs_match = old_result == new_result;
        diffs.push(ExecutionDiff {
            function: func_name.clone(),
            args: args_str,
            old_result,
            new_result,
            outputs_match,
        });
    }

    Ok(diffs)
}

/// Invoke a function on a WASM contract and return a string representation of the result
fn invoke_wasm(wasm: &[u8], function: &str, args: &str) -> String {
    match ContractExecutor::new(wasm.to_vec()) {
        Err(e) => format!("Err(executor: {})", e),
        Ok(executor) => {
            let mut engine = DebuggerEngine::new(executor, vec![]);
            let parsed = if args == "null" || args == "[]" {
                None
            } else {
                Some(args.to_string())
            };
            match engine.execute(function, parsed.as_deref()) {
                Ok(val) => format!("Ok({:?})", val),
                Err(e) => format!("Err({})", e),
            }
        }
    }
}

/// Format a compatibility report as human-readable text
fn format_text_report(report: &CompatibilityReport) -> String {
    let mut out = String::new();

    out.push_str("Contract Upgrade Compatibility Report\n");
    out.push_str("======================================\n");
    out.push_str(&format!("Old: {}\n", report.old_wasm_path));
    out.push_str(&format!("New: {}\n", report.new_wasm_path));
    out.push('\n');

    let status = if report.is_compatible { "COMPATIBLE" } else { "INCOMPATIBLE" };
    out.push_str(&format!("Status: {}\n", status));

    out.push('\n');
    out.push_str(&format!("Breaking Changes ({}):\n", report.breaking_changes.len()));
    if report.breaking_changes.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for change in &report.breaking_changes {
            out.push_str(&format!("  {}\n", change));
        }
    }

    out.push('\n');
    out.push_str(&format!("Non-Breaking Changes ({}):\n", report.non_breaking_changes.len()));
    if report.non_breaking_changes.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for change in &report.non_breaking_changes {
            out.push_str(&format!("  {}\n", change));
        }
    }

    if !report.execution_diffs.is_empty() {
        out.push('\n');
        out.push_str(&format!("Execution Diffs ({}):\n", report.execution_diffs.len()));
        for diff in &report.execution_diffs {
            let match_str = if diff.outputs_match { "MATCH" } else { "MISMATCH" };
            out.push_str(&format!(
                "  {} args={} OLD={} NEW={} [{}]\n",
                diff.function, diff.args, diff.old_result, diff.new_result, match_str
            ));
        }
    }

    out.push('\n');
    let old_names: Vec<&str> = report.old_functions.iter().map(|f| f.name.as_str()).collect();
    let new_names: Vec<&str> = report.new_functions.iter().map(|f| f.name.as_str()).collect();
    out.push_str(&format!("Old Functions ({}): {}\n", old_names.len(), old_names.join(", ")));
    out.push_str(&format!("New Functions ({}): {}\n", new_names.len(), new_names.join(", ")));

    out
}