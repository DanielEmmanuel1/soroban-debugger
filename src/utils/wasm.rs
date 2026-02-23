use crate::analyzer::upgrade::{FunctionSignature, WasmType};
use crate::Result;
use wasmparser::{CompositeType, Parser, Payload, TypeRef, ValType};

/// Parse exported functions from WASM
pub fn parse_functions(wasm_bytes: &[u8]) -> Result<Vec<String>> {
    let mut functions = Vec::new();
    let parser = Parser::new(0);

    for payload in parser.parse_all(wasm_bytes) {
        match payload? {
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export?;
                    if matches!(export.kind, wasmparser::ExternalKind::Func) {
                        functions.push(export.name.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    Ok(functions)
}

/// Get WASM module information
pub fn get_module_info(wasm_bytes: &[u8]) -> Result<ModuleInfo> {
    let mut info = ModuleInfo::default();
    let parser = Parser::new(0);

    for payload in parser.parse_all(wasm_bytes) {
        match payload? {
            Payload::Version { .. } => {}
            Payload::TypeSection(reader) => {
                info.type_count = reader.count();
            }
            Payload::FunctionSection(reader) => {
                info.function_count = reader.count();
            }
            Payload::ExportSection(reader) => {
                info.export_count = reader.count();
            }
            _ => {}
        }
    }

    Ok(info)
}

/// Information about a WASM module
#[derive(Debug, Default)]
pub struct ModuleInfo {
    pub type_count: u32,
    pub function_count: u32,
    pub export_count: u32,
}

/// Parse full function signatures (name + param types + return types) from WASM
pub fn parse_function_signatures(wasm_bytes: &[u8]) -> Result<Vec<FunctionSignature>> {
    // Step 1: collect all type definitions indexed by type index
    let mut func_types: Vec<Option<wasmparser::FuncType>> = Vec::new();
    // Type indices for imported functions (in import order)
    let mut import_type_indices: Vec<u32> = Vec::new();
    // Type indices for local functions (in function-section order)
    let mut local_type_indices: Vec<u32> = Vec::new();
    // Exported function names and their function indices
    let mut exports: Vec<(String, u32)> = Vec::new();

    let parser = Parser::new(0);
    for payload in parser.parse_all(wasm_bytes) {
        match payload? {
            Payload::TypeSection(reader) => {
                for rec_group in reader {
                    let rec_group = rec_group?;
                    for sub_type in rec_group.into_types() {
                        match sub_type.composite_type {
                            CompositeType::Func(ft) => func_types.push(Some(ft)),
                            _ => func_types.push(None),
                        }
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import?;
                    if let TypeRef::Func(type_idx) = import.ty {
                        import_type_indices.push(type_idx);
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for type_idx in reader {
                    local_type_indices.push(type_idx?);
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export?;
                    if matches!(export.kind, wasmparser::ExternalKind::Func) {
                        exports.push((export.name.to_string(), export.index));
                    }
                }
            }
            _ => {}
        }
    }

    // Step 2: build combined function-index → type-index map
    let all_type_indices: Vec<u32> = import_type_indices
        .iter()
        .chain(local_type_indices.iter())
        .copied()
        .collect();

    // Step 3: resolve each export to a FunctionSignature
    let mut signatures = Vec::new();
    for (name, func_idx) in exports {
        let func_idx = func_idx as usize;
        if func_idx >= all_type_indices.len() {
            continue;
        }
        let type_idx = all_type_indices[func_idx] as usize;
        if type_idx >= func_types.len() {
            continue;
        }
        if let Some(ft) = &func_types[type_idx] {
            let params = ft.params().iter().map(val_type_to_wasm_type).collect();
            let results = ft.results().iter().map(val_type_to_wasm_type).collect();
            signatures.push(FunctionSignature { name, params, results });
        }
    }

    Ok(signatures)
}

fn val_type_to_wasm_type(vt: &ValType) -> WasmType {
    match vt {
        ValType::I32 => WasmType::I32,
        ValType::I64 => WasmType::I64,
        ValType::F32 => WasmType::F32,
        ValType::F64 => WasmType::F64,
        ValType::V128 => WasmType::V128,
        ValType::Ref(rt) => {
            if rt.is_func_ref() {
                WasmType::FuncRef
            } else if rt.is_extern_ref() {
                WasmType::ExternRef
            } else {
                WasmType::Unknown
            }
        }
    }
}