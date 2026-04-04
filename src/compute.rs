//! Compute/inference engine
//!
//! Handles AI model execution using ONNX Runtime.

use anyhow::{Context, Result};
#[cfg(feature = "compute")]
use ort::session::{builder::GraphOptimizationLevel, Session};
use rayon::prelude::*;
use sha3::{Digest, Keccak256};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::batch::{
    hash_result_output, BatchConfig, BatchInput, BatchInputManifest, BatchResult,
    BatchResultManifest, ExecutionMetadata,
};

use crate::blockchain::TaskInfo;
use crate::config::Config;

/// Supported inference frameworks
#[derive(Debug, Clone, PartialEq)]
pub enum Framework {
    ONNX,
    PyTorch,
    TensorFlow,
    Unknown(String),
}

impl From<&str> for Framework {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "onnx" => Framework::ONNX,
            "pytorch" | "torch" => Framework::PyTorch,
            "tensorflow" | "tf" => Framework::TensorFlow,
            other => Framework::Unknown(other.to_string()),
        }
    }
}

/// Model requirements parsed from task
#[derive(Debug, Clone)]
pub struct ModelRequirements {
    pub framework: Framework,
    pub min_vram_mb: Option<u64>,
    pub min_ram_mb: Option<u64>,
    pub gpu_required: bool,
}

impl ModelRequirements {
    /// Parse from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(json)?;

        let framework = value
            .get("framework")
            .and_then(|v| v.as_str())
            .map(Framework::from)
            .unwrap_or(Framework::Unknown("unspecified".to_string()));

        let min_vram_mb = value
            .get("min_vram")
            .and_then(|v| v.as_str())
            .and_then(|s| parse_memory_string(s));

        let min_ram_mb = value
            .get("min_ram")
            .and_then(|v| v.as_str())
            .and_then(|s| parse_memory_string(s));

        let gpu_required = value
            .get("gpu_required")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(Self {
            framework,
            min_vram_mb,
            min_ram_mb,
            gpu_required,
        })
    }
}

/// Detect inference framework from model magic bytes (best-effort heuristic).
///
/// | Framework | Signature                          | Notes                        |
/// |-----------|------------------------------------|------------------------------|
/// | PyTorch   | `PK\x03\x04` (ZIP magic)           | Modern .pt / .pth (zip-based)|
/// | PyTorch   | `\x80\x02` or `\x80\x04` (pickle) | Legacy pickle .pt            |
/// | TF/Keras  | `\x89HDF`                          | HDF5 .h5 Keras model         |
/// | ONNX      | first byte `\x08` or `\x0a`        | Protobuf field encoding      |
pub fn detect_framework(data: &[u8]) -> Framework {
    if data.len() < 4 {
        return Framework::Unknown("too small".to_string());
    }
    if data.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        return Framework::PyTorch; // ZIP-based .pt
    }
    if data.starts_with(&[0x80, 0x02]) || data.starts_with(&[0x80, 0x04]) {
        return Framework::PyTorch; // pickle-based .pt
    }
    if data.starts_with(&[0x89, 0x48, 0x44, 0x46]) {
        return Framework::TensorFlow; // HDF5 .h5
    }
    if data[0] == 0x08 || data[0] == 0x0A {
        return Framework::ONNX; // protobuf varint encoding
    }
    Framework::Unknown("unrecognised magic bytes".to_string())
}

/// Parse memory string like "8GB" or "4096MB"
fn parse_memory_string(s: &str) -> Option<u64> {
    let s = s.to_uppercase();
    if s.ends_with("GB") {
        s.trim_end_matches("GB")
            .parse::<u64>()
            .ok()
            .map(|v| v * 1024)
    } else if s.ends_with("MB") {
        s.trim_end_matches("MB").parse::<u64>().ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// Compute engine for running inference tasks
pub struct ComputeEngine {
    supported_frameworks: Vec<Framework>,
    max_vram_mb: Option<u64>,
    max_ram_mb: Option<u64>,
    concurrent_tasks: usize,
    active_tasks: usize,
}

impl ComputeEngine {
    /// Create a new compute engine
    pub fn new(config: &Config) -> Result<Self> {
        let supported_frameworks: Vec<Framework> = config
            .compute
            .frameworks
            .iter()
            .map(|s| Framework::from(s.as_str()))
            .collect();

        info!("Compute engine initialized");
        info!("Supported frameworks: {:?}", supported_frameworks);

        // Detect available resources
        let (detected_vram, detected_ram) = detect_resources();

        let max_vram_mb = config.compute.max_vram_mb.or(detected_vram);
        let max_ram_mb = config.compute.max_ram_mb.or(detected_ram);

        if let Some(vram) = max_vram_mb {
            info!("Available VRAM: {} MB", vram);
        }
        if let Some(ram) = max_ram_mb {
            info!("Available RAM: {} MB", ram);
        }

        Ok(Self {
            supported_frameworks,
            max_vram_mb,
            max_ram_mb,
            concurrent_tasks: config.compute.concurrent_tasks,
            active_tasks: 0,
        })
    }

    /// Check if this node can handle the given requirements
    pub fn can_handle(&self, requirements: &ModelRequirements) -> bool {
        // Check framework support
        if !matches!(requirements.framework, Framework::Unknown(_)) {
            if !self.supported_frameworks.contains(&requirements.framework) {
                debug!("Framework {:?} not supported", requirements.framework);
                return false;
            }
        }

        // Check VRAM
        if let (Some(required), Some(available)) = (requirements.min_vram_mb, self.max_vram_mb) {
            if required > available {
                debug!(
                    "Insufficient VRAM: required {} MB, available {} MB",
                    required, available
                );
                return false;
            }
        }

        // Check RAM
        if let (Some(required), Some(available)) = (requirements.min_ram_mb, self.max_ram_mb) {
            if required > available {
                debug!(
                    "Insufficient RAM: required {} MB, available {} MB",
                    required, available
                );
                return false;
            }
        }

        // Check concurrent task limit
        if self.active_tasks >= self.concurrent_tasks {
            debug!("At concurrent task limit: {}", self.concurrent_tasks);
            return false;
        }

        true
    }

    /// Execute a model inference task from file paths
    pub async fn execute_from_paths(
        &mut self,
        model_path: &PathBuf,
        input_path: &PathBuf,
        requirements: &ModelRequirements,
    ) -> Result<Vec<u8>> {
        if !self.can_handle(requirements) {
            anyhow::bail!("Cannot handle task requirements");
        }

        self.active_tasks += 1;
        let result = self
            .execute_inner(model_path, input_path, requirements)
            .await;
        self.active_tasks -= 1;

        result
    }

    async fn execute_inner(
        &self,
        model_path: &PathBuf,
        input_path: &PathBuf,
        requirements: &ModelRequirements,
    ) -> Result<Vec<u8>> {
        info!("Executing inference task");
        info!("Model: {:?}", model_path);
        info!("Input: {:?}", input_path);

        match requirements.framework {
            Framework::ONNX => self.execute_onnx_file(model_path, input_path).await,
            Framework::PyTorch => self.execute_pytorch_file(model_path, input_path).await,
            Framework::TensorFlow => self.execute_tensorflow_file(model_path, input_path).await,
            Framework::Unknown(ref name) => {
                warn!("Unknown framework: {}", name);
                Err(anyhow::anyhow!("Unknown framework: {}", name))
            }
        }
    }

    #[cfg(feature = "compute")]
    async fn execute_onnx_file(
        &self,
        model_path: &PathBuf,
        input_path: &PathBuf,
    ) -> Result<Vec<u8>> {
        info!("Loading ONNX model from {:?}", model_path);

        // Load the ONNX model
        let mut session = Session::builder()?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .commit_from_file(model_path)
            .context("Failed to load ONNX model")?;

        // Load input data
        let input_bytes = tokio::fs::read(input_path)
            .await
            .context("Failed to read input file")?;

        // Run inference
        let result = self.run_onnx_inference(&mut session, &input_bytes)?;

        info!("Inference completed, output size: {} bytes", result.len());
        Ok(result)
    }

    #[cfg(not(feature = "compute"))]
    async fn execute_onnx_file(
        &self,
        _model_path: &PathBuf,
        _input_path: &PathBuf,
    ) -> Result<Vec<u8>> {
        anyhow::bail!("ONNX compute not available in this build (requires --features compute)")
    }

    /// Run ONNX inference with simplified API
    #[cfg(feature = "compute")]
    fn run_onnx_inference(&self, session: &mut Session, input_bytes: &[u8]) -> Result<Vec<u8>> {
        // Get input info
        let inputs = session.inputs();
        if inputs.is_empty() {
            anyhow::bail!("Model has no inputs");
        }

        let input_name = inputs[0].name().to_string();
        info!("Model input name: {}", input_name);

        // Parse input as f32 values with optional shape
        let (values, provided_shape) = self.parse_f32_input(input_bytes);
        info!("Parsed {} input values", values.len());

        // Determine shape: use provided shape or default to [1, N]
        let shape: Vec<i64> = if let Some(s) = provided_shape {
            info!("Using provided shape: {:?}", s);
            s
        } else {
            // Default: batch of 1, then all values
            let shape = vec![1, values.len() as i64];
            info!("Using default shape: {:?}", shape);
            shape
        };

        // Validate shape matches value count
        let expected_count: i64 = shape.iter().product();
        if expected_count != values.len() as i64 && expected_count > 0 {
            warn!(
                "Shape {:?} expects {} values but got {}. Adjusting...",
                shape,
                expected_count,
                values.len()
            );
            // Pad or truncate values to match expected count
            let mut adjusted_values = values.clone();
            adjusted_values.resize(expected_count as usize, 0.0);
            let input_tensor = ort::value::Tensor::from_array((shape.clone(), adjusted_values))?;
            return self.run_inference_with_tensor(session, &input_name, input_tensor);
        }

        // Create input tensor using tuple (shape, Vec<data>)
        let input_tensor = ort::value::Tensor::from_array((shape, values))?;
        self.run_inference_with_tensor(session, &input_name, input_tensor)
    }

    /// Helper to run inference with a prepared tensor
    #[cfg(feature = "compute")]
    fn run_inference_with_tensor(
        &self,
        session: &mut Session,
        input_name: &str,
        input_tensor: ort::value::Tensor<f32>,
    ) -> Result<Vec<u8>> {
        // Get output name before running (to avoid borrow conflicts)
        let output_name = session
            .outputs()
            .first()
            .map(|o| o.name().to_string())
            .unwrap_or_else(|| "output".to_string());

        info!("Running inference, output name: {}", output_name);

        // Run inference
        let outputs = session.run(ort::inputs![input_name => input_tensor])?;

        // Get output by name
        let output = outputs.get(&output_name).context("No output from model")?;

        // Extract output as bytes
        self.extract_tensor_bytes(output)
    }

    /// Parse input bytes as f32 values and optional shape
    fn parse_f32_input(&self, input_bytes: &[u8]) -> (Vec<f32>, Option<Vec<i64>>) {
        // Try JSON first
        if let Ok(json_str) = std::str::from_utf8(input_bytes) {
            // Try as simple Vec<f32>
            if let Ok(values) = serde_json::from_str::<Vec<f32>>(json_str) {
                return (values, None);
            }

            // Try as object with "input" field (and optional "shape")
            if let Ok(obj) = serde_json::from_str::<serde_json::Value>(json_str) {
                if let Some(input_arr) = obj
                    .get("input")
                    .or_else(|| obj.get("data"))
                    .or_else(|| obj.get("values"))
                {
                    if let Ok(values) = serde_json::from_value::<Vec<f32>>(input_arr.clone()) {
                        // Try to get shape
                        let shape = obj
                            .get("shape")
                            .and_then(|s| serde_json::from_value::<Vec<i64>>(s.clone()).ok());
                        return (values, shape);
                    }
                }

                // Try to extract params for batch input (temperature, pH, etc.)
                if let Some(params) = obj.get("params") {
                    if let Ok(param_obj) = serde_json::from_value::<
                        serde_json::Map<String, serde_json::Value>,
                    >(params.clone())
                    {
                        let values: Vec<f32> = param_obj
                            .values()
                            .filter_map(|v| v.as_f64().map(|f| f as f32))
                            .collect();
                        if !values.is_empty() {
                            return (values, None);
                        }
                    }
                }

                // Try to extract numeric values from any JSON object
                if let Some(map) = obj.as_object() {
                    let values: Vec<f32> = map
                        .values()
                        .filter_map(|v| v.as_f64().map(|f| f as f32))
                        .collect();
                    if !values.is_empty() {
                        return (values, None);
                    }
                }
            }
        }

        // Try raw f32 bytes (little-endian)
        if input_bytes.len() >= 4 && input_bytes.len() % 4 == 0 {
            let values: Vec<f32> = input_bytes
                .chunks_exact(4)
                .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                .collect();
            return (values, None);
        }

        // Fallback: return single zero
        warn!("Could not parse input, using zero");
        (vec![0.0f32], None)
    }

    /// Extract tensor output as JSON bytes for human-readable results
    #[cfg(feature = "compute")]
    fn extract_tensor_bytes(&self, output: &ort::value::Value) -> Result<Vec<u8>> {
        // Try f32 tensor - most common for inference outputs
        if let Ok(tensor) = output.try_extract_tensor::<f32>() {
            let (shape, data) = tensor;
            let values: Vec<f32> = data.iter().copied().collect();
            let shape_vec: Vec<i64> = shape.iter().map(|&d| d as i64).collect();
            info!(
                "Extracted f32 tensor: shape={:?}, {} values",
                shape_vec,
                values.len()
            );

            // Return as JSON for readability
            let json_output = serde_json::json!({
                "type": "f32",
                "shape": shape_vec,
                "values": values,
            });
            let bytes = serde_json::to_vec(&json_output)?;
            return Ok(bytes);
        }

        // Try i64 tensor
        if let Ok(tensor) = output.try_extract_tensor::<i64>() {
            let (shape, data) = tensor;
            let values: Vec<i64> = data.iter().copied().collect();
            let shape_vec: Vec<i64> = shape.iter().map(|&d| d as i64).collect();
            info!(
                "Extracted i64 tensor: shape={:?}, {} values",
                shape_vec,
                values.len()
            );

            let json_output = serde_json::json!({
                "type": "i64",
                "shape": shape_vec,
                "values": values,
            });
            let bytes = serde_json::to_vec(&json_output)?;
            return Ok(bytes);
        }

        // Try f64 tensor
        if let Ok(tensor) = output.try_extract_tensor::<f64>() {
            let (shape, data) = tensor;
            let values: Vec<f64> = data.iter().copied().collect();
            let shape_vec: Vec<i64> = shape.iter().map(|&d| d as i64).collect();
            info!(
                "Extracted f64 tensor: shape={:?}, {} values",
                shape_vec,
                values.len()
            );

            let json_output = serde_json::json!({
                "type": "f64",
                "shape": shape_vec,
                "values": values,
            });
            let bytes = serde_json::to_vec(&json_output)?;
            return Ok(bytes);
        }

        warn!("Could not extract tensor as known type, using raw bytes");
        Ok(vec![0u8; 32])
    }

    /// Execute a PyTorch TorchScript model (.pt / .pth) via a Python subprocess.
    ///
    /// Using a subprocess avoids linking against LibTorch at compile time (a
    /// multi-GB download). Node operators who want PyTorch support install
    /// Python + torch themselves; the node detects availability at runtime.
    async fn execute_pytorch_file(
        &self,
        model_path: &PathBuf,
        input_path: &PathBuf,
    ) -> Result<Vec<u8>> {
        // Python runner — loads a TorchScript model and returns JSON output
        // matching the same {"type","shape","values"} schema as the ONNX path.
        const PYTORCH_RUNNER: &str = r#"
import sys, json, os
import torch

model_path, input_path = sys.argv[1], sys.argv[2]

with open(input_path, 'rb') as f:
    raw = f.read()

try:
    data = json.loads(raw)
    if isinstance(data, list):
        values, shape = data, [1, len(data)]
    elif isinstance(data, dict):
        vals = data.get('input') or data.get('data') or data.get('values', [])
        shape = data.get('shape', [1, max(len(vals), 1)])
        values = vals
    else:
        values, shape = [float(data)], [1, 1]
except Exception:
    values, shape = [0.0], [1, 1]

model = torch.jit.load(model_path, map_location='cpu')
model.eval()
with torch.no_grad():
    t = torch.tensor(values, dtype=torch.float32).reshape(shape)
    out = model(t)
    out_list = out.flatten().tolist()
    out_shape = list(out.shape)

print(json.dumps({"type": "f32", "shape": out_shape, "values": out_list}), end='')
"#;

        info!(
            "Executing PyTorch model via Python subprocess: {:?}",
            model_path
        );

        let output = Command::new("python3")
            .args([
                "-c",
                PYTORCH_RUNNER,
                model_path.to_str().context("Invalid model path")?,
                input_path.to_str().context("Invalid input path")?,
            ])
            .output()
            .await
            .context(
                "Failed to spawn python3 for PyTorch execution — is Python + torch installed?",
            )?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("PyTorch runner failed: {}", stderr.trim()));
        }

        let stdout = output.stdout;
        if stdout.is_empty() {
            return Err(anyhow::anyhow!("PyTorch runner produced no output"));
        }

        debug!("PyTorch output: {} bytes", stdout.len());
        Ok(stdout)
    }

    /// Execute a TensorFlow model (SavedModel directory, .h5, or .pb) via a
    /// Python subprocess. Same subprocess rationale as PyTorch above.
    async fn execute_tensorflow_file(
        &self,
        model_path: &PathBuf,
        input_path: &PathBuf,
    ) -> Result<Vec<u8>> {
        const TF_RUNNER: &str = r#"
import sys, json, os
import numpy as np
import tensorflow as tf

model_path, input_path = sys.argv[1], sys.argv[2]

with open(input_path, 'rb') as f:
    raw = f.read()

try:
    data = json.loads(raw)
    if isinstance(data, list):
        values, shape = data, [1, len(data)]
    elif isinstance(data, dict):
        vals = data.get('input') or data.get('data') or data.get('values', [])
        shape = data.get('shape', [1, max(len(vals), 1)])
        values = vals
    else:
        values, shape = [float(data)], [1, 1]
except Exception:
    values, shape = [0.0], [1, 1]

arr = np.array(values, dtype=np.float32).reshape(shape)

if os.path.isdir(model_path):
    model = tf.saved_model.load(model_path)
    infer = model.signatures.get('serving_default')
    if infer:
        key = list(infer.structured_input_signature[1].keys())[0]
        result = infer(**{key: tf.constant(arr)})
        out = list(result.values())[0].numpy()
    else:
        out = model(arr).numpy()
else:
    model = tf.keras.models.load_model(model_path)
    out = model.predict(arr, verbose=0)

out_list = out.flatten().tolist()
out_shape = list(out.shape)
print(json.dumps({"type": "f32", "shape": out_shape, "values": out_list}), end='')
"#;

        info!(
            "Executing TensorFlow model via Python subprocess: {:?}",
            model_path
        );

        let output = Command::new("python3")
            .args([
                "-c",
                TF_RUNNER,
                model_path.to_str().context("Invalid model path")?,
                input_path.to_str().context("Invalid input path")?,
            ])
            .output()
            .await
            .context("Failed to spawn python3 for TensorFlow execution — is Python + tensorflow installed?")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "TensorFlow runner failed: {}",
                stderr.trim()
            ));
        }

        let stdout = output.stdout;
        if stdout.is_empty() {
            return Err(anyhow::anyhow!("TensorFlow runner produced no output"));
        }

        debug!("TensorFlow output: {} bytes", stdout.len());
        Ok(stdout)
    }

    /// Get current resource usage
    pub fn resource_usage(&self) -> ResourceUsage {
        ResourceUsage {
            active_tasks: self.active_tasks,
            max_tasks: self.concurrent_tasks,
            vram_available_mb: self.max_vram_mb,
            ram_available_mb: self.max_ram_mb,
        }
    }

    /// Check if this node can handle a task from the blockchain.
    pub fn can_handle_task(&self, _task: &TaskInfo) -> bool {
        if self.active_tasks >= self.concurrent_tasks {
            debug!("At concurrent task limit: {}", self.concurrent_tasks);
            return false;
        }
        // Accept tasks for any real framework we support
        self.supported_frameworks.iter().any(|f| {
            matches!(f, Framework::ONNX | Framework::PyTorch | Framework::TensorFlow)
        })
    }

    /// Execute a task with raw model and input data
    pub async fn execute(&self, model_data: &[u8], input_data: &[u8]) -> Result<Vec<u8>> {
        info!("Executing inference task");
        info!("Model size: {} bytes", model_data.len());
        info!("Input size: {} bytes", input_data.len());

        // Skip very small "models" (likely JSON metadata, not real models)
        if model_data.len() < 100 {
            info!(
                "Model too small ({} bytes), using placeholder mode",
                model_data.len()
            );
            return self.execute_placeholder(model_data, input_data);
        }

        // Try to run as ONNX model first (most common format)
        match self.execute_onnx_memory(model_data, input_data).await {
            Ok(result) => {
                info!(
                    "ONNX inference completed successfully, output: {} bytes",
                    result.len()
                );
                return Ok(result);
            }
            Err(e) => {
                debug!("ONNX inference failed: {}", e);
                // Check if it's a known non-ONNX format before warning
                if model_data.starts_with(b"{") || model_data.starts_with(b"[") {
                    info!("Model appears to be JSON metadata, using placeholder mode");
                } else {
                    warn!(
                        "ONNX inference failed: {}. Falling back to placeholder mode.",
                        e
                    );
                }
            }
        }

        // Try PyTorch or TensorFlow based on magic-byte detection
        match detect_framework(model_data) {
            Framework::PyTorch => {
                match self.execute_pytorch_memory(model_data, input_data).await {
                    Ok(r) => {
                        info!("PyTorch inference succeeded, output: {} bytes", r.len());
                        return Ok(r);
                    }
                    Err(e) => warn!("PyTorch inference failed: {}. Falling back to placeholder.", e),
                }
            }
            Framework::TensorFlow => {
                match self.execute_tensorflow_memory(model_data, input_data).await {
                    Ok(r) => {
                        info!("TensorFlow inference succeeded, output: {} bytes", r.len());
                        return Ok(r);
                    }
                    Err(e) => warn!("TensorFlow inference failed: {}. Falling back to placeholder.", e),
                }
            }
            _ => {}
        }

        // Fallback: Placeholder mode
        self.execute_placeholder(model_data, input_data)
    }

    /// Execute a model with an explicit framework hint (skips magic-byte detection).
    pub async fn execute_with_framework(
        &self,
        model_data: &[u8],
        input_data: &[u8],
        framework: &Framework,
    ) -> Result<Vec<u8>> {
        match framework {
            Framework::ONNX => self.execute_onnx_memory(model_data, input_data).await,
            Framework::PyTorch => self.execute_pytorch_memory(model_data, input_data).await,
            Framework::TensorFlow => self.execute_tensorflow_memory(model_data, input_data).await,
            Framework::Unknown(_) => self.execute(model_data, input_data).await,
        }
    }

    /// Placeholder execution - deterministic hash of model + input
    fn execute_placeholder(&self, model_data: &[u8], input_data: &[u8]) -> Result<Vec<u8>> {
        if model_data.is_empty() || input_data.is_empty() {
            warn!("Empty model or input data in placeholder mode");
        }

        let mut hasher = Keccak256::new();
        hasher.update(model_data);
        hasher.update(input_data);
        let result = hasher.finalize().to_vec();

        info!("Task execution completed (placeholder mode)");
        Ok(result)
    }

    /// Write model + input bytes to temp files, run PyTorch subprocess, clean up.
    async fn execute_pytorch_memory(
        &self,
        model_data: &[u8],
        input_data: &[u8],
    ) -> Result<Vec<u8>> {
        let hash = {
            let mut h = Keccak256::new();
            h.update(model_data);
            hex::encode(&h.finalize()[..8])
        };
        let model_path = PathBuf::from(format!("/tmp/oarn_model_{}.pt", hash));
        let input_path = PathBuf::from(format!("/tmp/oarn_input_{}.json", hash));

        tokio::fs::write(&model_path, model_data)
            .await
            .context("Failed to write PyTorch model to temp file")?;
        tokio::fs::write(&input_path, input_data)
            .await
            .context("Failed to write input to temp file")?;

        let result = self.execute_pytorch_file(&model_path, &input_path).await;

        let _ = tokio::fs::remove_file(&model_path).await;
        let _ = tokio::fs::remove_file(&input_path).await;

        result
    }

    /// Write model + input bytes to temp files, run TensorFlow subprocess, clean up.
    async fn execute_tensorflow_memory(
        &self,
        model_data: &[u8],
        input_data: &[u8],
    ) -> Result<Vec<u8>> {
        let hash = {
            let mut h = Keccak256::new();
            h.update(model_data);
            hex::encode(&h.finalize()[..8])
        };
        // Use .h5 for HDF5 Keras models, .pb for protobuf SavedModel
        let ext = if model_data.starts_with(&[0x89, 0x48, 0x44, 0x46]) { "h5" } else { "pb" };
        let model_path = PathBuf::from(format!("/tmp/oarn_model_{}.{}", hash, ext));
        let input_path = PathBuf::from(format!("/tmp/oarn_input_{}.json", hash));

        tokio::fs::write(&model_path, model_data)
            .await
            .context("Failed to write TF model to temp file")?;
        tokio::fs::write(&input_path, input_data)
            .await
            .context("Failed to write input to temp file")?;

        let result = self.execute_tensorflow_file(&model_path, &input_path).await;

        let _ = tokio::fs::remove_file(&model_path).await;
        let _ = tokio::fs::remove_file(&input_path).await;

        result
    }

    /// Execute ONNX model directly from memory
    #[cfg(feature = "compute")]
    async fn execute_onnx_memory(&self, model_data: &[u8], input_data: &[u8]) -> Result<Vec<u8>> {
        info!(
            "Loading ONNX model from memory ({} bytes)",
            model_data.len()
        );

        // Load the ONNX model from memory
        let mut session = Session::builder()?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .commit_from_memory(model_data)
            .context("Failed to load ONNX model from memory")?;

        info!("ONNX model loaded successfully");

        // Run inference using shared helper
        let result = self.run_onnx_inference(&mut session, input_data)?;
        info!("ONNX inference completed, output: {} bytes", result.len());

        Ok(result)
    }

    #[cfg(not(feature = "compute"))]
    async fn execute_onnx_memory(&self, _model_data: &[u8], _input_data: &[u8]) -> Result<Vec<u8>> {
        anyhow::bail!("ONNX compute not available in this build (requires --features compute)")
    }

    /// Hash a result for on-chain submission
    pub fn hash_result(&self, result: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(result);
        let hash = hasher.finalize();
        let mut result_hash = [0u8; 32];
        result_hash.copy_from_slice(&hash);
        result_hash
    }

    /// Execute a batch task with multiple inputs in parallel
    ///
    /// Returns a BatchResultManifest containing all results and aggregated hash
    pub async fn execute_batch(
        &self,
        task_id: u64,
        manifest: &BatchInputManifest,
        model_data: &[u8],
        node_address: &str,
        config: Option<BatchConfig>,
    ) -> Result<BatchResultManifest> {
        let config = config.unwrap_or_default();
        let start_time = Instant::now();

        info!(
            "Starting batch execution: {} inputs, {} max workers",
            manifest.inputs.len(),
            config.max_workers
        );

        // Configure thread pool
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(config.max_workers)
            .build()
            .context("Failed to build thread pool")?;

        // Share model data across threads
        let model_data = Arc::new(model_data.to_vec());
        let inputs = &manifest.inputs;

        // Process inputs in parallel
        let results: Vec<BatchResult> = pool.install(|| {
            inputs
                .par_iter()
                .map(|input| self.execute_single_input(input, &model_data))
                .collect()
        });

        let total_time_ms = start_time.elapsed().as_millis() as u64;

        info!(
            "Batch execution completed: {} results in {} ms",
            results.len(),
            total_time_ms
        );

        // Create result manifest
        let metadata = ExecutionMetadata {
            total_time_ms,
            parallel_workers: config.max_workers,
            framework: "onnx".to_string(),
            node_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        };

        let result_manifest = BatchResultManifest::new(
            task_id,
            manifest.model_cid.clone(), // Use model_cid as input_manifest_cid for now
            node_address.to_string(),
            results,
            metadata,
        );

        Ok(result_manifest)
    }

    /// Execute a single input from the batch
    fn execute_single_input(&self, input: &BatchInput, model_data: &[u8]) -> BatchResult {
        // Serialize params to JSON for input
        let input_json = serde_json::to_vec(&input.params).unwrap_or_default();

        // Execute inference (sync version for Rayon)
        let output = self.execute_sync(model_data, &input_json);

        // Parse output as JSON or create wrapper
        let output_value = match serde_json::from_slice::<serde_json::Value>(&output) {
            Ok(v) => v,
            Err(_) => {
                // Wrap raw bytes as hex in output
                serde_json::json!({
                    "raw_output": hex::encode(&output),
                    "output_size": output.len()
                })
            }
        };

        let hash = hash_result_output(&output_value);

        BatchResult {
            input_id: input.id,
            output: output_value,
            hash,
        }
    }

    /// Synchronous execution for use in Rayon parallel context.
    fn execute_sync(&self, model_data: &[u8], input_data: &[u8]) -> Vec<u8> {
        if model_data.len() < 100 {
            return self.execute_placeholder_sync(model_data, input_data);
        }

        // Try ONNX first
        match self.execute_onnx_sync(model_data, input_data) {
            Ok(r) => { debug!("ONNX sync inference succeeded: {} bytes", r.len()); return r; }
            Err(e) => { debug!("ONNX sync failed: {}", e); }
        }

        // Detect and try PyTorch / TensorFlow (subprocess, blocking)
        match detect_framework(model_data) {
            Framework::PyTorch => {
                match self.execute_pytorch_sync(model_data, input_data) {
                    Ok(r) => { debug!("PyTorch sync inference succeeded: {} bytes", r.len()); return r; }
                    Err(e) => { warn!("PyTorch sync failed: {}", e); }
                }
            }
            Framework::TensorFlow => {
                match self.execute_tensorflow_sync(model_data, input_data) {
                    Ok(r) => { debug!("TF sync inference succeeded: {} bytes", r.len()); return r; }
                    Err(e) => { warn!("TF sync failed: {}", e); }
                }
            }
            _ => {}
        }

        self.execute_placeholder_sync(model_data, input_data)
    }

    /// Synchronous PyTorch execution for Rayon context (uses std::process::Command).
    fn execute_pytorch_sync(&self, model_data: &[u8], input_data: &[u8]) -> Result<Vec<u8>> {
        let hash = hex::encode(&{
            let mut h = Keccak256::new();
            h.update(model_data);
            h.finalize()[..8].to_vec()
        });
        let model_path = format!("/tmp/oarn_sync_model_{}.pt", hash);
        let input_path = format!("/tmp/oarn_sync_input_{}.json", hash);

        std::fs::write(&model_path, model_data)
            .context("Failed to write PyTorch model (sync)")?;
        std::fs::write(&input_path, input_data)
            .context("Failed to write input (sync)")?;

        let result = self.run_python_subprocess_sync(
            include_str!("../scripts/pytorch_runner.py"),
            &model_path,
            &input_path,
            "PyTorch",
        );

        let _ = std::fs::remove_file(&model_path);
        let _ = std::fs::remove_file(&input_path);
        result
    }

    /// Synchronous TensorFlow execution for Rayon context.
    fn execute_tensorflow_sync(&self, model_data: &[u8], input_data: &[u8]) -> Result<Vec<u8>> {
        let hash = hex::encode(&{
            let mut h = Keccak256::new();
            h.update(model_data);
            h.finalize()[..8].to_vec()
        });
        let ext = if model_data.starts_with(&[0x89, 0x48, 0x44, 0x46]) { "h5" } else { "pb" };
        let model_path = format!("/tmp/oarn_sync_model_{}.{}", hash, ext);
        let input_path = format!("/tmp/oarn_sync_input_{}.json", hash);

        std::fs::write(&model_path, model_data)
            .context("Failed to write TF model (sync)")?;
        std::fs::write(&input_path, input_data)
            .context("Failed to write input (sync)")?;

        let result = self.run_python_subprocess_sync(
            include_str!("../scripts/tensorflow_runner.py"),
            &model_path,
            &input_path,
            "TensorFlow",
        );

        let _ = std::fs::remove_file(&model_path);
        let _ = std::fs::remove_file(&input_path);
        result
    }

    /// Shared blocking subprocess helper for Rayon context.
    fn run_python_subprocess_sync(
        &self,
        script: &str,
        model_path: &str,
        input_path: &str,
        label: &str,
    ) -> Result<Vec<u8>> {
        let output = std::process::Command::new("python3")
            .args(["-c", script, model_path, input_path])
            .output()
            .with_context(|| format!("Failed to spawn python3 for {} (sync)", label))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("{} runner (sync) failed: {}", label, stderr.trim());
        }
        if output.stdout.is_empty() {
            anyhow::bail!("{} runner (sync) produced no output", label);
        }
        Ok(output.stdout)
    }

    /// Synchronous placeholder execution
    fn execute_placeholder_sync(&self, model_data: &[u8], input_data: &[u8]) -> Vec<u8> {
        let mut hasher = Keccak256::new();
        hasher.update(model_data);
        hasher.update(input_data);
        hasher.finalize().to_vec()
    }

    #[cfg(feature = "compute")]
    fn execute_onnx_sync(&self, model_data: &[u8], input_data: &[u8]) -> Result<Vec<u8>> {
        let mut session = Session::builder()?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .commit_from_memory(model_data)
            .context("Failed to load ONNX model")?;

        self.run_onnx_inference(&mut session, input_data)
    }

    #[cfg(not(feature = "compute"))]
    fn execute_onnx_sync(&self, _model_data: &[u8], _input_data: &[u8]) -> Result<Vec<u8>> {
        anyhow::bail!("ONNX compute not available in this build (requires --features compute)")
    }
}

/// Current resource usage
#[derive(Debug, Clone)]
pub struct ResourceUsage {
    pub active_tasks: usize,
    pub max_tasks: usize,
    pub vram_available_mb: Option<u64>,
    pub ram_available_mb: Option<u64>,
}

/// Detect available system resources
fn detect_resources() -> (Option<u64>, Option<u64>) {
    // RAM detection using sysinfo
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_memory();
    let ram_mb = Some(sys.total_memory() / (1024 * 1024)); // Convert bytes to MB

    // VRAM detection via nvidia-smi (CUDA) or rocm-smi (ROCm)
    let vram_mb = detect_vram_nvidia().or_else(detect_vram_rocm);

    (vram_mb, ram_mb)
}

/// Detect VRAM via nvidia-smi (CUDA GPUs).
/// Returns total VRAM in MB for the first GPU found, or None if CUDA unavailable.
fn detect_vram_nvidia() -> Option<u64> {
    let output = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=memory.total", "--format=csv,noheader,nounits"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    // nvidia-smi returns one line per GPU in MiB; take the first GPU
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .next()
        .and_then(|line| line.trim().parse::<u64>().ok())
}

/// Detect VRAM via rocm-smi (AMD ROCm GPUs).
/// Returns total VRAM in MB for the first GPU found, or None if ROCm unavailable.
fn detect_vram_rocm() -> Option<u64> {
    // rocm-smi --showmeminfo vram prints lines like:
    //   GPU[0]          : VRAM Total Memory (B): 17163091968
    let output = std::process::Command::new("rocm-smi")
        .args(["--showmeminfo", "vram"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains("VRAM Total Memory (B):") {
            let bytes: u64 = line
                .split(':')
                .last()?
                .trim()
                .parse()
                .ok()?;
            return Some(bytes / (1024 * 1024));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_framework_from_str_onnx() {
        assert_eq!(Framework::from("onnx"), Framework::ONNX);
        assert_eq!(Framework::from("ONNX"), Framework::ONNX);
    }

    #[test]
    fn test_framework_from_str_pytorch() {
        assert_eq!(Framework::from("pytorch"), Framework::PyTorch);
        assert_eq!(Framework::from("PyTorch"), Framework::PyTorch);
        assert_eq!(Framework::from("torch"), Framework::PyTorch);
    }

    #[test]
    fn test_framework_from_str_tensorflow() {
        assert_eq!(Framework::from("tensorflow"), Framework::TensorFlow);
        assert_eq!(Framework::from("TensorFlow"), Framework::TensorFlow);
        assert_eq!(Framework::from("tf"), Framework::TensorFlow);
    }

    #[test]
    fn test_framework_from_str_unknown() {
        let framework = Framework::from("custom_framework");
        assert!(matches!(framework, Framework::Unknown(s) if s == "custom_framework"));
    }

    #[test]
    fn test_parse_memory_string_gb() {
        assert_eq!(parse_memory_string("8GB"), Some(8192)); // 8 * 1024
        assert_eq!(parse_memory_string("16gb"), Some(16384));
        assert_eq!(parse_memory_string("1GB"), Some(1024));
    }

    #[test]
    fn test_parse_memory_string_mb() {
        assert_eq!(parse_memory_string("4096MB"), Some(4096));
        assert_eq!(parse_memory_string("512mb"), Some(512));
    }

    #[test]
    fn test_parse_memory_string_plain() {
        assert_eq!(parse_memory_string("1024"), Some(1024));
    }

    #[test]
    fn test_parse_memory_string_invalid() {
        assert_eq!(parse_memory_string("invalid"), None);
        assert_eq!(parse_memory_string(""), None);
    }

    #[test]
    fn test_model_requirements_from_json() {
        let json =
            r#"{"framework": "onnx", "min_vram": "4GB", "min_ram": "8GB", "gpu_required": true}"#;
        let requirements = ModelRequirements::from_json(json).unwrap();

        assert_eq!(requirements.framework, Framework::ONNX);
        assert_eq!(requirements.min_vram_mb, Some(4096));
        assert_eq!(requirements.min_ram_mb, Some(8192));
        assert!(requirements.gpu_required);
    }

    #[test]
    fn test_model_requirements_from_json_minimal() {
        let json = r#"{}"#;
        let requirements = ModelRequirements::from_json(json).unwrap();

        assert!(matches!(requirements.framework, Framework::Unknown(_)));
        assert!(requirements.min_vram_mb.is_none());
        assert!(requirements.min_ram_mb.is_none());
        assert!(!requirements.gpu_required);
    }

    #[test]
    fn test_model_requirements_from_json_partial() {
        let json = r#"{"framework": "pytorch", "gpu_required": false}"#;
        let requirements = ModelRequirements::from_json(json).unwrap();

        assert_eq!(requirements.framework, Framework::PyTorch);
        assert!(requirements.min_vram_mb.is_none());
        assert!(!requirements.gpu_required);
    }

    #[test]
    fn test_compute_engine_new() {
        let config = crate::config::Config::default();
        let engine = ComputeEngine::new(&config).unwrap();

        assert!(engine.supported_frameworks.contains(&Framework::ONNX));
        assert!(engine.supported_frameworks.contains(&Framework::PyTorch));
        assert_eq!(engine.concurrent_tasks, 1);
        assert_eq!(engine.active_tasks, 0);
    }

    #[test]
    fn test_compute_engine_can_handle_supported_framework() {
        let config = crate::config::Config::default();
        let engine = ComputeEngine::new(&config).unwrap();

        let requirements = ModelRequirements {
            framework: Framework::ONNX,
            min_vram_mb: None,
            min_ram_mb: None,
            gpu_required: false,
        };

        assert!(engine.can_handle(&requirements));
    }

    #[test]
    fn test_compute_engine_can_handle_unsupported_framework() {
        let config = crate::config::Config::default();
        let engine = ComputeEngine::new(&config).unwrap();

        let requirements = ModelRequirements {
            framework: Framework::TensorFlow,
            min_vram_mb: None,
            min_ram_mb: None,
            gpu_required: false,
        };

        // TensorFlow is not in default frameworks
        assert!(!engine.can_handle(&requirements));
    }

    #[test]
    fn test_compute_engine_can_handle_unknown_framework() {
        let config = crate::config::Config::default();
        let engine = ComputeEngine::new(&config).unwrap();

        let requirements = ModelRequirements {
            framework: Framework::Unknown("custom".to_string()),
            min_vram_mb: None,
            min_ram_mb: None,
            gpu_required: false,
        };

        // Unknown frameworks should be allowed (flexible)
        assert!(engine.can_handle(&requirements));
    }

    #[test]
    fn test_compute_engine_resource_usage() {
        let config = crate::config::Config::default();
        let engine = ComputeEngine::new(&config).unwrap();

        let usage = engine.resource_usage();
        assert_eq!(usage.active_tasks, 0);
        assert_eq!(usage.max_tasks, 1);
    }

    #[test]
    fn test_detect_resources() {
        let (vram, ram) = detect_resources();

        // VRAM is Some if nvidia-smi/rocm-smi is available, None otherwise — both are valid
        if let Some(v) = vram {
            assert!(v > 0, "detected VRAM should be > 0 MB");
        }

        // RAM should be detected
        assert!(ram.is_some());
        assert!(ram.unwrap() > 0);
    }

    #[test]
    fn test_resource_usage_clone() {
        let usage = ResourceUsage {
            active_tasks: 1,
            max_tasks: 4,
            vram_available_mb: Some(8192),
            ram_available_mb: Some(16384),
        };

        let cloned = usage.clone();
        assert_eq!(cloned.active_tasks, 1);
        assert_eq!(cloned.max_tasks, 4);
    }
}
