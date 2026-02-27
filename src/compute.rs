//! Compute/inference engine
//!
//! Handles AI model execution using ONNX Runtime.

use anyhow::{Context, Result};
use ort::session::{builder::GraphOptimizationLevel, Session};
use sha3::{Digest, Keccak256};
use std::path::PathBuf;
use tracing::{debug, info, warn};

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

        let framework = value.get("framework")
            .and_then(|v| v.as_str())
            .map(Framework::from)
            .unwrap_or(Framework::Unknown("unspecified".to_string()));

        let min_vram_mb = value.get("min_vram")
            .and_then(|v| v.as_str())
            .and_then(|s| parse_memory_string(s));

        let min_ram_mb = value.get("min_ram")
            .and_then(|v| v.as_str())
            .and_then(|s| parse_memory_string(s));

        let gpu_required = value.get("gpu_required")
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

/// Parse memory string like "8GB" or "4096MB"
fn parse_memory_string(s: &str) -> Option<u64> {
    let s = s.to_uppercase();
    if s.ends_with("GB") {
        s.trim_end_matches("GB").parse::<u64>().ok().map(|v| v * 1024)
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
        let supported_frameworks: Vec<Framework> = config.compute.frameworks
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
                debug!("Insufficient VRAM: required {} MB, available {} MB", required, available);
                return false;
            }
        }

        // Check RAM
        if let (Some(required), Some(available)) = (requirements.min_ram_mb, self.max_ram_mb) {
            if required > available {
                debug!("Insufficient RAM: required {} MB, available {} MB", required, available);
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
        let result = self.execute_inner(model_path, input_path, requirements).await;
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
            Framework::ONNX => {
                self.execute_onnx_file(model_path, input_path).await
            }
            Framework::PyTorch => {
                self.execute_pytorch_file(model_path, input_path).await
            }
            Framework::TensorFlow => {
                self.execute_tensorflow_file(model_path, input_path).await
            }
            Framework::Unknown(ref name) => {
                warn!("Unknown framework: {}", name);
                Err(anyhow::anyhow!("Unknown framework: {}", name))
            }
        }
    }

    async fn execute_onnx_file(&self, model_path: &PathBuf, input_path: &PathBuf) -> Result<Vec<u8>> {
        info!("Loading ONNX model from {:?}", model_path);

        // Load the ONNX model
        let mut session = Session::builder()?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .commit_from_file(model_path)
            .context("Failed to load ONNX model")?;

        // Load input data
        let input_bytes = tokio::fs::read(input_path).await
            .context("Failed to read input file")?;

        // Run inference
        let result = self.run_onnx_inference(&mut session, &input_bytes)?;

        info!("Inference completed, output size: {} bytes", result.len());
        Ok(result)
    }

    /// Run ONNX inference with simplified API
    fn run_onnx_inference(&self, session: &mut Session, input_bytes: &[u8]) -> Result<Vec<u8>> {
        // Get input info
        let inputs = session.inputs();
        if inputs.is_empty() {
            anyhow::bail!("Model has no inputs");
        }

        let input_name = inputs[0].name().to_string();
        info!("Model input name: {}", input_name);

        // Parse input as f32 values
        let values = self.parse_f32_input(input_bytes);
        info!("Parsed {} input values", values.len());

        // Use simple 1D shape for now - models should specify their shape
        let shape: Vec<i64> = vec![1, values.len() as i64];

        // Create input tensor using tuple (shape, Vec<data>)
        let input_tensor = ort::value::Tensor::from_array((shape, values))?;

        // Get output name before running (to avoid borrow conflicts)
        let output_name = session.outputs().first()
            .map(|o| o.name().to_string())
            .unwrap_or_else(|| "output".to_string());

        // Run inference
        let outputs = session.run(ort::inputs![input_name => input_tensor])?;

        // Get output by name
        let output = outputs.get(&output_name)
            .context("No output from model")?;

        // Extract output as bytes
        self.extract_tensor_bytes(output)
    }

    /// Parse input bytes as f32 values
    fn parse_f32_input(&self, input_bytes: &[u8]) -> Vec<f32> {
        // Try JSON first
        if let Ok(json_str) = std::str::from_utf8(input_bytes) {
            if let Ok(values) = serde_json::from_str::<Vec<f32>>(json_str) {
                return values;
            }
        }

        // Try raw f32 bytes
        if input_bytes.len() >= 4 && input_bytes.len() % 4 == 0 {
            return input_bytes
                .chunks_exact(4)
                .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                .collect();
        }

        // Fallback: return single zero
        warn!("Could not parse input, using zero");
        vec![0.0f32]
    }

    /// Extract tensor output as bytes
    fn extract_tensor_bytes(&self, output: &ort::value::Value) -> Result<Vec<u8>> {
        // Try f32 tensor
        if let Ok(tensor) = output.try_extract_tensor::<f32>() {
            let (_, data) = tensor;
            let bytes: Vec<u8> = data.iter()
                .flat_map(|f| f.to_le_bytes())
                .collect();
            info!("Extracted f32 tensor: {} bytes", bytes.len());
            return Ok(bytes);
        }

        // Try i64 tensor
        if let Ok(tensor) = output.try_extract_tensor::<i64>() {
            let (_, data) = tensor;
            let bytes: Vec<u8> = data.iter()
                .flat_map(|i| i.to_le_bytes())
                .collect();
            info!("Extracted i64 tensor: {} bytes", bytes.len());
            return Ok(bytes);
        }

        warn!("Could not extract tensor, using placeholder");
        Ok(vec![0u8; 32])
    }

    async fn execute_pytorch_file(&self, _model_path: &PathBuf, _input_path: &PathBuf) -> Result<Vec<u8>> {
        // TODO: Implement PyTorch execution via tch-rs
        info!("PyTorch execution not yet implemented");
        Ok(vec![0u8; 32])
    }

    async fn execute_tensorflow_file(&self, _model_path: &PathBuf, _input_path: &PathBuf) -> Result<Vec<u8>> {
        // TODO: Implement TensorFlow execution
        info!("TensorFlow execution not yet implemented");
        Ok(vec![0u8; 32])
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

    /// Check if this node can handle a task from the blockchain
    pub fn can_handle_task(&self, _task: &TaskInfo) -> bool {
        // For now, check concurrent task limit
        // TODO: Parse model requirements from task metadata
        if self.active_tasks >= self.concurrent_tasks {
            debug!("At concurrent task limit: {}", self.concurrent_tasks);
            return false;
        }

        // Assume we can handle ONNX tasks
        if self.supported_frameworks.contains(&Framework::ONNX) {
            return true;
        }

        false
    }

    /// Execute a task with raw model and input data
    pub async fn execute(&self, model_data: &[u8], input_data: &[u8]) -> Result<Vec<u8>> {
        info!("Executing inference task");
        info!("Model size: {} bytes", model_data.len());
        info!("Input size: {} bytes", input_data.len());

        // Check if this looks like a real ONNX model (starts with ONNX magic bytes)
        let is_onnx = model_data.len() > 8 && &model_data[0..4] == b"\x08\x00"
            || (model_data.len() > 4 && model_data[0] == 0x08); // Protobuf ONNX header

        if is_onnx && model_data.len() > 100 {
            // Try to run real ONNX inference
            match self.execute_onnx_memory(model_data, input_data).await {
                Ok(result) => {
                    info!("ONNX inference completed successfully");
                    return Ok(result);
                }
                Err(e) => {
                    warn!("ONNX inference failed: {}. Falling back to placeholder mode.", e);
                }
            }
        }

        // Fallback: Placeholder mode - hash model + input to produce a deterministic result
        if model_data.is_empty() || input_data.is_empty() {
            warn!("Empty model or input data - using placeholder mode");
        } else {
            info!("Using placeholder execution mode (model not recognized as ONNX)");
        }

        let mut hasher = Keccak256::new();
        hasher.update(model_data);
        hasher.update(input_data);
        let result = hasher.finalize().to_vec();

        info!("Task execution completed (placeholder mode)");
        Ok(result)
    }

    /// Execute ONNX model directly from memory
    async fn execute_onnx_memory(&self, model_data: &[u8], input_data: &[u8]) -> Result<Vec<u8>> {
        info!("Loading ONNX model from memory ({} bytes)", model_data.len());

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

    /// Hash a result for on-chain submission
    pub fn hash_result(&self, result: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(result);
        let hash = hasher.finalize();
        let mut result_hash = [0u8; 32];
        result_hash.copy_from_slice(&hash);
        result_hash
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

    // VRAM detection would require GPU-specific libraries
    // TODO: Implement CUDA/ROCm detection
    let vram_mb = None;

    (vram_mb, ram_mb)
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
        let json = r#"{"framework": "onnx", "min_vram": "4GB", "min_ram": "8GB", "gpu_required": true}"#;
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

        // VRAM detection not implemented, should be None
        assert!(vram.is_none());

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
