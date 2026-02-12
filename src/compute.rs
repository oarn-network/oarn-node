//! Compute/inference engine
//!
//! Handles AI model execution in a sandboxed environment

use anyhow::Result;
use std::path::PathBuf;
use tracing::{debug, info, warn};

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

    /// Execute a model inference task
    pub async fn execute(
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
                self.execute_onnx(model_path, input_path).await
            }
            Framework::PyTorch => {
                self.execute_pytorch(model_path, input_path).await
            }
            Framework::TensorFlow => {
                self.execute_tensorflow(model_path, input_path).await
            }
            Framework::Unknown(ref name) => {
                warn!("Unknown framework: {}", name);
                Err(anyhow::anyhow!("Unknown framework: {}", name))
            }
        }
    }

    async fn execute_onnx(&self, _model_path: &PathBuf, _input_path: &PathBuf) -> Result<Vec<u8>> {
        // TODO: Implement ONNX Runtime execution
        // For now, return placeholder
        info!("ONNX execution not yet implemented");
        Ok(vec![0u8; 32]) // Placeholder result
    }

    async fn execute_pytorch(&self, _model_path: &PathBuf, _input_path: &PathBuf) -> Result<Vec<u8>> {
        // TODO: Implement PyTorch execution via tch-rs
        info!("PyTorch execution not yet implemented");
        Ok(vec![0u8; 32])
    }

    async fn execute_tensorflow(&self, _model_path: &PathBuf, _input_path: &PathBuf) -> Result<Vec<u8>> {
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
