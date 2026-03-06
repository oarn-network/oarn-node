//! Batch Task Types and Utilities
//!
//! This module provides types and utilities for handling batch tasks,
//! where a single task contains multiple input parameter combinations
//! that are executed in parallel.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

// ============================================
// Batch Input Types
// ============================================

/// Single input parameter set for batch processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchInput {
    pub id: usize,
    pub params: serde_json::Value,
}

/// Manifest containing all inputs for a batch task
/// Uploaded to IPFS, hash stored on-chain as inputHash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchInputManifest {
    pub version: String,
    #[serde(rename = "type")]
    pub manifest_type: String,
    pub model_cid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_schema: Option<serde_json::Value>,
    pub inputs: Vec<BatchInput>,
    pub total_count: usize,
    pub checksum: String,
}

impl BatchInputManifest {
    /// Check if this is a valid batch input manifest
    pub fn is_valid(&self) -> bool {
        self.version == "1.0"
            && self.manifest_type == "batch_input_manifest"
            && !self.model_cid.is_empty()
            && self.inputs.len() == self.total_count
    }

    /// Parse from JSON bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let manifest: BatchInputManifest = serde_json::from_slice(data)
            .map_err(|e| anyhow!("Failed to parse batch input manifest: {}", e))?;

        if !manifest.is_valid() {
            return Err(anyhow!("Invalid batch input manifest"));
        }

        Ok(manifest)
    }

    /// Try to parse data as batch manifest, returns None if not a batch manifest
    pub fn try_from_bytes(data: &[u8]) -> Option<Self> {
        Self::from_bytes(data).ok()
    }
}

// ============================================
// Batch Result Types
// ============================================

/// Single result from batch execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult {
    pub input_id: usize,
    pub output: serde_json::Value,
    pub hash: String,
}

/// Execution metadata for batch processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionMetadata {
    pub total_time_ms: u64,
    pub parallel_workers: usize,
    pub framework: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_version: Option<String>,
}

/// Manifest containing all results from batch execution
/// Created by nodes, uploaded to IPFS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResultManifest {
    pub version: String,
    #[serde(rename = "type")]
    pub manifest_type: String,
    pub task_id: u64,
    pub input_manifest_cid: String,
    pub node_address: String,
    pub results: Vec<BatchResult>,
    pub aggregated_hash: String,
    pub execution_metadata: ExecutionMetadata,
}

impl BatchResultManifest {
    /// Create a new batch result manifest
    pub fn new(
        task_id: u64,
        input_manifest_cid: String,
        node_address: String,
        results: Vec<BatchResult>,
        execution_metadata: ExecutionMetadata,
    ) -> Self {
        let aggregated_hash = compute_aggregated_hash(&results);

        Self {
            version: "1.0".to_string(),
            manifest_type: "batch_result_manifest".to_string(),
            task_id,
            input_manifest_cid,
            node_address,
            results,
            aggregated_hash,
            execution_metadata,
        }
    }

    /// Serialize to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| anyhow!("Failed to serialize batch result manifest: {}", e))
    }
}

// ============================================
// Hash Utilities
// ============================================

/// Compute deterministic aggregated hash from results
/// Results are sorted by input_id for determinism
pub fn compute_aggregated_hash(results: &[BatchResult]) -> String {
    // Sort by input_id
    let mut sorted: Vec<_> = results.iter().collect();
    sorted.sort_by_key(|r| r.input_id);

    // Concatenate all result hashes
    let concatenated: String = sorted.iter().map(|r| r.hash.as_str()).collect();

    // Compute keccak256 of concatenated hashes
    let mut hasher = Keccak256::new();
    hasher.update(concatenated.as_bytes());
    let result = hasher.finalize();

    format!("0x{}", hex::encode(result))
}

/// Compute keccak256 hash of arbitrary data
pub fn keccak256_hash(data: &[u8]) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("0x{}", hex::encode(result))
}

/// Hash a single result output
pub fn hash_result_output(output: &serde_json::Value) -> String {
    let serialized = serde_json::to_string(output).unwrap_or_default();
    keccak256_hash(serialized.as_bytes())
}

// ============================================
// Batch Processing Configuration
// ============================================

/// Configuration for batch processing
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Maximum number of parallel workers (default: num_cpus)
    pub max_workers: usize,
    /// Chunk size for processing (inputs per batch)
    pub chunk_size: usize,
    /// Whether to report progress
    pub report_progress: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_workers: num_cpus::get(),
            chunk_size: 100,
            report_progress: true,
        }
    }
}

impl BatchConfig {
    /// Create config with specified worker count
    pub fn with_workers(workers: usize) -> Self {
        Self {
            max_workers: workers,
            ..Default::default()
        }
    }

    /// Calculate optimal chunk size based on total inputs
    pub fn optimal_chunk_size(&self, total_inputs: usize) -> usize {
        let min_chunks = self.max_workers;
        let ideal_chunk_size = total_inputs / min_chunks;

        // Clamp between 10 and 1000
        ideal_chunk_size.clamp(10, 1000)
    }
}

// ============================================
// Tests
// ============================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_input_manifest_parsing() {
        let json = r#"{
            "version": "1.0",
            "type": "batch_input_manifest",
            "model_cid": "QmTest123",
            "inputs": [
                {"id": 0, "params": {"temperature": 25.0}},
                {"id": 1, "params": {"temperature": 30.0}}
            ],
            "total_count": 2,
            "checksum": "0xabc123"
        }"#;

        let manifest = BatchInputManifest::from_bytes(json.as_bytes()).unwrap();
        assert_eq!(manifest.version, "1.0");
        assert_eq!(manifest.inputs.len(), 2);
        assert!(manifest.is_valid());
    }

    #[test]
    fn test_try_from_bytes_non_batch() {
        let non_batch = r#"{"some": "random", "data": 123}"#;
        let result = BatchInputManifest::try_from_bytes(non_batch.as_bytes());
        assert!(result.is_none());
    }

    #[test]
    fn test_aggregated_hash_determinism() {
        let results = vec![
            BatchResult {
                input_id: 1,
                output: serde_json::json!({"yield": 0.5}),
                hash: "0xabc".to_string(),
            },
            BatchResult {
                input_id: 0,
                output: serde_json::json!({"yield": 0.3}),
                hash: "0x123".to_string(),
            },
        ];

        let hash1 = compute_aggregated_hash(&results);

        // Reverse order - should produce same hash due to sorting
        let reversed = vec![results[1].clone(), results[0].clone()];
        let hash2 = compute_aggregated_hash(&reversed);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_batch_result_manifest_creation() {
        let results = vec![
            BatchResult {
                input_id: 0,
                output: serde_json::json!({"yield": 0.5}),
                hash: "0x123".to_string(),
            },
        ];

        let metadata = ExecutionMetadata {
            total_time_ms: 1000,
            parallel_workers: 4,
            framework: "onnx".to_string(),
            node_version: Some("0.1.0".to_string()),
        };

        let manifest = BatchResultManifest::new(
            42,
            "QmInput123".to_string(),
            "0xNode".to_string(),
            results,
            metadata,
        );

        assert_eq!(manifest.task_id, 42);
        assert_eq!(manifest.version, "1.0");
        assert!(!manifest.aggregated_hash.is_empty());
    }
}
