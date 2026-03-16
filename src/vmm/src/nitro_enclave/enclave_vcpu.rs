// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! CPU pool management for Nitro Enclaves.
//!
//! Reads the NE CPU pool from sysfs and selects CPUs for the enclave.

use std::fs;

const NE_CPUS_PATH: &str = "/sys/module/nitro_enclaves/parameters/ne_cpus";

/// Errors from CPU pool operations.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum CpuPoolError {
    /// Failed to read NE CPU pool from sysfs: {0}
    ReadPool(std::io::Error),
    /// NE CPU pool is empty or not configured
    EmptyPool,
    /// Not enough CPUs in the NE pool: need {needed}, have {available}
    NotEnoughCpus {
        /// Number of CPUs requested.
        needed: u32,
        /// Number of CPUs available in the pool.
        available: u32,
    },
    /// Invalid CPU pool format: {0}
    InvalidFormat(String),
}

/// Parse the NE CPU pool string (e.g., "2-3" or "2,3,5" or "1-3,5").
///
/// Returns a sorted list of CPU IDs.
pub fn parse_cpu_pool(pool_str: &str) -> Result<Vec<u32>, CpuPoolError> {
    let pool_str = pool_str.trim();
    if pool_str.is_empty() {
        return Err(CpuPoolError::EmptyPool);
    }

    let mut cpus = Vec::new();
    for part in pool_str.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let bounds: Vec<&str> = part.splitn(2, '-').collect();
            if bounds.len() != 2 {
                return Err(CpuPoolError::InvalidFormat(part.to_string()));
            }
            let start: u32 = bounds[0]
                .trim()
                .parse()
                .map_err(|_| CpuPoolError::InvalidFormat(part.to_string()))?;
            let end: u32 = bounds[1]
                .trim()
                .parse()
                .map_err(|_| CpuPoolError::InvalidFormat(part.to_string()))?;
            if start > end {
                return Err(CpuPoolError::InvalidFormat(part.to_string()));
            }
            cpus.extend(start..=end);
        } else {
            let cpu: u32 = part
                .parse()
                .map_err(|_| CpuPoolError::InvalidFormat(part.to_string()))?;
            cpus.push(cpu);
        }
    }

    cpus.sort_unstable();
    cpus.dedup();

    if cpus.is_empty() {
        return Err(CpuPoolError::EmptyPool);
    }

    Ok(cpus)
}

/// Read the NE CPU pool from sysfs.
pub fn read_cpu_pool() -> Result<Vec<u32>, CpuPoolError> {
    let pool_str = fs::read_to_string(NE_CPUS_PATH).map_err(CpuPoolError::ReadPool)?;
    parse_cpu_pool(&pool_str)
}

/// Auto-select `count` CPUs from the NE CPU pool.
///
/// If `cpu_ids` is provided, validates they are in the pool and returns them.
/// Otherwise, picks the first `count` CPUs from the pool.
pub fn select_cpus(cpu_ids: Option<&[u32]>, count: u32) -> Result<Vec<u32>, CpuPoolError> {
    // If explicit CPU IDs are provided, use them directly without reading sysfs.
    // This is needed when running inside a jailer where sysfs may not be available.
    if let Some(ids) = cpu_ids {
        return Ok(ids.to_vec());
    }

    let pool = read_cpu_pool()?;
    if pool.len() < count as usize {
        return Err(CpuPoolError::NotEnoughCpus {
            needed: count,
            available: pool.len() as u32,
        });
    }
    Ok(pool[..count as usize].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cpu_pool_range() {
        let cpus = parse_cpu_pool("2-5").unwrap();
        assert_eq!(cpus, vec![2, 3, 4, 5]);
    }

    #[test]
    fn test_parse_cpu_pool_list() {
        let cpus = parse_cpu_pool("1,3,5").unwrap();
        assert_eq!(cpus, vec![1, 3, 5]);
    }

    #[test]
    fn test_parse_cpu_pool_mixed() {
        let cpus = parse_cpu_pool("1-3,5,7-8").unwrap();
        assert_eq!(cpus, vec![1, 2, 3, 5, 7, 8]);
    }

    #[test]
    fn test_parse_cpu_pool_single() {
        let cpus = parse_cpu_pool("4").unwrap();
        assert_eq!(cpus, vec![4]);
    }

    #[test]
    fn test_parse_cpu_pool_with_newline() {
        let cpus = parse_cpu_pool("2-3\n").unwrap();
        assert_eq!(cpus, vec![2, 3]);
    }

    #[test]
    fn test_parse_cpu_pool_empty() {
        assert!(parse_cpu_pool("").is_err());
    }

    #[test]
    fn test_parse_cpu_pool_invalid() {
        assert!(parse_cpu_pool("abc").is_err());
    }

    #[test]
    fn test_parse_cpu_pool_reversed_range() {
        assert!(parse_cpu_pool("5-2").is_err());
    }

    #[test]
    fn test_parse_cpu_pool_dedup() {
        let cpus = parse_cpu_pool("2-4,3-5").unwrap();
        assert_eq!(cpus, vec![2, 3, 4, 5]);
    }
}
