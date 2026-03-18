// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for Nitro Enclaves support.

#![allow(clippy::tests_outside_test_module)]

use std::fs;

use vmm::nitro_enclave::eif;
use vmm::nitro_enclave::enclave_vcpu;
use vmm::nitro_enclave::ne_ioctl::{NeEnclaveStartInfo, NeImageLoadInfo, NeUserMemoryRegion};
use vmm::resources::VmResources;
use vmm::vmm_config::enclave::EnclaveConfig;

// ---- Config Parsing Tests ----

#[test]
fn test_enclave_config_parsing() {
    let json = r#"{
        "boot-source": {
            "kernel_image_path": "/tmp/kernel",
            "initrd_path": "/tmp/initrd",
            "boot_args": "console=ttyS0"
        },
        "drives": [],
        "machine-config": {
            "vcpu_count": 2,
            "mem_size_mib": 256
        },
        "enclave": {
            "debug_mode": true,
            "enclave_cid": 42
        }
    }"#;

    let vmm_config: vmm::resources::VmmConfig = serde_json::from_str(json).unwrap();
    assert!(vmm_config.enclave.is_some());
    let enclave = vmm_config.enclave.unwrap();
    assert!(enclave.debug_mode);
    assert_eq!(enclave.enclave_cid, Some(42));
    assert_eq!(enclave.cpu_ids, None);
}

#[test]
fn test_enclave_config_absent() {
    let json = r#"{
        "boot-source": {
            "kernel_image_path": "/tmp/kernel"
        },
        "drives": []
    }"#;

    let vmm_config: vmm::resources::VmmConfig = serde_json::from_str(json).unwrap();
    assert!(vmm_config.enclave.is_none());
}

#[test]
fn test_enclave_config_serde_roundtrip() {
    let config = EnclaveConfig {
        cpu_ids: Some(vec![2, 3]),
        debug_mode: true,
        enclave_cid: Some(100),
    };
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: EnclaveConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, deserialized);
}

// ---- EIF Builder Tests ----

#[test]
fn test_eif_builder_basic() {
    let dir = tempfile::tempdir().unwrap();
    let kernel_path = dir.path().join("kernel");
    let initrd_path = dir.path().join("initrd");

    fs::write(&kernel_path, b"FAKE_KERNEL_DATA_FOR_TESTING").unwrap();
    fs::write(&initrd_path, b"FAKE_INITRD_DATA_FOR_TESTING").unwrap();

    let eif = eif::build_eif(
        &kernel_path,
        &initrd_path,
        "console=ttyS0 reboot=k panic=1",
        256 * 1024 * 1024,
        2,
    )
    .unwrap();

    // Check magic bytes
    assert_eq!(&eif[0..4], &[0x2e, 0x65, 0x69, 0x66]);
    // Check version (big-endian u16)
    assert_eq!(u16::from_be_bytes([eif[4], eif[5]]), 4);
    // Check reserved(u16) + num_sections(u16) at offset 24
    assert_eq!(u16::from_be_bytes([eif[24], eif[25]]), 0); // reserved
    assert_eq!(u16::from_be_bytes([eif[26], eif[27]]), 4); // num_sections
    // Check total size is reasonable
    assert!(eif.len() > 548); // > header size
}

#[test]
fn test_eif_builder_empty_kernel() {
    let dir = tempfile::tempdir().unwrap();
    let kernel_path = dir.path().join("kernel");
    let initrd_path = dir.path().join("initrd");

    fs::write(&kernel_path, b"").unwrap();
    fs::write(&initrd_path, b"initrd").unwrap();

    let result = eif::build_eif(&kernel_path, &initrd_path, "", 256 * 1024 * 1024, 2);
    assert!(result.is_err());
}

#[test]
fn test_eif_builder_missing_kernel() {
    let dir = tempfile::tempdir().unwrap();
    let kernel_path = dir.path().join("nonexistent_kernel");
    let initrd_path = dir.path().join("initrd");

    fs::write(&initrd_path, b"initrd").unwrap();

    let result = eif::build_eif(&kernel_path, &initrd_path, "", 256 * 1024 * 1024, 2);
    assert!(result.is_err());
}

// ---- NE ioctl Struct Size Tests ----

#[test]
fn test_ne_ioctl_struct_sizes() {
    // These must match the C ABI from linux/nitro_enclaves.h
    assert_eq!(std::mem::size_of::<NeImageLoadInfo>(), 16);
    assert_eq!(std::mem::size_of::<NeUserMemoryRegion>(), 24);
    assert_eq!(std::mem::size_of::<NeEnclaveStartInfo>(), 16);
}

#[test]
fn test_ne_ioctl_struct_alignment() {
    assert_eq!(std::mem::align_of::<NeImageLoadInfo>(), 8);
    assert_eq!(std::mem::align_of::<NeUserMemoryRegion>(), 8);
    assert_eq!(std::mem::align_of::<NeEnclaveStartInfo>(), 8);
}

// ---- CPU Pool Parsing Tests ----

#[test]
fn test_cpu_pool_parsing_range() {
    let cpus = enclave_vcpu::parse_cpu_pool("2-5").unwrap();
    assert_eq!(cpus, vec![2, 3, 4, 5]);
}

#[test]
fn test_cpu_pool_parsing_list() {
    let cpus = enclave_vcpu::parse_cpu_pool("1,3,5,7").unwrap();
    assert_eq!(cpus, vec![1, 3, 5, 7]);
}

#[test]
fn test_cpu_pool_parsing_mixed() {
    let cpus = enclave_vcpu::parse_cpu_pool("1-3,5,7-8").unwrap();
    assert_eq!(cpus, vec![1, 2, 3, 5, 7, 8]);
}

#[test]
fn test_cpu_pool_parsing_single() {
    let cpus = enclave_vcpu::parse_cpu_pool("4").unwrap();
    assert_eq!(cpus, vec![4]);
}

#[test]
fn test_cpu_pool_parsing_with_whitespace() {
    let cpus = enclave_vcpu::parse_cpu_pool("  2-3\n").unwrap();
    assert_eq!(cpus, vec![2, 3]);
}

#[test]
fn test_cpu_pool_parsing_empty() {
    assert!(enclave_vcpu::parse_cpu_pool("").is_err());
    assert!(enclave_vcpu::parse_cpu_pool("   ").is_err());
}

#[test]
fn test_cpu_pool_parsing_invalid() {
    assert!(enclave_vcpu::parse_cpu_pool("abc").is_err());
    assert!(enclave_vcpu::parse_cpu_pool("5-2").is_err());
}

#[test]
fn test_cpu_pool_dedup() {
    let cpus = enclave_vcpu::parse_cpu_pool("2-4,3-5").unwrap();
    assert_eq!(cpus, vec![2, 3, 4, 5]);
}

// ---- Hardware-dependent tests (require NE-capable instance) ----

/// This test requires Nitro Enclaves hardware and a configured CPU pool.
/// Run with: `ARTIFACT_DIR=<path> cargo test -p vmm --test enclave_tests -- --ignored`
#[test]
#[ignore]
fn test_build_and_boot_enclave() {
    use vmm::EventManager;
    use vmm::nitro_enclave::enclave_builder;
    use vmm::vmm_config::boot_source::BootSourceConfig;
    use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
    use vmm::vmm_config::machine_config::MachineConfigUpdate;

    let artifact_dir = std::env::var("ARTIFACT_DIR").unwrap_or_else(|_| {
        let fc_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let current = fc_root.join("build/current_artifacts");
        let content = fs::read_to_string(&current)
            .unwrap_or_else(|e| panic!("Cannot read {}: {e}", current.display()));
        fc_root
            .join(content.trim())
            .to_string_lossy()
            .into_owned()
    });
    let artifact_path = std::path::Path::new(&artifact_dir);

    // Find a bzImage-* kernel in the artifact directory
    let kernel_path = fs::read_dir(artifact_path)
        .expect("Cannot read artifact directory")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("bzImage-"))
        })
        .unwrap_or_else(|| panic!("No bzImage-* found in {artifact_dir}"));

    let initrd_path = artifact_path.join("initramfs.cpio");
    assert!(
        initrd_path.exists(),
        "initramfs.cpio not found in {artifact_dir}"
    );

    let instance_info = InstanceInfo {
        id: "test-enclave".to_string(),
        state: VmState::NotStarted,
        vmm_version: "test".to_string(),
        app_name: "test".to_string(),
    };

    let boot_source_config = BootSourceConfig {
        kernel_image_path: kernel_path.to_string_lossy().into_owned(),
        initrd_path: Some(initrd_path.to_string_lossy().into_owned()),
        boot_args: Some("console=ttyS0 reboot=k panic=1".to_string()),
    };

    let mut vm_resources = VmResources::default();
    vm_resources
        .build_boot_source(boot_source_config)
        .expect("Failed to set boot source");

    let machine_update = MachineConfigUpdate {
        vcpu_count: Some(2),
        mem_size_mib: Some(256),
        huge_pages: Some(vmm::vmm_config::machine_config::HugePageConfig::Hugetlbfs2M),
        ..Default::default()
    };
    vm_resources
        .update_machine_config(&machine_update)
        .expect("Failed to update machine config");

    let enclave_config = EnclaveConfig {
        cpu_ids: None,
        debug_mode: true,
        enclave_cid: None,
    };

    let mut event_manager = EventManager::new().expect("Unable to create EventManager");

    let enclave_vmm = enclave_builder::build_and_boot_enclave(
        &instance_info,
        &vm_resources,
        &enclave_config,
        &mut event_manager,
    )
    .expect("Failed to build and boot enclave");

    drop(enclave_vmm);
}
