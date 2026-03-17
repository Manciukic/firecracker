// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Enclave build orchestrator.
//!
//! Loads a pre-built EIF image or builds one from kernel+initrd+boot_args,
//! then boots a Nitro Enclave from `VmResources`.

use std::path::Path;
use std::sync::{Arc, Mutex};

use event_manager::SubscriberOps;

use crate::device_manager::DeviceManager;
use crate::logger::info;
use crate::nitro_enclave::eif;
use crate::nitro_enclave::enclave_vcpu;
use crate::nitro_enclave::enclave_vm::EnclaveVm;
use crate::nitro_enclave::heartbeat;
use crate::nitro_enclave::vsock_console::VsockConsole;
use crate::resources::VmResources;
use crate::utils::mib_to_bytes;
use crate::vmm_config::enclave::EnclaveConfig;
use crate::vmm_config::instance_info::{InstanceInfo, VmState};
use crate::vstate::vm::Vm;
use crate::{EventManager, Vmm};

/// Errors from building and booting an enclave.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum EnclaveBuilderError {
    /// Boot source not configured (kernel_image_path required)
    NoBootSource,
    /// Failed to read EIF image: {0}
    ReadEif(std::io::Error),
    /// initrd_path is required when kernel_image_path is not a pre-built EIF
    NoInitrd,
    /// Failed to build EIF from kernel+initrd: {0}
    EifBuild(#[from] eif::EifError),
    /// Enclave VM error: {0}
    EnclaveVm(#[from] crate::nitro_enclave::enclave_vm::EnclaveVmError),
    /// CPU selection error: {0}
    CpuSelection(#[from] enclave_vcpu::CpuPoolError),
    /// Console error: {0}
    Console(#[from] crate::nitro_enclave::vsock_console::VsockConsoleError),
}

/// Build and boot a Nitro Enclave from the given VM resources and enclave config.
///
/// If `kernel_image_path` points to a pre-built EIF file (detected by magic bytes),
/// it is loaded directly. Otherwise, an EIF is built from `kernel_image_path` +
/// `initrd_path` + `boot_args`.
pub fn build_and_boot_enclave(
    instance_info: &InstanceInfo,
    vm_resources: &VmResources,
    enclave_config: &EnclaveConfig,
    event_manager: &mut EventManager,
) -> Result<Arc<Mutex<Vmm>>, EnclaveBuilderError> {
    // 1. Get boot config
    let _boot_config = vm_resources
        .boot_source
        .builder
        .as_ref()
        .ok_or(EnclaveBuilderError::NoBootSource)?;
    let kernel_path = &vm_resources.boot_source.config.kernel_image_path;

    // 2. Load or build EIF
    let eif_data = if eif::is_eif(Path::new(kernel_path)) {
        info!("Loading pre-built EIF from {kernel_path}");
        std::fs::read(kernel_path).map_err(EnclaveBuilderError::ReadEif)?
    } else {
        let initrd_path = vm_resources
            .boot_source
            .config
            .initrd_path
            .as_deref()
            .ok_or(EnclaveBuilderError::NoInitrd)?;
        let boot_args = vm_resources
            .boot_source
            .config
            .boot_args
            .as_deref()
            .unwrap_or("");
        let default_mem = mib_to_bytes(vm_resources.machine_config.mem_size_mib) as u64;
        let default_cpus = vm_resources.machine_config.vcpu_count as u64;
        info!("Building EIF from kernel={kernel_path} initrd={initrd_path}");
        eif::build_eif(
            Path::new(kernel_path),
            Path::new(initrd_path),
            boot_args,
            default_mem,
            default_cpus,
        )?
    };
    info!("EIF ready: {} bytes", eif_data.len());

    // 3. Create enclave VM
    let mut enclave_vm = EnclaveVm::new()?;
    info!("Enclave VM created");

    // 4. Add vCPUs
    let vcpu_count = vm_resources.machine_config.vcpu_count as u32;
    let cpu_ids = enclave_vcpu::select_cpus(enclave_config.cpu_ids.as_deref(), vcpu_count)?;
    for &cpu_id in &cpu_ids {
        enclave_vm.add_vcpu(cpu_id)?;
    }
    info!("Added {} vCPUs: {:?}", cpu_ids.len(), cpu_ids);

    // 5. Allocate hugepage memory, copy EIF, then donate to NE.
    let mem_size = mib_to_bytes(vm_resources.machine_config.mem_size_mib);
    enclave_vm.load_and_add_memory(mem_size, vm_resources.machine_config.huge_pages, &eif_data)?;
    info!(
        "Allocated {} MiB, loaded EIF, and donated memory to enclave",
        vm_resources.machine_config.mem_size_mib
    );

    // 7. Start enclave
    let cid = enclave_config.enclave_cid.unwrap_or(0);
    let assigned_cid = enclave_vm.start(enclave_config.debug_mode, cid)?;
    info!("Enclave started with CID={assigned_cid}");

    // 8. Debug mode: vsock console
    if enclave_config.debug_mode {
        info!("Starting vsock console for CID={assigned_cid}");
        let console = VsockConsole::connect(assigned_cid, vm_resources.serial_out_path.as_deref())?;
        event_manager.add_subscriber(Arc::new(Mutex::new(console)));
    }

    // 9. Build unified Vmm with Vm::Enclave and register with event manager.
    //    Initial state is Booting — transitions to Running on heartbeat.
    let mut info = instance_info.clone();
    info.state = VmState::Booting;
    let vmm = Vmm {
        instance_info: info,
        machine_config: vm_resources.machine_config.clone(),
        boot_source_config: vm_resources.boot_source.config.clone(),
        shutdown_exit_code: None,
        vm: Arc::new(Vm::Enclave(enclave_vm)),
        kvm: None,
        uffd: None,
        vcpus_handles: Vec::new(),
        vcpus_exit_evt: None,
        device_manager: DeviceManager::new_without_legacy(),
    };
    let vmm = Arc::new(Mutex::new(vmm));
    event_manager.add_subscriber(vmm.clone());

    // 10. Heartbeat — the enclave sends 0xB7 on vsock port 9000 at boot.
    //     On success, transitions Vmm state from Booting → Running.
    match heartbeat::Heartbeat::new(vmm.clone()) {
        Ok(hb) => {
            event_manager.add_subscriber(Arc::new(Mutex::new(hb)));
            info!("Heartbeat listener registered on vsock port 9000");
        }
        Err(e) => info!("Heartbeat setup failed (non-fatal): {e}"),
    }

    Ok(vmm)
}
