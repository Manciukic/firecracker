// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Nitro Enclaves VM lifecycle management.
//!
//! Wraps the NE kernel API to create, configure, and start an enclave.

use vm_memory::{Bytes, GuestMemoryRegion, MemoryRegionAddress};

use crate::nitro_enclave::ne_ioctl::{EnclaveFd, NitroEnclaveFd};
use crate::vmm_config::machine_config::HugePageConfig;
use crate::vstate::memory::{self, GuestRegionMmap, MemoryError};

/// Errors from enclave VM operations.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum EnclaveVmError {
    /// Failed to open /dev/nitro_enclaves: {0}
    OpenDevice(std::io::Error),
    /// Failed to create enclave VM: {0}
    CreateVm(std::io::Error),
    /// Failed to add vCPU {cpu_id}: {source}
    AddVcpu {
        /// vCPU ID that failed.
        cpu_id: u32,
        /// Underlying error.
        source: std::io::Error,
    },
    /// Failed to allocate enclave memory: {0}
    AllocateMemory(MemoryError),
    /// Failed to set user memory region: {0}
    SetMemoryRegion(std::io::Error),
    /// Failed to get image load info: {0}
    GetImageLoadInfo(std::io::Error),
    /// Failed to start enclave: {0}
    StartEnclave(std::io::Error),
    /// Image offset {offset} + image size {image_size} exceeds allocated memory {mem_size}
    ImageTooLarge {
        /// Offset from NE_GET_IMAGE_LOAD_INFO.
        offset: u64,
        /// EIF image size.
        image_size: u64,
        /// Total memory allocated.
        mem_size: u64,
    },
    /// Failed to get host address from memory region: {0}
    GetHostAddress(vm_memory::guest_memory::Error),
    /// Failed to write EIF into memory region: {0}
    WriteEif(vm_memory::guest_memory::Error),
}

/// Manages the lifecycle of a Nitro Enclave VM.
#[derive(Debug)]
pub struct EnclaveVm {
    _dev_fd: NitroEnclaveFd,
    enclave_fd: EnclaveFd,
    memory_regions: Vec<GuestRegionMmap>,
    vcpu_ids: Vec<u32>,
    enclave_cid: Option<u64>,
    debug_mode: bool,
}

impl EnclaveVm {
    /// Create a new enclave VM by opening `/dev/nitro_enclaves` and issuing `NE_CREATE_VM`.
    pub fn new() -> Result<Self, EnclaveVmError> {
        let dev_fd = NitroEnclaveFd::open().map_err(EnclaveVmError::OpenDevice)?;
        let enclave_raw_fd = dev_fd.create_vm().map_err(EnclaveVmError::CreateVm)?;

        Ok(Self {
            _dev_fd: dev_fd,
            enclave_fd: EnclaveFd::new(enclave_raw_fd),
            memory_regions: Vec::new(),
            vcpu_ids: Vec::new(),
            enclave_cid: None,
            debug_mode: false,
        })
    }

    /// Add a vCPU to the enclave.
    pub fn add_vcpu(&mut self, cpu_id: u32) -> Result<(), EnclaveVmError> {
        self.enclave_fd
            .add_vcpu(cpu_id)
            .map_err(|e| EnclaveVmError::AddVcpu { cpu_id, source: e })?;
        self.vcpu_ids.push(cpu_id);
        Ok(())
    }

    /// Allocate hugepage memory, copy the EIF image into it, then donate
    /// the memory to the NE driver.
    ///
    /// The EIF must be written into the hugepages **before** calling
    /// `NE_SET_USER_MEMORY_REGION`, because that ioctl donates the pages
    /// to the enclave and userspace can no longer access them.
    pub fn load_and_add_memory(
        &mut self,
        size: usize,
        huge_pages: HugePageConfig,
        eif_data: &[u8],
    ) -> Result<(), EnclaveVmError> {
        // 1. Allocate hugepage region using the standard vm-memory infrastructure
        let region =
            memory::enclave_region(size, huge_pages).map_err(EnclaveVmError::AllocateMemory)?;

        // 2. Get image load offset
        let info = self
            .enclave_fd
            .get_image_load_info()
            .map_err(EnclaveVmError::GetImageLoadInfo)?;
        let offset = info.memory_offset as usize;

        if offset as u64 + eif_data.len() as u64 > region.len() {
            return Err(EnclaveVmError::ImageTooLarge {
                offset: offset as u64,
                image_size: eif_data.len() as u64,
                mem_size: region.len(),
            });
        }

        // 3. Copy EIF into the region BEFORE donating
        region
            .write_slice(eif_data, MemoryRegionAddress(offset as u64))
            .map_err(EnclaveVmError::WriteEif)?;

        // 4. Donate memory to the enclave
        let addr = region
            .get_host_address(MemoryRegionAddress(0))
            .map_err(EnclaveVmError::GetHostAddress)? as u64;
        self.enclave_fd
            .set_user_memory_region(addr, region.len())
            .map_err(EnclaveVmError::SetMemoryRegion)?;

        self.memory_regions.push(region);
        Ok(())
    }

    /// Start the enclave.
    pub fn start(&mut self, debug: bool, cid: u64) -> Result<u64, EnclaveVmError> {
        let assigned_cid = self
            .enclave_fd
            .start(debug, cid)
            .map_err(EnclaveVmError::StartEnclave)?;
        self.enclave_cid = Some(assigned_cid);
        self.debug_mode = debug;
        Ok(assigned_cid)
    }

    /// Get the enclave CID (available after start).
    pub fn enclave_cid(&self) -> Option<u64> {
        self.enclave_cid
    }

    /// Get the raw enclave fd for event polling (e.g., to detect HUP).
    pub fn enclave_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.enclave_fd.as_raw_fd()
    }

    /// Get the list of vCPU IDs assigned to this enclave.
    pub fn vcpu_ids(&self) -> &[u32] {
        &self.vcpu_ids
    }

    /// Whether the enclave was started in debug mode.
    pub fn debug_mode(&self) -> bool {
        self.debug_mode
    }
}
