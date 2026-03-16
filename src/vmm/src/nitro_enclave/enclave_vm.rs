// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Nitro Enclaves VM lifecycle management.
//!
//! Wraps the NE kernel API to create, configure, and start an enclave.

use crate::nitro_enclave::ne_ioctl::{EnclaveFd, NitroEnclaveFd};

/// A hugepage-backed memory region for the enclave.
#[derive(Debug)]
pub struct HugepageRegion {
    addr: *mut u8,
    size: usize,
}

// SAFETY: The pointer in HugepageRegion is from mmap and is only used by the enclave.
unsafe impl Send for HugepageRegion {}

impl HugepageRegion {
    /// Allocate a hugepage-backed memory region.
    ///
    /// `mmap_flags` should include `MAP_HUGETLB | MAP_HUGE_2MB` for 2MB hugepages.
    pub fn allocate(size: usize, mmap_flags: libc::c_int) -> std::io::Result<Self> {
        // SAFETY: We're requesting an anonymous private mapping backed by hugepages.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | mmap_flags,
                -1,
                0,
            )
        };

        if addr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            addr: addr.cast::<u8>(),
            size,
        })
    }

    /// Get the base address of the region.
    pub fn addr(&self) -> *mut u8 {
        self.addr
    }

    /// Get the size of the region in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get the base address as u64 for ioctl calls.
    pub fn addr_u64(&self) -> u64 {
        self.addr as u64
    }
}

impl Drop for HugepageRegion {
    fn drop(&mut self) {
        // SAFETY: We allocated this region with mmap and own it exclusively.
        unsafe {
            libc::munmap(self.addr.cast(), self.size);
        }
    }
}

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
    /// Failed to allocate hugepage memory: {0}
    AllocateMemory(std::io::Error),
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
}

/// Manages the lifecycle of a Nitro Enclave VM.
#[derive(Debug)]
pub struct EnclaveVm {
    _dev_fd: NitroEnclaveFd,
    enclave_fd: EnclaveFd,
    memory_regions: Vec<HugepageRegion>,
    vcpu_ids: Vec<u32>,
    enclave_cid: Option<u64>,
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
        })
    }

    /// Add a vCPU to the enclave.
    pub fn add_vcpu(&mut self, cpu_id: u32) -> Result<(), EnclaveVmError> {
        self.enclave_fd
            .add_vcpu(cpu_id)
            .map_err(|e| EnclaveVmError::AddVcpu {
                cpu_id,
                source: e,
            })?;
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
        mmap_flags: libc::c_int,
        eif_data: &[u8],
    ) -> Result<(), EnclaveVmError> {
        // 1. Allocate hugepage region
        let region =
            HugepageRegion::allocate(size, mmap_flags).map_err(EnclaveVmError::AllocateMemory)?;

        // 2. Get image load offset
        let info = self
            .enclave_fd
            .get_image_load_info()
            .map_err(EnclaveVmError::GetImageLoadInfo)?;
        let offset = info.memory_offset as usize;

        if offset + eif_data.len() > region.size() {
            return Err(EnclaveVmError::ImageTooLarge {
                offset: offset as u64,
                image_size: eif_data.len() as u64,
                mem_size: region.size() as u64,
            });
        }

        // 3. Copy EIF into the hugepage region BEFORE donating
        // SAFETY: We just allocated this region and confirmed bounds above.
        unsafe {
            std::ptr::copy_nonoverlapping(
                eif_data.as_ptr(),
                region.addr().add(offset),
                eif_data.len(),
            );
        }

        // 4. Donate memory to the enclave
        self.enclave_fd
            .set_user_memory_region(region.addr_u64(), region.size() as u64)
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
}
