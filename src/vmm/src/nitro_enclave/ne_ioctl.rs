// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Nitro Enclaves kernel ioctl bindings.
//!
//! These structures and constants match `/usr/include/linux/nitro_enclaves.h`.

use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};

// NE ioctl magic number
const NE_MAGIC: u8 = 0xAE;

// ioctl request codes for /dev/nitro_enclaves
// Computed as u64 to avoid overflow in const context, then cast at call site.
/// Create a new enclave VM. Returns an enclave fd via return value.
pub const NE_CREATE_VM: u64 = nix_ioctl_read!(NE_MAGIC, 0x20, u64);
/// Add a vCPU to the enclave.
pub const NE_ADD_VCPU: u64 = nix_ioctl_readwrite!(NE_MAGIC, 0x21, u32);
/// Get image load info (memory offset).
pub const NE_GET_IMAGE_LOAD_INFO: u64 = nix_ioctl_readwrite!(NE_MAGIC, 0x22, NeImageLoadInfo);
/// Set a user memory region for the enclave.
pub const NE_SET_USER_MEMORY_REGION: u64 = nix_ioctl_write!(NE_MAGIC, 0x23, NeUserMemoryRegion);
/// Start the enclave.
pub const NE_START_ENCLAVE: u64 = nix_ioctl_readwrite!(NE_MAGIC, 0x24, NeEnclaveStartInfo);

// Macros for building ioctl numbers (matching Linux kernel conventions)
// _IOC(dir, type, nr, size) = (dir << 30) | (size << 16) | (type << 8) | nr

macro_rules! nix_ioctl_read {
    ($magic:expr, $nr:expr, $ty:ty) => {
        (2u64 << 30)
            | ((std::mem::size_of::<$ty>() as u64) << 16)
            | (($magic as u64) << 8)
            | ($nr as u64)
    };
}

macro_rules! nix_ioctl_write {
    ($magic:expr, $nr:expr, $ty:ty) => {
        (1u64 << 30)
            | ((std::mem::size_of::<$ty>() as u64) << 16)
            | (($magic as u64) << 8)
            | ($nr as u64)
    };
}

macro_rules! nix_ioctl_readwrite {
    ($magic:expr, $nr:expr, $ty:ty) => {
        (3u64 << 30)
            | ((std::mem::size_of::<$ty>() as u64) << 16)
            | (($magic as u64) << 8)
            | ($nr as u64)
    };
}

/// Helper to call ioctl with a u64 request code, casting to libc::Ioctl
/// (which is i32 on musl, u64 on glibc).
///
/// # Safety
/// Caller must ensure the fd, request, and arg are valid for the given ioctl.
unsafe fn ne_ioctl(fd: i32, request: u64, arg: *mut libc::c_void) -> i32 {
    // SAFETY: Caller guarantees valid fd, request, and arg.
    unsafe { libc::ioctl(fd, request as libc::Ioctl, arg) }
}

// Re-export macros for use within this file (macros must be defined before use)
use nix_ioctl_read;
use nix_ioctl_readwrite;
use nix_ioctl_write;

/// NE image load info flags
pub mod image_load_flags {
    /// Load image in enclave memory.
    pub const NE_EIF_IMAGE: u64 = 0x01;
}

/// NE enclave start flags
pub mod start_flags {
    /// Start enclave in debug mode.
    pub const NE_ENCLAVE_DEBUG_MODE: u64 = 1;
}

/// Information about where to load the enclave image.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NeImageLoadInfo {
    /// Flags for image loading (e.g., `NE_EIF_IMAGE`).
    pub flags: u64,
    /// Memory offset where the image should be loaded (output).
    pub memory_offset: u64,
}

/// Describes a user memory region to be added to the enclave.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NeUserMemoryRegion {
    /// Flags (currently must be 0).
    pub flags: u64,
    /// Size of the memory region in bytes.
    pub memory_size: u64,
    /// Userspace address of the memory region.
    pub userspace_addr: u64,
}

/// Information for starting the enclave.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NeEnclaveStartInfo {
    /// Flags (e.g., `NE_ENCLAVE_DEBUG_MODE`).
    pub flags: u64,
    /// Enclave CID (0 = auto-assign, filled in on return).
    pub enclave_cid: u64,
}

/// Safe wrapper around the `/dev/nitro_enclaves` device fd.
#[derive(Debug)]
pub struct NitroEnclaveFd {
    fd: OwnedFd,
}

impl NitroEnclaveFd {
    /// Open `/dev/nitro_enclaves`.
    pub fn open() -> std::io::Result<Self> {
        use std::fs::OpenOptions;
        use std::os::unix::io::IntoRawFd;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/nitro_enclaves")?;
        let raw_fd = file.into_raw_fd();
        // SAFETY: We just obtained this fd from a successful open().
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        Ok(Self { fd })
    }

    /// Create a new enclave VM. Returns the enclave fd.
    pub fn create_vm(&self) -> std::io::Result<OwnedFd> {
        let mut slot: u64 = 0;
        // SAFETY: NE_CREATE_VM ioctl on a valid NE device fd.
        let ret = unsafe {
            ne_ioctl(
                self.fd.as_raw_fd(),
                NE_CREATE_VM,
                (&mut slot as *mut u64).cast(),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // The ioctl returns the enclave fd as the return value.
        // SAFETY: The kernel returned a valid fd.
        Ok(unsafe { OwnedFd::from_raw_fd(ret) })
    }
}

/// Safe wrapper around an enclave instance fd.
#[derive(Debug)]
pub struct EnclaveFd {
    fd: OwnedFd,
}

impl EnclaveFd {
    /// Create from an owned fd returned by `NE_CREATE_VM`.
    pub fn new(fd: OwnedFd) -> Self {
        Self { fd }
    }

    /// Add a vCPU to the enclave.
    pub fn add_vcpu(&self, cpu_id: u32) -> std::io::Result<()> {
        let mut id = cpu_id;
        // SAFETY: NE_ADD_VCPU ioctl on a valid enclave fd.
        let ret = unsafe {
            ne_ioctl(
                self.fd.as_raw_fd(),
                NE_ADD_VCPU,
                (&mut id as *mut u32).cast(),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Get the memory offset where the enclave image should be loaded.
    pub fn get_image_load_info(&self) -> std::io::Result<NeImageLoadInfo> {
        let mut info = NeImageLoadInfo {
            flags: image_load_flags::NE_EIF_IMAGE,
            memory_offset: 0,
        };
        // SAFETY: NE_GET_IMAGE_LOAD_INFO ioctl on a valid enclave fd.
        let ret = unsafe {
            ne_ioctl(
                self.fd.as_raw_fd(),
                NE_GET_IMAGE_LOAD_INFO,
                (&mut info as *mut NeImageLoadInfo).cast(),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(info)
    }

    /// Set a user memory region for the enclave.
    pub fn set_user_memory_region(&self, addr: u64, size: u64) -> std::io::Result<()> {
        let mut region = NeUserMemoryRegion {
            flags: 0,
            memory_size: size,
            userspace_addr: addr,
        };
        // SAFETY: NE_SET_USER_MEMORY_REGION ioctl on a valid enclave fd.
        let ret = unsafe {
            ne_ioctl(
                self.fd.as_raw_fd(),
                NE_SET_USER_MEMORY_REGION,
                (&mut region as *mut NeUserMemoryRegion).cast(),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Start the enclave. Returns the assigned CID.
    pub fn start(&self, debug: bool, cid: u64) -> std::io::Result<u64> {
        let mut info = NeEnclaveStartInfo {
            flags: if debug {
                start_flags::NE_ENCLAVE_DEBUG_MODE
            } else {
                0
            },
            enclave_cid: cid,
        };
        // SAFETY: NE_START_ENCLAVE ioctl on a valid enclave fd.
        let ret = unsafe {
            ne_ioctl(
                self.fd.as_raw_fd(),
                NE_START_ENCLAVE,
                (&mut info as *mut NeEnclaveStartInfo).cast(),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(info.enclave_cid)
    }

    /// Get the raw fd for polling.
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

use std::os::unix::io::FromRawFd;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ne_ioctl_struct_sizes() {
        assert_eq!(std::mem::size_of::<NeImageLoadInfo>(), 16);
        assert_eq!(std::mem::size_of::<NeUserMemoryRegion>(), 24);
        assert_eq!(std::mem::size_of::<NeEnclaveStartInfo>(), 16);
    }
}
