// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! EIF (Enclave Image Format) builder.
//!
//! Builds an EIF image in memory from kernel, initrd, and command line,
//! matching the format expected by the Nitro Enclaves kernel module.
//!
//! The EIF format uses big-endian byte order throughout, matching the
//! `aws-nitro-enclaves-image-format` crate.

use std::fs;
use std::path::Path;

use crc32fast::Hasher as Crc32Hasher;

/// EIF magic number.
const EIF_MAGIC: [u8; 4] = [0x2e, 0x65, 0x69, 0x66]; // ".eif"

/// EIF header version.
const EIF_HDR_VERSION: u16 = 4;

/// Section types (matching aws-nitro-enclaves-image-format).
const EIF_SECTION_KERNEL: u16 = 1;
const EIF_SECTION_CMDLINE: u16 = 2;
const EIF_SECTION_RAMDISK: u16 = 3;
const EIF_SECTION_METADATA: u16 = 5;

/// Default flags.
const EIF_DEFAULT_FLAGS: u16 = 0;

/// Maximum number of sections in the fixed-size header arrays.
const MAX_NUM_SECTIONS: usize = 32;

/// EIF header size (fixed):
/// magic(4) + version(2) + flags(2) + default_mem(8) + default_cpus(8) +
/// reserved(2) + num_sections(2) + offsets(32×8) + sizes(32×8) + unused(4) + crc32(4) = 548
const EIF_HEADER_SIZE: usize =
    4 + 2 + 2 + 8 + 8 + 2 + 2 + MAX_NUM_SECTIONS * 8 + MAX_NUM_SECTIONS * 8 + 4 + 4;

/// Byte offset of the eif_crc32 field within the header.
const EIF_CRC32_OFFSET: usize = EIF_HEADER_SIZE - 4;

/// EIF section header size: type(2) + flags(2) + size(8) = 12
const EIF_SECTION_HEADER_SIZE: usize = 12;

/// Check whether a file is an EIF by reading the first 4 bytes (magic number).
pub fn is_eif(path: &Path) -> bool {
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    use std::io::Read;
    let mut magic = [0u8; 4];
    if (&file).take(4).read_exact(&mut magic).is_err() {
        return false;
    }
    magic == EIF_MAGIC
}

/// Errors from EIF building.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum EifError {
    /// Failed to read kernel image: {0}
    ReadKernel(std::io::Error),
    /// Failed to read initrd image: {0}
    ReadInitrd(std::io::Error),
    /// Kernel image is empty
    EmptyKernel,
}

/// Build an EIF image from kernel, initrd, and command line.
///
/// `default_mem` is the enclave memory in bytes, `default_cpus` is the vCPU count.
/// These are written into the EIF header for the NE hypervisor.
///
/// Returns the assembled EIF blob ready to be loaded into enclave memory.
/// All multi-byte fields are big-endian.
pub fn build_eif(
    kernel_path: &Path,
    initrd_path: &Path,
    cmdline: &str,
    default_mem: u64,
    default_cpus: u64,
) -> Result<Vec<u8>, EifError> {
    let kernel_data = fs::read(kernel_path).map_err(EifError::ReadKernel)?;
    if kernel_data.is_empty() {
        return Err(EifError::EmptyKernel);
    }
    let initrd_data = fs::read(initrd_path).map_err(EifError::ReadInitrd)?;
    let cmdline_data = cmdline.as_bytes();

    // Build minimal metadata JSON required by the NE hypervisor.
    let metadata = build_metadata();
    let metadata_data = metadata.as_bytes();

    let num_sections: u16 = 4;

    // Calculate total image size
    let sections_size = (EIF_SECTION_HEADER_SIZE * num_sections as usize)
        + kernel_data.len()
        + cmdline_data.len()
        + metadata_data.len()
        + initrd_data.len();
    let total_size = EIF_HEADER_SIZE + sections_size;

    let mut eif = Vec::with_capacity(total_size);

    // --- EIF Header (all big-endian) ---
    eif.extend_from_slice(&EIF_MAGIC);
    eif.extend_from_slice(&EIF_HDR_VERSION.to_be_bytes());
    eif.extend_from_slice(&EIF_DEFAULT_FLAGS.to_be_bytes());
    eif.extend_from_slice(&default_mem.to_be_bytes());
    eif.extend_from_slice(&default_cpus.to_be_bytes());
    eif.extend_from_slice(&0u16.to_be_bytes()); // reserved
    eif.extend_from_slice(&num_sections.to_be_bytes());

    // Compute section offsets (order: KERNEL, CMDLINE, METADATA, RAMDISK)
    let kernel_section_offset = EIF_HEADER_SIZE as u64;
    let cmdline_section_offset =
        kernel_section_offset + EIF_SECTION_HEADER_SIZE as u64 + kernel_data.len() as u64;
    let metadata_section_offset =
        cmdline_section_offset + EIF_SECTION_HEADER_SIZE as u64 + cmdline_data.len() as u64;
    let ramdisk_section_offset =
        metadata_section_offset + EIF_SECTION_HEADER_SIZE as u64 + metadata_data.len() as u64;

    // Section offsets array (32 entries, big-endian, unused slots are zero)
    let offsets = [
        kernel_section_offset,
        cmdline_section_offset,
        metadata_section_offset,
        ramdisk_section_offset,
    ];
    for i in 0..MAX_NUM_SECTIONS {
        let val = if i < offsets.len() { offsets[i] } else { 0 };
        eif.extend_from_slice(&val.to_be_bytes());
    }

    // Section sizes array (32 entries, big-endian, unused slots are zero)
    let sizes = [
        kernel_data.len() as u64,
        cmdline_data.len() as u64,
        metadata_data.len() as u64,
        initrd_data.len() as u64,
    ];
    for i in 0..MAX_NUM_SECTIONS {
        let val = if i < sizes.len() { sizes[i] } else { 0 };
        eif.extend_from_slice(&val.to_be_bytes());
    }

    // unused (4 bytes)
    eif.extend_from_slice(&0u32.to_be_bytes());
    // eif_crc32 placeholder (4 bytes) — filled in after all sections are written
    eif.extend_from_slice(&0u32.to_be_bytes());

    debug_assert_eq!(eif.len(), EIF_HEADER_SIZE);

    // --- Sections (order: KERNEL, CMDLINE, METADATA, RAMDISK) ---
    write_section(&mut eif, EIF_SECTION_KERNEL, &kernel_data);
    write_section(&mut eif, EIF_SECTION_CMDLINE, cmdline_data);
    write_section(&mut eif, EIF_SECTION_METADATA, metadata_data);
    write_section(&mut eif, EIF_SECTION_RAMDISK, &initrd_data);

    // Compute EIF CRC32 over the entire image, excluding the 4-byte CRC field itself.
    let mut hasher = Crc32Hasher::new();
    hasher.update(&eif[..EIF_CRC32_OFFSET]);
    hasher.update(&eif[EIF_CRC32_OFFSET + 4..]);
    let crc = hasher.finalize();
    eif[EIF_CRC32_OFFSET..EIF_CRC32_OFFSET + 4].copy_from_slice(&crc.to_be_bytes());

    Ok(eif)
}

/// Build a minimal metadata JSON string required by the NE hypervisor.
fn build_metadata() -> String {
    format!(
        r#"{{"ImageName":"firecracker-enclave","ImageVersion":"","BuildMetadata":{{"BuildTime":"","BuildTool":"firecracker","BuildToolVersion":"","OperatingSystem":"Linux","KernelVersion":""}},"DockerInfo":{{}},"CustomMetadata":null}}"#
    )
}

/// Write a section (header + data) to the EIF buffer. All fields big-endian.
fn write_section(eif: &mut Vec<u8>, section_type: u16, data: &[u8]) {
    eif.extend_from_slice(&section_type.to_be_bytes());
    eif.extend_from_slice(&0u16.to_be_bytes()); // flags
    eif.extend_from_slice(&(data.len() as u64).to_be_bytes());
    eif.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eif_builder() {
        let dir = tempfile::tempdir().unwrap();
        let kernel_path = dir.path().join("kernel");
        let initrd_path = dir.path().join("initrd");

        fs::write(&kernel_path, b"FAKE_KERNEL_DATA_1234").unwrap();
        fs::write(&initrd_path, b"FAKE_INITRD_DATA_5678").unwrap();

        let mem = 256 * 1024 * 1024; // 256 MiB
        let cpus = 2;
        let eif = build_eif(&kernel_path, &initrd_path, "console=ttyS0", mem, cpus).unwrap();

        // Verify magic
        assert_eq!(&eif[0..4], &EIF_MAGIC);
        // Verify version (big-endian)
        assert_eq!(u16::from_be_bytes([eif[4], eif[5]]), EIF_HDR_VERSION);
        // Verify default_mem (big-endian u64 at offset 8)
        assert_eq!(u64::from_be_bytes(eif[8..16].try_into().unwrap()), mem);
        // Verify default_cpus (big-endian u64 at offset 16)
        assert_eq!(u64::from_be_bytes(eif[16..24].try_into().unwrap()), cpus);
        // Verify reserved(u16) + num_sections(u16) at offset 24
        assert_eq!(u16::from_be_bytes([eif[24], eif[25]]), 0); // reserved
        assert_eq!(u16::from_be_bytes([eif[26], eif[27]]), 4); // num_sections
        // Verify header size
        assert_eq!(EIF_HEADER_SIZE, 548);
        // Verify total size is reasonable
        assert!(eif.len() > EIF_HEADER_SIZE);
        // Verify first section type is KERNEL (big-endian u16 at offset 548)
        assert_eq!(
            u16::from_be_bytes([eif[EIF_HEADER_SIZE], eif[EIF_HEADER_SIZE + 1]]),
            EIF_SECTION_KERNEL
        );
        // Verify CRC32 is valid (recompute excluding CRC field)
        let stored_crc = u32::from_be_bytes(
            eif[EIF_CRC32_OFFSET..EIF_CRC32_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        let mut hasher = Crc32Hasher::new();
        hasher.update(&eif[..EIF_CRC32_OFFSET]);
        hasher.update(&eif[EIF_CRC32_OFFSET + 4..]);
        assert_eq!(hasher.finalize(), stored_crc);
    }

    #[test]
    fn test_is_eif() {
        let dir = tempfile::tempdir().unwrap();

        // A file starting with EIF magic should be detected
        let eif_path = dir.path().join("test.eif");
        let mut data = EIF_MAGIC.to_vec();
        data.extend_from_slice(&[0u8; 100]);
        fs::write(&eif_path, &data).unwrap();
        assert!(is_eif(&eif_path));

        // A raw kernel (not EIF) should not be detected
        let kernel_path = dir.path().join("vmlinux");
        fs::write(&kernel_path, b"\x7fELF_fake_kernel").unwrap();
        assert!(!is_eif(&kernel_path));

        // Non-existent file should return false
        assert!(!is_eif(dir.path().join("nonexistent").as_path()));

        // Empty file should return false
        let empty_path = dir.path().join("empty");
        fs::write(&empty_path, b"").unwrap();
        assert!(!is_eif(&empty_path));
    }

    #[test]
    fn test_eif_empty_kernel_error() {
        let dir = tempfile::tempdir().unwrap();
        let kernel_path = dir.path().join("kernel");
        let initrd_path = dir.path().join("initrd");

        fs::write(&kernel_path, b"").unwrap();
        fs::write(&initrd_path, b"initrd").unwrap();

        let result = build_eif(&kernel_path, &initrd_path, "", 256 * 1024 * 1024, 2);
        assert!(matches!(result, Err(EifError::EmptyKernel)));
    }
}
