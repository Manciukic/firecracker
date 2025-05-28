// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{ErrorKind, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;

use libc::off_t;
use vm_memory::bitmap::BitmapSlice;
use vm_memory::{GuestMemoryError, ReadVolatile, VolatileMemoryError, VolatileSlice, WriteVolatile};

use crate::vstate::memory::{GuestAddress, GuestMemory, GuestMemoryMmap};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SyncIoError {
    /// Flush: {0}
    Flush(std::io::Error),
    /// Seek: {0}
    Seek(std::io::Error),
    /// SyncAll: {0}
    SyncAll(std::io::Error),
    /// Transfer: {0}
    Transfer(GuestMemoryError),
}

#[derive(Debug)]
pub struct SyncFileEngine {
    file: File,
}

// SAFETY: `File` is send and ultimately a POD.
unsafe impl Send for SyncFileEngine {}

fn pread_volatile_raw_fd<Fd: AsRawFd>(
    raw_fd: &mut Fd,
    buf: &mut VolatileSlice<impl BitmapSlice>,
    offset: off_t,
) -> Result<usize, VolatileMemoryError> {
    let fd = raw_fd.as_raw_fd();
    let guard = buf.ptr_guard_mut();

    let dst = guard.as_ptr().cast::<libc::c_void>();

    // SAFETY: We got a valid file descriptor from `AsRawFd`. The memory pointed to by `dst` is
    // valid for writes of length `buf.len() by the invariants upheld by the constructor
    // of `VolatileSlice`.
    let bytes_read = unsafe { libc::pread64(fd, dst, buf.len(), offset) };

    if bytes_read < 0 {
        // We don't know if a partial read might have happened, so mark everything as dirty
        buf.bitmap().mark_dirty(0, buf.len());

        Err(VolatileMemoryError::IOError(std::io::Error::last_os_error()))
    } else {
        let bytes_read = bytes_read.try_into().unwrap();
        buf.bitmap().mark_dirty(0, bytes_read);
        Ok(bytes_read)
    }
}

fn pread_exact_volatile<B: BitmapSlice, Fd: AsRawFd>(
    raw_fd: &mut Fd,
    buf: &mut VolatileSlice<B>,
    offset: off_t,
) -> Result<(), VolatileMemoryError> {
    // Implementation based on https://github.com/rust-lang/rust/blob/7e7483d26e3cec7a44ef00cf7ae6c9c8c918bec6/library/std/src/io/mod.rs#L465

    let mut offset = offset;
    let mut partial_buf = buf.offset(0)?;

    while !partial_buf.is_empty() {
        match pread_volatile_raw_fd(raw_fd, &mut partial_buf, offset) {
            Err(VolatileMemoryError::IOError(err)) if err.kind() == ErrorKind::Interrupted => {
                continue
            }
            Ok(0) => {
                return Err(VolatileMemoryError::IOError(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                )))
            }
            Ok(bytes_read) => {
                partial_buf = partial_buf.offset(bytes_read)?;
                offset += bytes_read as off_t
            },
            Err(err) => return Err(err),
        }
    }

    Ok(())
}


impl SyncFileEngine {
    pub fn from_file(file: File) -> SyncFileEngine {
        SyncFileEngine { file }
    }

    #[cfg(test)]
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Update the backing file of the engine
    pub fn update_file(&mut self, file: File) {
        self.file = file
    }

    pub fn read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, SyncIoError> {
        // self.file
        //     .seek(SeekFrom::Start(offset))
        //     .map_err(SyncIoError::Seek)?;
        mem.get_slice(addr, count as usize)
            .and_then(|mut slice| Ok(pread_exact_volatile(&mut self.file, &mut slice, offset as off_t)?))
            .map_err(SyncIoError::Transfer)?;
        Ok(count)
    }

    pub fn write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, SyncIoError> {
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(SyncIoError::Seek)?;
        mem.get_slice(addr, count as usize)
            .and_then(|slice| Ok(self.file.write_all_volatile(&slice)?))
            .map_err(SyncIoError::Transfer)?;
        Ok(count)
    }

    pub fn flush(&mut self) -> Result<(), SyncIoError> {
        // flush() first to force any cached data out of rust buffers.
        self.file.flush().map_err(SyncIoError::Flush)?;
        // Sync data out to physical media on host.
        self.file.sync_all().map_err(SyncIoError::SyncAll)
    }
}
