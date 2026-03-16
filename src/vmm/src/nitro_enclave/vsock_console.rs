// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Vsock-based debug console for Nitro Enclaves.
//!
//! Connects to the enclave's vsock console port and forwards output to the
//! serial output file (same path configured via the Firecracker serial API).

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::thread;
use std::time::Duration;

/// The console port is 10000 + enclave_cid (convention from AWS NE CLI).
const CONSOLE_PORT_OFFSET: u32 = 10000;

/// Maximum number of connection retries.
const MAX_RETRIES: u32 = 20;

/// Delay between retries.
const RETRY_DELAY: Duration = Duration::from_millis(500);

/// Errors from vsock console operations.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VsockConsoleError {
    /// Failed to create vsock socket: {0}
    CreateSocket(io::Error),
    /// Failed to connect to enclave console after {retries} retries: {source}
    Connect {
        /// Number of retries attempted.
        retries: u32,
        /// Last connection error.
        source: io::Error,
    },
    /// Failed to open serial output file: {0}
    OpenSerialOut(io::Error),
}

/// Vsock console that reads from the enclave and writes to the serial output.
#[derive(Debug)]
pub struct VsockConsole {
    _reader_handle: thread::JoinHandle<()>,
}

impl VsockConsole {
    /// Start a vsock console reader thread that connects to the enclave's
    /// console port and forwards output to the given serial output file.
    ///
    /// Following the nitro-cli convention, the console connects to
    /// `CID=VMADDR_CID_HYPERVISOR(0)` on `port=10000+enclave_cid`.
    ///
    /// If `serial_out_path` is `None`, output goes to stdout.
    pub fn start(
        enclave_cid: u64,
        serial_out_path: Option<&Path>,
    ) -> Result<Self, VsockConsoleError> {
        let port = CONSOLE_PORT_OFFSET + enclave_cid as u32;
        let cid = libc::VMADDR_CID_HYPERVISOR;

        let output: Box<dyn Write + Send> = match serial_out_path {
            Some(path) => {
                let file = OpenOptions::new()
                    .write(true)
                    .append(true)
                    .create(true)
                    .open(path)
                    .map_err(VsockConsoleError::OpenSerialOut)?;
                Box::new(file)
            }
            None => Box::new(io::stdout()),
        };

        let handle = thread::Builder::new()
            .name("ne-console".to_string())
            .spawn(move || {
                if let Err(e) = console_reader_loop(cid, port, output) {
                    eprintln!("Enclave console error: {e}");
                }
            })
            .expect("Failed to spawn console reader thread");

        Ok(Self {
            _reader_handle: handle,
        })
    }
}

/// Create an AF_VSOCK socket.
fn create_vsock_socket() -> io::Result<OwnedFd> {
    // SAFETY: Creating a VSOCK stream socket.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is valid from a successful socket() call.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Connect an AF_VSOCK socket to the given CID and port with retries.
fn connect_vsock(cid: u32, port: u32) -> Result<OwnedFd, VsockConsoleError> {
    let sock = create_vsock_socket().map_err(VsockConsoleError::CreateSocket)?;

    let addr = libc::sockaddr_vm {
        svm_family: libc::AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: cid,
        svm_zero: [0u8; 4],
    };

    let mut last_err = None;
    for _ in 0..MAX_RETRIES {
        // SAFETY: Connecting a vsock socket with a valid sockaddr_vm.
        let ret = unsafe {
            libc::connect(
                sock.as_raw_fd(),
                &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if ret == 0 {
            return Ok(sock);
        }
        last_err = Some(io::Error::last_os_error());
        thread::sleep(RETRY_DELAY);
    }

    Err(VsockConsoleError::Connect {
        retries: MAX_RETRIES,
        source: last_err.unwrap(),
    })
}

/// Read from the vsock console and write to the output.
fn console_reader_loop(
    cid: u32,
    port: u32,
    mut output: Box<dyn Write + Send>,
) -> Result<(), VsockConsoleError> {
    let sock = connect_vsock(cid, port)?;
    let fd = sock.as_raw_fd();

    let mut buf = [0u8; 4096];

    loop {
        // SAFETY: Reading from a connected vsock socket into our buffer.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        let _ = output.write_all(&buf[..n as usize]);
        let _ = output.flush();
    }

    Ok(())
}
