// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Vsock-based debug console for Nitro Enclaves.
//!
//! Connects to the enclave's vsock console port and forwards output to the
//! serial output file (same path configured via the Firecracker serial API).
//!
//! The console socket is registered as its own `MutEventSubscriber` with the
//! event manager, so reads are driven from the main thread's event loop.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

use event_manager::{EventOps, Events, MutEventSubscriber};
use vmm_sys_util::epoll::EventSet;

use crate::logger::{error, info};

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
///
/// Holds the connected (non-blocking) vsock socket and output writer.
/// Reading is driven by the event manager via `EnclaveVmm::process()`.
pub struct VsockConsole {
    /// Connected vsock socket fd (non-blocking).
    sock: OwnedFd,
    /// Output writer (serial file or stdout).
    output: Box<dyn Write + Send>,
    /// Read buffer.
    buf: [u8; 4096],
}

impl std::fmt::Debug for VsockConsole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VsockConsole")
            .field("sock_fd", &self.sock.as_raw_fd())
            .finish()
    }
}

impl VsockConsole {
    /// Connect to the enclave's console port and return a non-blocking console.
    ///
    /// Following the nitro-cli convention, the console connects to
    /// `CID=VMADDR_CID_HYPERVISOR(0)` on `port=10000+enclave_cid`.
    ///
    /// If `serial_out_path` is `None`, output goes to stdout.
    pub fn connect(
        enclave_cid: u64,
        serial_out_path: Option<&Path>,
    ) -> Result<Self, VsockConsoleError> {
        let port = CONSOLE_PORT_OFFSET + enclave_cid as u32;
        let cid = libc::VMADDR_CID_HYPERVISOR;

        let sock = connect_vsock(cid, port)?;

        // Set non-blocking for epoll-driven reads.
        // SAFETY: valid fd from successful connect.
        unsafe {
            libc::fcntl(sock.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK);
        }

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

        Ok(Self {
            sock,
            output,
            buf: [0u8; 4096],
        })
    }

    /// Read available data from the socket and write to output.
    ///
    /// Returns `true` if the connection is still alive (got `WouldBlock`),
    /// `false` on EOF or error.
    fn read_and_forward(&mut self) -> bool {
        loop {
            // SAFETY: Reading from a connected vsock socket into our buffer.
            let n = unsafe {
                libc::read(
                    self.sock.as_raw_fd(),
                    self.buf.as_mut_ptr().cast(),
                    self.buf.len(),
                )
            };
            if n > 0 {
                let _ = self.output.write_all(&self.buf[..n as usize]);
                let _ = self.output.flush();
            } else if n == 0 {
                // EOF
                return false;
            } else {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    return true;
                }
                return false;
            }
        }
    }
}

impl MutEventSubscriber for VsockConsole {
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        let event_set = event.event_set();

        if event_set.contains(EventSet::IN) {
            if !self.read_and_forward() {
                // EOF or error — remove from epoll.
                Self::remove_from_epoll(self.sock.as_raw_fd(), ops);
            }
        }

        if event_set.contains(EventSet::HANG_UP) || event_set.contains(EventSet::ERROR) {
            info!("Console vsock disconnected");
            Self::remove_from_epoll(self.sock.as_raw_fd(), ops);
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        // SAFETY: We use the raw fd value only for EventOps registration.
        let event_fd =
            unsafe { vmm_sys_util::eventfd::EventFd::from_raw_fd(self.sock.as_raw_fd()) };
        if let Err(err) = ops.add(Events::new(
            &event_fd,
            EventSet::IN | EventSet::HANG_UP | EventSet::ERROR,
        )) {
            error!("Failed to register console fd event: {}", err);
        }
        // Forget the EventFd wrapper so it doesn't close the real fd.
        std::mem::forget(event_fd);
    }
}

impl VsockConsole {
    fn remove_from_epoll(raw_fd: i32, ops: &mut EventOps) {
        // SAFETY: We use the raw fd value only for EventOps removal.
        let event_fd = unsafe { vmm_sys_util::eventfd::EventFd::from_raw_fd(raw_fd) };
        let _ = ops.remove(Events::new(
            &event_fd,
            EventSet::IN | EventSet::HANG_UP | EventSet::ERROR,
        ));
        std::mem::forget(event_fd);
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
        std::thread::sleep(RETRY_DELAY);
    }

    Err(VsockConsoleError::Connect {
        retries: MAX_RETRIES,
        source: last_err.unwrap(),
    })
}
