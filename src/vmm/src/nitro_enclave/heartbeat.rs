// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Heartbeat device for Nitro Enclaves.
//!
//! Listens on vsock port 9000 for a heartbeat byte (0xB7) from the enclave,
//! echoes it back, then closes the connection. Runs asynchronously on the
//! main event loop as a `MutEventSubscriber`.

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

use event_manager::{EventOps, Events, MutEventSubscriber};
use vmm_sys_util::epoll::EventSet;

use crate::logger::{error, info};

/// Port used for heartbeat communication.
const HEARTBEAT_PORT: u32 = 9000;

/// Expected heartbeat byte.
const HEARTBEAT_BYTE: u8 = 0xB7;

/// Errors from heartbeat operations.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum HeartbeatError {
    /// Failed to create vsock listener: {0}
    CreateSocket(io::Error),
    /// Failed to bind vsock listener: {0}
    Bind(io::Error),
    /// Failed to listen on vsock: {0}
    Listen(io::Error),
}

/// Async heartbeat device driven by the event manager.
///
/// States: Listening (accept) → Connected (read+echo) → Done (removed from epoll).
pub struct Heartbeat {
    /// Listening socket fd.
    listen_fd: OwnedFd,
    /// Connected client fd (set after accept).
    conn_fd: Option<OwnedFd>,
}

impl std::fmt::Debug for Heartbeat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Heartbeat")
            .field("listen_fd", &self.listen_fd.as_raw_fd())
            .field("conn_fd", &self.conn_fd.as_ref().map(|fd| fd.as_raw_fd()))
            .finish()
    }
}

impl Heartbeat {
    /// Create a new heartbeat listener bound to vsock port 9000.
    ///
    /// The listening socket is set to non-blocking so accept can be driven
    /// by epoll.
    pub fn new() -> Result<Self, HeartbeatError> {
        let listen_fd = create_vsock_listener()?;

        // Set non-blocking for epoll-driven accept.
        // SAFETY: valid fd from successful bind+listen.
        unsafe {
            libc::fcntl(listen_fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK);
        }

        Ok(Self {
            listen_fd,
            conn_fd: None,
        })
    }

    /// Try to accept a connection. Returns true if a connection was accepted.
    fn try_accept(&mut self) -> bool {
        // SAFETY: accept on a valid listening socket.
        let fd = unsafe {
            libc::accept(
                self.listen_fd.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if fd < 0 {
            return false;
        }
        // Set the connection non-blocking too.
        // SAFETY: valid fd from successful accept.
        unsafe {
            libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        }
        // SAFETY: fd is valid from a successful accept().
        self.conn_fd = Some(unsafe { OwnedFd::from_raw_fd(fd) });
        true
    }

    /// Try to read the heartbeat byte and echo it back. Returns true if done.
    fn try_read_and_echo(&self) -> bool {
        let conn = match self.conn_fd {
            Some(ref fd) => fd,
            None => return false,
        };

        let mut buf = [0u8; 1];
        // SAFETY: Reading from a valid connected socket.
        let n = unsafe { libc::read(conn.as_raw_fd(), buf.as_mut_ptr().cast(), 1) };
        if n <= 0 {
            return false;
        }

        if buf[0] != HEARTBEAT_BYTE {
            info!(
                "Unexpected heartbeat byte: expected 0x{:02X}, got 0x{:02X}",
                HEARTBEAT_BYTE, buf[0]
            );
            return true; // Still done, just unexpected.
        }

        // Echo it back.
        // SAFETY: Writing to a valid connected socket.
        let n = unsafe { libc::write(conn.as_raw_fd(), buf.as_ptr().cast(), 1) };
        if n <= 0 {
            info!("Failed to echo heartbeat byte");
        } else {
            info!("Heartbeat OK");
        }

        true
    }

    fn remove_fd(raw_fd: i32, ops: &mut EventOps) {
        // SAFETY: We use the raw fd value only for EventOps removal.
        let event_fd = unsafe { vmm_sys_util::eventfd::EventFd::from_raw_fd(raw_fd) };
        let _ = ops.remove(Events::new(
            &event_fd,
            EventSet::IN | EventSet::HANG_UP | EventSet::ERROR,
        ));
        std::mem::forget(event_fd);
    }
}

impl MutEventSubscriber for Heartbeat {
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        let event_set = event.event_set();
        let source_fd = event.fd();

        if source_fd == self.listen_fd.as_raw_fd() {
            // Listening socket — try to accept.
            if event_set.contains(EventSet::IN) && self.try_accept() {
                // Remove listen fd, register conn fd.
                Self::remove_fd(self.listen_fd.as_raw_fd(), ops);

                let conn_raw_fd = self.conn_fd.as_ref().unwrap().as_raw_fd();
                // SAFETY: We use the raw fd value only for EventOps registration.
                let efd = unsafe { vmm_sys_util::eventfd::EventFd::from_raw_fd(conn_raw_fd) };
                if let Err(err) = ops.add(Events::new(
                    &efd,
                    EventSet::IN | EventSet::HANG_UP | EventSet::ERROR,
                )) {
                    error!("Failed to register heartbeat conn fd: {}", err);
                }
                std::mem::forget(efd);
            }
        } else if let Some(conn_raw_fd) = self.conn_fd.as_ref().map(|fd| fd.as_raw_fd()) {
            if source_fd == conn_raw_fd {
                let done = if event_set.contains(EventSet::IN) {
                    self.try_read_and_echo()
                } else {
                    false
                };

                if done
                    || event_set.contains(EventSet::HANG_UP)
                    || event_set.contains(EventSet::ERROR)
                {
                    Self::remove_fd(conn_raw_fd, ops);
                    self.conn_fd = None;
                }
            }
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        // Register the listening socket for accept readiness.
        // SAFETY: We use the raw fd value only for EventOps registration.
        let event_fd =
            unsafe { vmm_sys_util::eventfd::EventFd::from_raw_fd(self.listen_fd.as_raw_fd()) };
        if let Err(err) = ops.add(Events::new(
            &event_fd,
            EventSet::IN | EventSet::HANG_UP | EventSet::ERROR,
        )) {
            error!("Failed to register heartbeat listen fd: {}", err);
        }
        std::mem::forget(event_fd);
    }
}

/// Create and bind a vsock listener on the heartbeat port.
fn create_vsock_listener() -> Result<OwnedFd, HeartbeatError> {
    // SAFETY: Creating a VSOCK stream socket.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(HeartbeatError::CreateSocket(io::Error::last_os_error()));
    }
    // SAFETY: fd is valid from a successful socket() call.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let addr = libc::sockaddr_vm {
        svm_family: libc::AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: HEARTBEAT_PORT,
        svm_cid: libc::VMADDR_CID_ANY,
        svm_zero: [0u8; 4],
    };

    // SAFETY: Binding a valid vsock socket with a valid sockaddr_vm.
    let ret = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(HeartbeatError::Bind(io::Error::last_os_error()));
    }

    // SAFETY: listen on a valid bound socket.
    let ret = unsafe { libc::listen(fd.as_raw_fd(), 1) };
    if ret < 0 {
        return Err(HeartbeatError::Listen(io::Error::last_os_error()));
    }

    Ok(fd)
}
