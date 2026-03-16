// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Heartbeat check for Nitro Enclaves.
//!
//! Listens on a vsock port for a heartbeat byte from the enclave to validate
//! that the enclave has booted successfully.

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

/// Port used for heartbeat communication.
const HEARTBEAT_PORT: u32 = 9000;

/// Expected heartbeat byte.
const HEARTBEAT_BYTE: u8 = 0xB7;

/// Timeout for heartbeat check.
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(60);

/// Errors from heartbeat operations.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum HeartbeatError {
    /// Failed to create vsock listener: {0}
    CreateSocket(io::Error),
    /// Failed to bind vsock listener: {0}
    Bind(io::Error),
    /// Failed to listen on vsock: {0}
    Listen(io::Error),
    /// Failed to accept vsock connection: {0}
    Accept(io::Error),
    /// Heartbeat timeout: no connection within {0:?}
    Timeout(Duration),
    /// Failed to read heartbeat: {0}
    Read(io::Error),
    /// Unexpected heartbeat byte: expected 0x{expected:02X}, got 0x{actual:02X}
    UnexpectedByte {
        /// Expected byte value.
        expected: u8,
        /// Actual byte received.
        actual: u8,
    },
    /// Failed to echo heartbeat: {0}
    Write(io::Error),
}

/// Perform a one-shot heartbeat check.
///
/// Binds to port 9000 on VMADDR_CID_ANY, accepts a connection from the
/// enclave, reads the heartbeat byte, echoes it back, and returns.
pub fn check_heartbeat() -> Result<(), HeartbeatError> {
    let listen_fd = create_vsock_listener()?;

    // Set a receive timeout for the accept
    let tv = libc::timeval {
        #[allow(deprecated)]
        tv_sec: HEARTBEAT_TIMEOUT.as_secs() as libc::time_t,
        tv_usec: 0,
    };
    // SAFETY: Setting socket option with valid parameters.
    let ret = unsafe {
        libc::setsockopt(
            listen_fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        // Non-fatal, we just won't have a timeout
    }

    // Accept one connection
    // SAFETY: accept on a valid listening socket.
    let conn_fd = unsafe { libc::accept(listen_fd.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut()) };
    if conn_fd < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut {
            return Err(HeartbeatError::Timeout(HEARTBEAT_TIMEOUT));
        }
        return Err(HeartbeatError::Accept(err));
    }
    // SAFETY: conn_fd is valid from a successful accept().
    let conn = unsafe { OwnedFd::from_raw_fd(conn_fd) };

    // Read heartbeat byte
    let mut buf = [0u8; 1];
    // SAFETY: Reading from a valid connected socket.
    let n = unsafe { libc::read(conn.as_raw_fd(), buf.as_mut_ptr().cast(), 1) };
    if n <= 0 {
        return Err(HeartbeatError::Read(io::Error::last_os_error()));
    }

    if buf[0] != HEARTBEAT_BYTE {
        return Err(HeartbeatError::UnexpectedByte {
            expected: HEARTBEAT_BYTE,
            actual: buf[0],
        });
    }

    // Echo it back
    // SAFETY: Writing to a valid connected socket.
    let n = unsafe { libc::write(conn.as_raw_fd(), buf.as_ptr().cast(), 1) };
    if n <= 0 {
        return Err(HeartbeatError::Write(io::Error::last_os_error()));
    }

    Ok(())
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
