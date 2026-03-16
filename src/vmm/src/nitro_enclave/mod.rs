// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Nitro Enclaves support for Firecracker.
//!
//! This module provides the ability to create and run a Nitro Enclave from
//! a kernel + initrd, using the `/dev/nitro_enclaves` kernel API instead of KVM.

pub mod eif;
pub mod enclave_builder;
pub mod enclave_vcpu;
pub mod enclave_vm;
pub mod heartbeat;
pub mod ne_ioctl;
pub mod vsock_console;

use std::os::unix::io::FromRawFd;

use event_manager::{EventOps, Events, MutEventSubscriber};
use vmm_sys_util::epoll::EventSet;

use crate::FcExitCode;
use crate::logger::{error, info};
use crate::vmm_config::instance_info::{InstanceInfo, VmState};

/// The top-level enclave VMM, analogous to `Vmm` for KVM-based microVMs.
///
/// Monitors the enclave fd for HUP (enclave exit) via the event manager.
pub struct EnclaveVmm {
    /// The enclave VM lifecycle object.
    pub enclave_vm: enclave_vm::EnclaveVm,
    /// Assigned enclave CID.
    pub cid: u64,
    /// Debug console (if debug mode is enabled).
    pub console: Option<vsock_console::VsockConsole>,
    /// Whether debug mode is active.
    pub debug_mode: bool,
    /// Shutdown exit code (set when enclave exits).
    shutdown_exit_code: Option<FcExitCode>,
    /// Instance info.
    pub instance_info: InstanceInfo,
}

impl std::fmt::Debug for EnclaveVmm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnclaveVmm")
            .field("cid", &self.cid)
            .field("debug_mode", &self.debug_mode)
            .field("shutdown_exit_code", &self.shutdown_exit_code)
            .field("instance_info", &self.instance_info)
            .finish()
    }
}

impl EnclaveVmm {
    /// Create a new `EnclaveVmm`.
    pub fn new(
        enclave_vm: enclave_vm::EnclaveVm,
        cid: u64,
        console: Option<vsock_console::VsockConsole>,
        debug_mode: bool,
        instance_info: InstanceInfo,
    ) -> Self {
        Self {
            enclave_vm,
            cid,
            console,
            debug_mode,
            shutdown_exit_code: None,
            instance_info,
        }
    }

    /// Provides the shutdown exit code if there is one.
    pub fn shutdown_exit_code(&self) -> Option<FcExitCode> {
        self.shutdown_exit_code
    }

    /// Signal the enclave to stop.
    pub fn stop(&mut self, exit_code: FcExitCode) {
        info!("EnclaveVmm is stopping.");
        self.shutdown_exit_code = Some(exit_code);
    }
}

impl MutEventSubscriber for EnclaveVmm {
    fn process(&mut self, event: Events, _: &mut EventOps) {
        let event_set = event.event_set();

        // HUP means the enclave has exited
        if event_set.contains(EventSet::HANG_UP) || event_set.contains(EventSet::ERROR) {
            info!("Enclave exited (CID={})", self.cid);
            self.stop(FcExitCode::Ok);
        } else if event_set.contains(EventSet::IN) {
            // Readable event on enclave fd - enclave may have exited
            info!("Enclave fd readable event (CID={})", self.cid);
            self.stop(FcExitCode::Ok);
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        let enclave_fd = self.enclave_vm.enclave_raw_fd();
        // SAFETY: We use the raw fd value only for EventOps registration.
        let event_fd = unsafe { vmm_sys_util::eventfd::EventFd::from_raw_fd(enclave_fd) };
        if let Err(err) = ops.add(Events::new(
            &event_fd,
            EventSet::IN | EventSet::HANG_UP | EventSet::ERROR,
        )) {
            error!("Failed to register enclave fd event: {}", err);
        }
        // Forget the EventFd wrapper so it doesn't close the real fd.
        std::mem::forget(event_fd);
        self.instance_info.state = VmState::Running;
    }
}
