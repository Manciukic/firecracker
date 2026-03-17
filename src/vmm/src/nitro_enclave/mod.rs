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
