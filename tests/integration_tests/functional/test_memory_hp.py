# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for verifying the virtio-mem is working correctly"""

import pytest


@pytest.mark.parametrize("use_vhost_user", [True, False])
def test_virtio_mem_detected(uvm_plain_6_1, rootfs, use_vhost_user):
    """
    Check that the guest kernel has enabled virtio-mem.
    """
    uvm = uvm_plain_6_1
    uvm.spawn()
    uvm.memory_monitor = None
    boot_args = "console=ttyS0 reboot=k panic=1 memhp_default_state=online_movable"

    if use_vhost_user:
        # We need to setup ssh keys manually because we did not specify rootfs
        # in microvm_factory.build method
        ssh_key = rootfs.with_suffix(".id_rsa")
        uvm.ssh_key = ssh_key
        uvm.basic_config(boot_args=boot_args, add_root_device=False)
        uvm.add_vhost_user_drive(
            "rootfs", rootfs, is_root_device=True, is_read_only=True
        )
    else:
        uvm.basic_config(boot_args=boot_args)

    uvm.api.memory_hotplug.put(total_size_mib=1024)
    uvm.add_net_iface()
    uvm.start()

    _, stdout, _ = uvm.ssh.check_output("dmesg | grep 'virtio_mem'")
    for line in stdout.splitlines():
        _, key, value = line.strip().split(":")
        key = key.strip()
        value = int(value.strip(), base=0)
        match key:
            case "start address":
                assert value == (512 << 30), "start address doesn't match"
            case "region size":
                assert value == 1024 << 20, "region size doesn't match"
            case "device block size":
                assert value == 2 << 20, "block size doesn't match"
            case "plugged size":
                assert value == 0, "plugged size doesn't match"
            case "requested size":
                assert value == 0, "requested size doesn't match"
            case _:
                continue


def test_snapshot_restore(uvm_plain_6_1, microvm_factory):
    """
    Check that a snapshot restore works.
    There's no device functionality check as it's not yet implemented.
    """
    uvm = uvm_plain_6_1
    uvm.spawn()
    uvm.memory_monitor = None
    uvm.basic_config(
        boot_args="console=ttyS0 reboot=k panic=1 memhp_default_state=online_movable"
    )
    uvm.api.memory_hotplug.put(total_size_mib=1024)
    uvm.add_net_iface()
    uvm.start()
    snapshot = uvm.snapshot_full()
    restored_vm = microvm_factory.build()
    restored_vm.spawn()
    restored_vm.restore_from_snapshot(snapshot, resume=True)
    assert restored_vm.state == "Running"
    restored_vm.ssh.check_output("true")
