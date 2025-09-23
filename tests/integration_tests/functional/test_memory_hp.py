# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for verifying the virtio-mem is working correctly"""

import pytest
import time


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


def wait_memory_hp(uvm, size, timeout=10):
    """
    Wait for the memory hotplug to complete.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if uvm.api.memory_hotplug.get().json()["plugged_size_mib"] == size:
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("Hotplug timeout")


def get_mem_total(uvm):
    """
    Get the total memory of the guest.
    """
    _, stdout, _ = uvm.ssh.check_output("cat /proc/meminfo | grep MemTotal")
    return int(stdout.strip().split()[1])


def get_mem_available(uvm):
    """
    Get the available memory of the guest.
    """
    _, stdout, _ = uvm.ssh.check_output("cat /proc/meminfo | grep MemAvailable")
    return int(stdout.strip().split()[1])


def check_memory_usable(uvm):
    """Allocates memory to verify it's usable (5% margin to avoid OOM-kill)"""
    mem_available = get_mem_available(uvm)
    # number of 64b ints to allocate as 95% of available memory
    count = mem_available * 1024 * 95 // 100 // 8
    
    uvm.ssh.check_output(
        f"python3 -c 'Q = 0x0123456789abcdef; a = [Q] * {count}; assert all(q == Q for q in a)'"
    )

def check_hotplug_unplug(uvm, requested_size_mib):
    """Verifies memory can be hotplugged and then unplugged"""
    mem_total_before = get_mem_total(uvm)
    uvm.api.memory_hotplug.patch(requested_size_mib=requested_size_mib)
    wait_memory_hp(uvm, requested_size_mib)

    # verify guest driver received the request
    _, stdout, _ = uvm.ssh.check_output(
        "dmesg | grep 'virtio_mem' | grep 'requested size' | tail -1"
    )
    assert int(stdout.strip().split(":")[-1].strip(), base=0) == requested_size_mib << 20

    # verify guest driver executed the request
    mem_total_after = get_mem_total(uvm)
    assert mem_total_after == mem_total_before + requested_size_mib * 1024

    # verify memory is usable
    check_memory_usable(uvm)

    uvm.api.memory_hotplug.patch(requested_size_mib=0)
    wait_memory_hp(uvm, 0)
    _, stdout, _ = uvm.ssh.check_output(
        "dmesg | grep 'virtio_mem' | grep 'requested size' | tail -1"
    )
    assert int(stdout.strip().split(":")[-1].strip(), base=0) == 0

    mem_total_after = get_mem_total(uvm)
    assert mem_total_after == mem_total_before


def test_virtio_mem_patch(uvm_plain_6_1):
    """
    Check that the guest kernel has enabled virtio-mem.
    """
    uvm = uvm_plain_6_1
    uvm.spawn()
    uvm.memory_monitor = None
    boot_args = "console=ttyS0 reboot=k panic=1 memhp_default_state=online_movable"

    uvm.basic_config(mem_size_mib=1024, boot_args=boot_args)

    uvm.api.memory_hotplug.put(total_size_mib=1024)
    uvm.add_net_iface()
    uvm.start()

    check_hotplug_unplug(uvm, 512)


def test_snapshot_restore_persistence(uvm_plain_6_1, microvm_factory):
    """
    Check that hptplugged memory is persisted across snapshot/restore.
    """
    uvm = uvm_plain_6_1
    uvm.spawn()
    uvm.memory_monitor = None
    uvm.basic_config(
        mem_size_mib=256,
        boot_args="console=ttyS0 reboot=k panic=1 memhp_default_state=online_movable"
    )
    uvm.api.memory_hotplug.put(total_size_mib=1024)
    uvm.add_net_iface()
    uvm.start()

    uvm.api.memory_hotplug.patch(requested_size_mib=1024)

    uvm.ssh.check_output(
        "mount -o remount,size=1024M -t tmpfs tmpfs /dev/shm"
    )

    uvm.ssh.check_output(
        "dd if=/dev/urandom of=/dev/shm/mem_hp_test bs=1M count=1024"
    )

    _, checksum_before, _ = uvm.ssh.check_output(
        "sha256sum /dev/shm/mem_hp_test"
    )

    snapshot = uvm.snapshot_full()
    restored_vm = microvm_factory.build()
    restored_vm.spawn()
    restored_vm.restore_from_snapshot(snapshot, resume=True)
    
    _, checksum_after, _ = restored_vm.ssh.check_output(
        "sha256sum /dev/shm/mem_hp_test"
    )

    assert checksum_before == checksum_after, "Checksums didn't match"
