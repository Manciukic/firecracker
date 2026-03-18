# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for Device Memory Buffer (DMB) support."""

import os

import pytest

import host_tools.drive as drive_tools

DMB_SIZE = 2 * 1024 * 1024  # 2 MiB

# DMB mmaps add to FC process RSS. Raise memory monitor thresholds accordingly.
DMB_MEM_OVERHEAD = 4 * 1024 * 1024  # 4 MiB headroom for DMB + state overhead


def _requires_pci(test_microvm):
    """Skip if PCI is not enabled — DMB requires PCI transport."""
    if not test_microvm.pci_enabled:
        pytest.skip("DMB requires PCI transport")


def _raise_mem_thresholds(vm):
    """Raise memory monitor thresholds to account for DMB mmap overhead."""
    if vm.memory_monitor:
        vm.memory_monitor.threshold_booted += DMB_MEM_OVERHEAD
        vm.memory_monitor.threshold_snapshot += DMB_MEM_OVERHEAD
        vm.memory_monitor.threshold_restored += DMB_MEM_OVERHEAD
        vm.memory_monitor.threshold += DMB_MEM_OVERHEAD


def test_dmb_block_device(uvm_plain_any):
    """
    Test that a block device with DMB enabled works correctly.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()
    test_microvm.basic_config()
    _requires_pci(test_microvm)
    _raise_mem_thresholds(test_microvm)
    test_microvm.add_net_iface()

    # Add a scratch block device with DMB enabled
    fs = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "scratch_dmb"), size=2
    )
    test_microvm.add_drive("scratch", fs.path, dmb_size=DMB_SIZE)

    test_microvm.start()

    # Verify the block device works through the DMB path
    test_microvm.ssh.run("dd if=/dev/vdb of=/dev/null bs=1M count=1")
    # Check dmesg for DMB enablement
    _, stdout, _ = test_microvm.ssh.run("dmesg | grep -i DMB")
    assert "DMB region" in stdout


def test_dmb_feature_negotiation(uvm_plain_any):
    """
    Test that DMB feature bit is advertised and the shared memory BAR is visible.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()
    test_microvm.basic_config()
    _requires_pci(test_microvm)
    _raise_mem_thresholds(test_microvm)
    test_microvm.add_net_iface()

    fs = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "scratch_dmb_feat"), size=2
    )
    test_microvm.add_drive("scratch", fs.path, dmb_size=DMB_SIZE)

    test_microvm.start()

    # Check dmesg for DMB region log message from the kernel driver
    _, stdout, _ = test_microvm.ssh.run("dmesg | grep DMB")
    assert "DMB region" in stdout


def test_dmb_disabled_by_default(uvm_plain_any):
    """
    Test that DMB is NOT advertised when dmb_size is not set.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    # Add a standard block device without DMB
    fs = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "scratch_no_dmb"), size=2
    )
    test_microvm.add_drive("scratch", fs.path)

    test_microvm.start()

    # DMB should NOT be in dmesg
    _, stdout, _ = test_microvm.ssh.run("dmesg | grep DMB")
    assert stdout.strip() == ""

    # Device should still work normally via regular guest memory
    test_microvm.ssh.run("dd if=/dev/vdb of=/dev/null bs=1M count=1")


def test_dmb_block_read_write(uvm_plain_any):
    """
    Test data integrity through the DMB path by writing and reading back data.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()
    test_microvm.basic_config()
    _requires_pci(test_microvm)
    _raise_mem_thresholds(test_microvm)
    test_microvm.add_net_iface()

    # Add a scratch block device with DMB enabled
    fs = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "scratch_dmb_rw"), size=2
    )
    test_microvm.add_drive("scratch", fs.path, dmb_size=DMB_SIZE)

    test_microvm.start()

    # Write known data pattern and read it back
    test_microvm.ssh.run("dd if=/dev/urandom of=/tmp/testdata bs=1K count=64")
    test_microvm.ssh.run("md5sum /tmp/testdata > /tmp/checksum_before")
    # Write to the block device
    test_microvm.ssh.run("dd if=/tmp/testdata of=/dev/vdb bs=1K count=64")
    # Read back from the block device
    test_microvm.ssh.run("dd if=/dev/vdb of=/tmp/testdata_read bs=1K count=64")
    test_microvm.ssh.run("md5sum /tmp/testdata_read > /tmp/checksum_after")

    # Compare checksums
    _, before, _ = test_microvm.ssh.run("cat /tmp/checksum_before | awk '{print $1}'")
    _, after, _ = test_microvm.ssh.run("cat /tmp/checksum_after | awk '{print $1}'")
    assert (
        before.strip() == after.strip()
    ), f"Data integrity check failed: {before.strip()} != {after.strip()}"


def test_dmb_snapshot_restore(uvm_plain_any, microvm_factory):
    """
    Test that DMB device data survives snapshot/restore.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()
    test_microvm.basic_config()
    _requires_pci(test_microvm)
    _raise_mem_thresholds(test_microvm)
    test_microvm.add_net_iface()

    # Add a scratch block device with DMB enabled
    fs = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "scratch_dmb_snap"), size=2
    )
    test_microvm.add_drive("scratch", fs.path, dmb_size=DMB_SIZE)

    test_microvm.start()

    # Write known data to the block device through DMB path
    test_microvm.ssh.run("dd if=/dev/urandom of=/tmp/testdata bs=1K count=64")
    _, before_md5, _ = test_microvm.ssh.run("md5sum /tmp/testdata | awk '{print $1}'")
    test_microvm.ssh.run("dd if=/tmp/testdata of=/dev/vdb bs=1K count=64")
    test_microvm.ssh.run("sync")

    # Take a full snapshot
    snapshot = test_microvm.snapshot_full()

    # Restore into a new VM
    restored_vm = microvm_factory.build()
    _raise_mem_thresholds(restored_vm)
    restored_vm.spawn()
    restored_vm.restore_from_snapshot(snapshot, resume=True)

    # Read data back from block device and verify integrity
    restored_vm.ssh.run("dd if=/dev/vdb of=/tmp/testdata_restored bs=1K count=64")
    _, after_md5, _ = restored_vm.ssh.run(
        "md5sum /tmp/testdata_restored | awk '{print $1}'"
    )
    assert before_md5.strip() == after_md5.strip(), (
        f"Data mismatch after snapshot/restore: "
        f"{before_md5.strip()} != {after_md5.strip()}"
    )

    # Verify DMB is still active after restore
    _, stdout, _ = restored_vm.ssh.run("dmesg | grep DMB")
    assert "DMB region" in stdout


def test_dmb_snapshot_write_after_restore(uvm_plain_any, microvm_factory):
    """
    Test that DMB device can write new data after snapshot/restore.
    """
    test_microvm = uvm_plain_any
    test_microvm.spawn()
    test_microvm.basic_config()
    _requires_pci(test_microvm)
    _raise_mem_thresholds(test_microvm)
    test_microvm.add_net_iface()

    fs = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "scratch_dmb_snap_wr"), size=2
    )
    test_microvm.add_drive("scratch", fs.path, dmb_size=DMB_SIZE)

    test_microvm.start()

    # Take a snapshot (no prior writes needed — we test post-restore writes)
    snapshot = test_microvm.snapshot_full()

    # Restore into a new VM
    restored_vm = microvm_factory.build()
    _raise_mem_thresholds(restored_vm)
    restored_vm.spawn()
    restored_vm.restore_from_snapshot(snapshot, resume=True)

    # Write new data after restore and verify integrity
    restored_vm.ssh.run("dd if=/dev/urandom of=/tmp/newdata bs=1K count=64")
    _, expected_md5, _ = restored_vm.ssh.run("md5sum /tmp/newdata | awk '{print $1}'")
    restored_vm.ssh.run("dd if=/tmp/newdata of=/dev/vdb bs=1K count=64")
    restored_vm.ssh.run("sync")
    restored_vm.ssh.run("dd if=/dev/vdb of=/tmp/newdata_read bs=1K count=64")
    _, actual_md5, _ = restored_vm.ssh.run(
        "md5sum /tmp/newdata_read | awk '{print $1}'"
    )
    assert expected_md5.strip() == actual_md5.strip(), (
        f"Write-after-restore integrity check failed: "
        f"{expected_md5.strip()} != {actual_md5.strip()}"
    )
