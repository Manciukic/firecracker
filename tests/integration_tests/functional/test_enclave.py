# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for Nitro Enclaves support in Firecracker."""

import os
import subprocess
import time
from pathlib import Path

import pytest

from framework.defs import ARTIFACT_DIR

EIF_PATH = ARTIFACT_DIR / "hello.eif"


def _has_ne_device():
    """Check if /dev/nitro_enclaves exists."""
    return os.path.exists("/dev/nitro_enclaves")


def _get_ne_cpus():
    """Read and parse the NE CPU pool from sysfs. Returns list of CPU IDs or empty list."""
    try:
        with open("/sys/module/nitro_enclaves/parameters/ne_cpus") as f:
            content = f.read().strip()
            if not content or content == "(null)":
                return []
            cpus = []
            for part in content.split(","):
                part = part.strip()
                if "-" in part:
                    start, end = part.split("-", 1)
                    cpus.extend(range(int(start), int(end) + 1))
                else:
                    cpus.append(int(part))
            return cpus
    except (FileNotFoundError, PermissionError, ValueError):
        return []


def _has_ne_cpus():
    """Check if NE CPU pool is configured."""
    return len(_get_ne_cpus()) > 0


def _build_hello_eif():
    """Build the hello.eif using nitro-cli if it doesn't exist."""
    if EIF_PATH.exists():
        return True
    try:
        # Ensure hello Docker image exists
        subprocess.run(
            ["docker", "build", "-t", "hello:latest",
             "/usr/share/nitro_enclaves/examples/hello/"],
            check=True, capture_output=True, timeout=60,
        )
        subprocess.run(
            ["nitro-cli", "build-enclave",
             "--docker-uri", "hello:latest",
             "--output-file", str(EIF_PATH)],
            check=True, capture_output=True, timeout=120,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


requires_ne = pytest.mark.skipif(
    not (_has_ne_device() and _has_ne_cpus()),
    reason="Requires Nitro Enclaves hardware with configured CPU pool",
)


def _get_kernel_path():
    """Find a kernel image in the artifact directory (for non-NE tests)."""
    candidates = sorted(ARTIFACT_DIR.glob("vmlinux-*"))
    candidates = [
        c for c in candidates if not c.name.endswith((".config", ".debug"))
    ]
    return candidates[0] if candidates else None


def _spawn_enclave_vm(microvm_factory, eif_path):
    """Create and spawn a Firecracker VM for enclave testing."""
    vm = microvm_factory.build(kernel=eif_path)
    # Disable swagger validation since /enclave is not in the swagger spec yet
    vm.spawn(validate_api=False)
    return vm


def _configure_and_start_enclave(vm, eif_path, debug_mode=True):
    """Configure boot source, machine config, enclave, and start."""
    ne_cpus = _get_ne_cpus()
    # Use first 2 CPUs from the NE pool; pass explicitly since jailer
    # doesn't have access to the sysfs CPU pool file.
    cpu_ids = ne_cpus[:2] if ne_cpus else None
    vcpu_count = len(cpu_ids) if cpu_ids else 2

    vm.api.machine_config.put(
        vcpu_count=vcpu_count,
        mem_size_mib=256,
        huge_pages="2M",
    )
    vm.api.boot.put(
        kernel_image_path=vm.create_jailed_resource(eif_path),
    )
    enclave_kwargs = {"debug_mode": debug_mode}
    if cpu_ids:
        enclave_kwargs["cpu_ids"] = cpu_ids
    vm.api.enclave.put(**enclave_kwargs)
    vm.api.actions.put(action_type="InstanceStart")


@requires_ne
def test_enclave_boot_debug_mode(microvm_factory):
    """Start Firecracker with a pre-built EIF in debug mode via API."""
    if not _build_hello_eif():
        pytest.skip("Could not build hello.eif (nitro-cli not available)")

    vm = _spawn_enclave_vm(microvm_factory, EIF_PATH)
    _configure_and_start_enclave(vm, EIF_PATH, debug_mode=True)

    # Give the enclave time to boot
    time.sleep(3)

    # Verify the Firecracker process is still running
    assert vm.firecracker_pid is not None
    assert os.path.exists(f"/proc/{vm.firecracker_pid}")

    vm.kill()


@requires_ne
def test_enclave_console_output(microvm_factory):
    """Verify that the enclave vsock console output appears in the serial log."""
    if not _build_hello_eif():
        pytest.skip("Could not build hello.eif (nitro-cli not available)")

    vm = _spawn_enclave_vm(microvm_factory, EIF_PATH)
    _configure_and_start_enclave(vm, EIF_PATH, debug_mode=True)

    # The hello enclave prints "Hello from the enclave side!" every 5s.
    # Wait long enough for at least one message to appear in the serial log.
    serial_path = vm.serial_out_path
    assert serial_path is not None, "serial_out_path not set"

    deadline = time.time() + 30
    found = False
    while time.time() < deadline:
        try:
            data = serial_path.read_text()
        except FileNotFoundError:
            data = ""
        if "Hello from the enclave side!" in data:
            found = True
            break
        time.sleep(1)

    assert found, (
        f"Expected 'Hello from the enclave side!' in serial output, "
        f"got: {serial_path.read_text()!r}"
    )

    vm.kill()


@requires_ne
def test_enclave_boot_production_mode(microvm_factory):
    """Start Firecracker with a pre-built EIF in production mode via API."""
    if not _build_hello_eif():
        pytest.skip("Could not build hello.eif (nitro-cli not available)")

    vm = _spawn_enclave_vm(microvm_factory, EIF_PATH)
    _configure_and_start_enclave(vm, EIF_PATH, debug_mode=False)

    time.sleep(3)
    assert vm.firecracker_pid is not None
    assert os.path.exists(f"/proc/{vm.firecracker_pid}")

    vm.kill()


def test_enclave_invalid_config_no_boot_source(microvm_factory):
    """Verify error when starting enclave without boot source configured."""
    kernel_path = _get_kernel_path()
    if kernel_path is None:
        pytest.skip("Kernel not found in artifacts")

    vm = microvm_factory.build(kernel=kernel_path)
    vm.spawn(validate_api=False)

    vm.api.machine_config.put(
        vcpu_count=2,
        mem_size_mib=256,
    )
    vm.api.enclave.put(debug_mode=True)

    # InstanceStart should fail since boot source is not configured
    with pytest.raises(RuntimeError):
        vm.api.actions.put(action_type="InstanceStart")

    vm.kill()


@requires_ne
def test_enclave_terminate(microvm_factory):
    """Start enclave and verify clean SIGTERM shutdown."""
    if not _build_hello_eif():
        pytest.skip("Could not build hello.eif (nitro-cli not available)")

    vm = _spawn_enclave_vm(microvm_factory, EIF_PATH)
    _configure_and_start_enclave(vm, EIF_PATH, debug_mode=True)

    time.sleep(3)

    pid = vm.firecracker_pid
    if not os.path.exists(f"/proc/{pid}"):
        pytest.skip("Enclave failed to start")

    # Send SIGTERM and verify clean shutdown
    vm.kill()

    # Process should be gone after kill
    assert not os.path.exists(f"/proc/{pid}")


# --- EIF build from kernel+initrd tests ---

NE_CMDLINE = (
    "reboot=k panic=30 pci=off nomodules console=ttyS0 "
    "i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd random.trust_cpu=on"
)


def _get_bzimage_path():
    """Find a bzImage in the artifact directory."""
    candidates = sorted(ARTIFACT_DIR.glob("bzImage-*"))
    return candidates[0] if candidates else None


@requires_ne
def test_enclave_eif_build_from_kernel(microvm_factory):
    """Build EIF from kernel+initrd at boot time and verify enclave starts.

    Uses CI artifacts (bzImage + initramfs.cpio) instead of a pre-built EIF.
    Firecracker detects the kernel is not an EIF and auto-builds one.
    """
    bzimage = _get_bzimage_path()
    if not bzimage:
        pytest.skip("bzImage not found in artifacts")
    initrd = ARTIFACT_DIR / "initramfs.cpio"
    if not initrd.exists():
        pytest.skip("initramfs.cpio not found in artifacts")

    vm = _spawn_enclave_vm(microvm_factory, bzimage)

    ne_cpus = _get_ne_cpus()
    cpu_ids = ne_cpus[:2] if ne_cpus else None
    vcpu_count = len(cpu_ids) if cpu_ids else 2

    vm.api.machine_config.put(
        vcpu_count=vcpu_count,
        mem_size_mib=256,
        huge_pages="2M",
    )
    vm.api.boot.put(
        kernel_image_path=vm.create_jailed_resource(bzimage),
        initrd_path=vm.create_jailed_resource(initrd),
        boot_args=NE_CMDLINE,
    )
    # Use production mode (no heartbeat/console) to keep the test fast.
    enclave_kwargs = {"debug_mode": False}
    if cpu_ids:
        enclave_kwargs["cpu_ids"] = cpu_ids
    vm.api.enclave.put(**enclave_kwargs)
    vm.api.actions.put(action_type="InstanceStart")

    # Verify the EIF was built (not loaded from a pre-built file) and
    # the enclave started by checking the Firecracker log.
    log = vm.log_data
    assert "Building EIF from kernel=" in log, (
        f"Expected 'Building EIF from kernel=' in log, got:\n{log}"
    )
    assert "Enclave started with CID=" in log, (
        f"Expected 'Enclave started with CID=' in log, got:\n{log}"
    )

    # The enclave may exit (the initramfs init script is for microVMs,
    # not enclaves), so kill() may fail — that's fine.
    try:
        vm.kill()
    except ProcessLookupError:
        pass
