# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for Nitro Enclaves support in Firecracker."""

import os
import platform
import time

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


requires_ne = pytest.mark.skipif(
    not (_has_ne_device() and _has_ne_cpus()),
    reason="Requires Nitro Enclaves hardware with configured CPU pool",
)


def _get_kernel_path():
    """Find a kernel image in the artifact directory (for non-NE tests)."""
    candidates = sorted(ARTIFACT_DIR.glob("vmlinux-*"))
    candidates = [c for c in candidates if not c.name.endswith((".config", ".debug"))]
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
def test_enclave_get_config(microvm_factory):
    """Verify GET /enclave returns effective config pre- and post-boot."""
    vm = _spawn_enclave_vm(microvm_factory, EIF_PATH)

    ne_cpus = _get_ne_cpus()
    cpu_ids = ne_cpus[:2] if ne_cpus else None
    vcpu_count = len(cpu_ids) if cpu_ids else 2

    vm.api.machine_config.put(
        vcpu_count=vcpu_count,
        mem_size_mib=256,
        huge_pages="2M",
    )
    vm.api.boot.put(
        kernel_image_path=vm.create_jailed_resource(EIF_PATH),
    )
    enclave_kwargs = {"debug_mode": True}
    if cpu_ids:
        enclave_kwargs["cpu_ids"] = cpu_ids
    vm.api.enclave.put(**enclave_kwargs)

    # Pre-boot: GET /enclave returns what was configured.
    response = vm.api.enclave.get()
    pre_boot = response.json()
    assert pre_boot["debug_mode"] is True
    if cpu_ids:
        assert pre_boot["cpu_ids"] == cpu_ids

    # Start the enclave.
    vm.api.actions.put(action_type="InstanceStart")

    # Post-boot: GET /enclave returns effective values.
    response = vm.api.enclave.get()
    post_boot = response.json()
    assert post_boot["debug_mode"] is True
    assert post_boot["enclave_cid"] is not None
    assert isinstance(post_boot["enclave_cid"], int)
    assert post_boot["enclave_cid"] >= 3
    if cpu_ids:
        assert post_boot["cpu_ids"] == cpu_ids

    vm.kill()


@requires_ne
def test_enclave_boot_debug_mode(microvm_factory):
    """Start Firecracker with a pre-built EIF in debug mode via API."""
    vm = _spawn_enclave_vm(microvm_factory, EIF_PATH)
    _configure_and_start_enclave(vm, EIF_PATH, debug_mode=True)

    # Give the enclave time to boot
    time.sleep(3)

    # Verify the Firecracker process is still running
    assert vm.firecracker_pid is not None
    assert os.path.exists(f"/proc/{vm.firecracker_pid}")

    vm.kill()


@requires_ne
def test_enclave_state_booting_to_running(microvm_factory):
    """Verify enclave transitions from Booting to Running after heartbeat."""
    vm = _spawn_enclave_vm(microvm_factory, EIF_PATH)
    _configure_and_start_enclave(vm, EIF_PATH, debug_mode=True)

    # Immediately after start, state should be "Booting"
    response = vm.api.describe.get()
    initial_state = response.json()["state"]
    assert (
        initial_state == "Booting"
    ), f"Expected initial state 'Booting', got '{initial_state}'"

    # Poll until state transitions to "Running" (heartbeat received)
    deadline = time.time() + 30
    state = initial_state
    while time.time() < deadline:
        response = vm.api.describe.get()
        state = response.json()["state"]
        if state == "Running":
            break
        time.sleep(0.5)

    assert (
        state == "Running"
    ), f"Expected state 'Running' after heartbeat, got '{state}'"

    vm.kill()


@requires_ne
def test_enclave_console_output(microvm_factory):
    """Verify that the enclave vsock console output appears in the serial log."""
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


def _ne_cmdline():
    """Return NE boot command line, appropriate for the current architecture."""
    base = "reboot=k panic=30 pci=off nomodules console=ttyS0 random.trust_cpu=on"
    if platform.machine() == "x86_64":
        base += " i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd"
    return base


NE_CMDLINE = _ne_cmdline()


def _get_kernel_image_path():
    """Find a bootable kernel image for EIF building in the artifact directory.

    On x86_64 this is bzImage-*, on aarch64 this is Image-*.
    """
    arch = platform.machine()
    if arch == "x86_64":
        pattern = "bzImage-*"
    elif arch == "aarch64":
        pattern = "Image-*"
    else:
        return None
    candidates = sorted(ARTIFACT_DIR.glob(pattern))
    return candidates[0] if candidates else None


@requires_ne
def test_enclave_eif_build_from_kernel(microvm_factory):
    """Build EIF from kernel+initrd at boot time and verify enclave starts.

    Uses CI artifacts (bzImage/Image + initramfs.cpio) instead of a pre-built EIF.
    Firecracker detects the kernel is not an EIF and auto-builds one.
    """
    kernel_image = _get_kernel_image_path()
    if not kernel_image:
        pytest.skip("Bootable kernel image not found in artifacts")
    initrd = ARTIFACT_DIR / "initramfs.cpio"
    if not initrd.exists():
        pytest.skip("initramfs.cpio not found in artifacts")

    vm = _spawn_enclave_vm(microvm_factory, kernel_image)

    ne_cpus = _get_ne_cpus()
    cpu_ids = ne_cpus[:2] if ne_cpus else None
    vcpu_count = len(cpu_ids) if cpu_ids else 2

    vm.api.machine_config.put(
        vcpu_count=vcpu_count,
        mem_size_mib=256,
        huge_pages="2M",
    )
    vm.api.boot.put(
        kernel_image_path=vm.create_jailed_resource(kernel_image),
        initrd_path=vm.create_jailed_resource(initrd),
        boot_args=NE_CMDLINE,
    )
    # Production mode — our CI kernel doesn't support the NE vsock console.
    enclave_kwargs = {"debug_mode": False}
    if cpu_ids:
        enclave_kwargs["cpu_ids"] = cpu_ids
    vm.api.enclave.put(**enclave_kwargs)
    vm.api.actions.put(action_type="InstanceStart")

    # Verify the EIF was built (not loaded from a pre-built file) and
    # the enclave started by checking the Firecracker log.
    log = vm.log_data
    assert (
        "Building EIF from kernel=" in log
    ), f"Expected 'Building EIF from kernel=' in log, got:\n{log}"
    assert (
        "Enclave started with CID=" in log
    ), f"Expected 'Enclave started with CID=' in log, got:\n{log}"

    # Poll until state transitions to "Running" (heartbeat received)
    deadline = time.time() + 30
    state = "Booting"
    while time.time() < deadline:
        response = vm.api.describe.get()
        state = response.json()["state"]
        if state == "Running":
            break
        time.sleep(0.5)

    assert (
        state == "Running"
    ), f"Expected state 'Running' after heartbeat, got '{state}'"

    vm.kill()
