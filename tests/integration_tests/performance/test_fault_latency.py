# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Performance tests for anonymous memory fault-in latency in Firecracker VMs."""

import pytest

from framework.microvm import HugePagesConfig

ITERATIONS = 10
ALLOC_SIZE_MIB = 128


@pytest.mark.nonci
@pytest.mark.parametrize("huge_pages", HugePagesConfig)
@pytest.mark.parametrize("access_pattern", ["sequential", "random"])
def test_anon_fault_latency(
    microvm_factory, guest_kernel, rootfs, huge_pages, access_pattern, metrics
):
    """
    Test the latency of fault-in anonymous memory allocation in VMs.

    This test measures how quickly a VM can allocate and fault-in anonymous memory
    using mmap() with MAP_ANONYMOUS | MAP_PRIVATE, then touching the first byte of
    each page to trigger page faults. Tests both sequential and random access patterns.

    Tests are run with different huge pages settings.
    """

    # Run multiple iterations with fresh VMs
    for i in range(ITERATIONS):
        uvm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
        uvm.spawn()
        uvm.basic_config(
            huge_pages=huge_pages,
        )
        uvm.add_net_iface()
        uvm.start()

        # Add VM dimensions to metrics
        if i == 0:  # Only set dimensions once
            metrics.set_dimensions(
                {
                    "performance_test": "test_anon_fault_latency",
                    "huge_pages": str(huge_pages),
                    "access_pattern": access_pattern,
                    **uvm.dimensions,
                }
            )

        # Run the fault latency helper
        _, duration_ns_str, _ = uvm.ssh.check_output(
            f"/usr/local/bin/fault_latency_helper {ALLOC_SIZE_MIB} {access_pattern}"
        )
        duration_ns = int(duration_ns_str.strip())

        # Convert to milliseconds for metrics
        duration_ms = duration_ns / 1_000_000

        metrics.put_metric("fault_latency", duration_ms, "Milliseconds")
        print(f"i={i} duration_ms={duration_ms:.0f}ms")
