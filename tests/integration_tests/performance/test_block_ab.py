# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for block device emulation."""

import concurrent
import os
import shutil
from pathlib import Path
from statistics import mean

import pytest

import host_tools.drive as drive_tools
from framework.utils import CmdBuilder, check_output, track_cpu_utilization

# size of the block device used in the test, in MB
BLOCK_DEVICE_SIZE_MB = 2048

# Time (in seconds) for which fio "warms up"
WARMUP_SEC = 10

# Time (in seconds) for which fio runs after warmup is done
RUNTIME_SEC = 30

# VM guest memory size
GUEST_MEM_MIB = 1024


def prepare_microvm_for_test(microvm):
    """Prepares the microvm for running a fio-based performance test by tweaking
    various performance related parameters."""
    _, _, stderr = microvm.ssh.check_output(
        "echo 'none' > /sys/block/vdb/queue/scheduler"
    )
    assert stderr == ""

    # First, flush all guest cached data to host, then drop guest FS caches.
    _, _, stderr = microvm.ssh.check_output("sync")
    assert stderr == ""
    _, _, stderr = microvm.ssh.check_output("echo 3 > /proc/sys/vm/drop_caches")
    assert stderr == ""

    # Then, flush all host cached data to hardware, also drop host FS caches.
    check_output("sync")
    check_output("echo 3 > /proc/sys/vm/drop_caches")


def run_fio(microvm, mode, block_size, ioengine):
    """Run a fio test in the specified mode with block size bs."""
    cmd = (
        CmdBuilder("fio")
        .with_arg(f"--name={mode}-{block_size}")
        .with_arg(f"--rw={mode}")
        .with_arg(f"--bs={block_size}")
        .with_arg("--filename=/dev/vdb")
        .with_arg("--time_base=1")
        .with_arg(f"--size={BLOCK_DEVICE_SIZE_MB}M")
        .with_arg("--direct=1")
        .with_arg(f"--ioengine={ioengine}")
        .with_arg("--iodepth=32")
        .with_arg(f"--ramp_time={WARMUP_SEC}")
        .with_arg(f"--numjobs={microvm.vcpus_count}")
        # Set affinity of the entire fio process to a set of vCPUs equal in size to number of workers
        .with_arg(
            f"--cpus_allowed={','.join(str(i) for i in range(microvm.vcpus_count))}"
        )
        # Instruct fio to pin one worker per vcpu
        .with_arg("--cpus_allowed_policy=split")
        .with_arg("--randrepeat=0")
        .with_arg(f"--runtime={RUNTIME_SEC}")
        .with_arg(f"--write_bw_log={mode}")
        .with_arg(f"--write_lat_log={mode}")
        .with_arg(f"--write_iops_log={mode}")
        .with_arg("--log_avg_msec=1000")
        .with_arg("--output-format=json+")
        .build()
    )

    logs_path = Path(microvm.jailer.chroot_base_with_id()) / "fio_output"

    if logs_path.is_dir():
        shutil.rmtree(logs_path)

    logs_path.mkdir()

    prepare_microvm_for_test(microvm)

    # Start the CPU load monitor.
    with concurrent.futures.ThreadPoolExecutor() as executor:
        cpu_load_future = executor.submit(
            track_cpu_utilization,
            microvm.firecracker_pid,
            RUNTIME_SEC,
            omit=WARMUP_SEC,
        )

        # Print the fio command in the log and run it
        rc, _, stderr = microvm.ssh.run(f"cd /tmp; {cmd}")
        assert rc == 0, stderr
        assert stderr == ""

        microvm.ssh.scp_get("/tmp/*.log", logs_path)
        microvm.ssh.check_output("rm /tmp/*.log")

        return logs_path, cpu_load_future.result()


def process_fio_logs(vm, fio_mode, metric, logs_dir, metrics):
    """Parses the fio logs in `{logs_dir}/{fio_mode}_bw.*.log and emits their contents as CloudWatch metrics"""

    unit = {
        "bw": "Kilobytes/Second",
        "clat": "Microseconds",
        "iops": "Count/Second",
    }.get(metric)

    # how to aggregate the 1s metrics coming from each separate job
    agg = {
        # calculate the total bandwidth and iops achieved across all jobs
        "iops": sum,
        "bw": sum,
        # calculate the mean latency across all jobs
        "clat": mean,
    }.get(metric)

    assert unit is not None and agg is not None, f"Unknown metric: {metric}"

    data = [
        Path(f"{logs_dir}/{fio_mode}_{metric}.{job_id + 1}.log")
        .read_text("UTF-8")
        .splitlines()
        for job_id in range(vm.vcpus_count)
    ]

    for tup in zip(*data):
        metrics_read = []
        metrics_write = []

        for line in tup:
            _, value, direction, _ = line.split(",", maxsplit=3)
            value = int(value.strip())
            # fio emits latency as nsecs but EMF only supports down to micros
            if metric == "clat":
                value = value / 1000

            # See https://fio.readthedocs.io/en/latest/fio_doc.html#log-file-formats
            match direction.strip():
                case "0":
                    metrics_read.append(value)
                case "1":
                    metrics_write.append(value)
                case _:
                    assert False

        if metrics_read:
            metrics.put_metric(f"{metric}_read", agg(metrics_read), unit)
        if metrics_write:
            metrics.put_metric(f"{metric}_write", agg(metrics_write), unit)


def run_block_performance_test(
    test_name,
    microvm_factory,
    guest_kernel_acpi,
    rootfs,
    vcpus,
    fio_mode,
    fio_block_size,
    fio_engine,
    io_engine,
    metrics,
):
    """Runs block device tests"""

    vm = microvm_factory.build(guest_kernel_acpi, rootfs, monitor_memory=False)
    vm.spawn(log_level="Info", emit_metrics=True)
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=GUEST_MEM_MIB)
    vm.add_net_iface()

    # Add a secondary block device for benchmark tests.
    if io_engine != "vhost-user":
        fs = drive_tools.FilesystemFile(
            os.path.join(vm.fsfiles, "scratch"), BLOCK_DEVICE_SIZE_MB
        )
        vm.add_drive("scratch", fs.path, io_engine=io_engine)
    else:
        fs = drive_tools.FilesystemFile(size=BLOCK_DEVICE_SIZE_MB)
        vm.add_vhost_user_drive("scratch", fs.path)

    vm.start()

    dimensions = {
        "performance_test": test_name,
        "io_engine": io_engine,
        "fio_mode": fio_mode,
        "fio_engine": fio_engine,
        "fio_block_size": str(fio_block_size),
        **vm.dimensions,
    }
    metrics.set_dimensions(dimensions)
    # also emit with the legacy dimension set to avoid breaking dashboards
    # can be removed once we have enough data to switch the dashboards to the new metrics
    if fio_engine == "libaio":
        legacy_dimensions = {**dimensions}
        del legacy_dimensions["fio_engine"]
        metrics.put_dimensions(legacy_dimensions)

    next_cpu = vm.pin_threads(0)
    if io_engine == "vhost-user":
        vm.disks_vhost_user["scratch"].pin(next_cpu)

    logs_dir, cpu_util = run_fio(vm, fio_mode, fio_block_size, fio_engine)

    process_fio_logs(vm, fio_mode, "bw", logs_dir, metrics)
    process_fio_logs(vm, fio_mode, "clat", logs_dir, metrics)
    process_fio_logs(vm, fio_mode, "iops", logs_dir, metrics)

    for thread_name, values in cpu_util.items():
        for value in values:
            metrics.put_metric(f"cpu_utilization_{thread_name}", value, "Percent")


@pytest.mark.timeout(120)
@pytest.mark.nonci
@pytest.mark.parametrize("vcpus", [1, 2], ids=["1vcpu", "2vcpu"])
@pytest.mark.parametrize("fio_mode", ["randread", "randwrite"])
@pytest.mark.parametrize("fio_block_size", [4096, 65536], ids=["bs4096", "bs65536"])
@pytest.mark.parametrize("fio_engine", ["libaio", "sync"])
def test_block_performance(
    microvm_factory,
    guest_kernel_acpi,
    rootfs,
    vcpus,
    fio_mode,
    fio_block_size,
    fio_engine,
    io_engine,
    metrics,
):
    """
    Execute block device emulation benchmarking scenarios.
    """

    if fio_engine == "sync" and vcpus != 1 and fio_block_size != 4096:
        pytest.skip("Run sync tests only for 1 vcpu and 4k blocks to measure FC latency overhead")
    if fio_block_size == 65536 and vcpus != 2:
        pytest.skip("Run 64k blocks tests only for 2 vcpus to measure max throughput")
    run_block_performance_test(
        "test_block_performance",
        microvm_factory,
        guest_kernel_acpi,
        rootfs,
        vcpus,
        fio_mode,
        fio_block_size,
        fio_engine,
        io_engine,
        metrics,
    )


@pytest.mark.nonci
@pytest.mark.parametrize("vcpus", [1, 2], ids=["1vcpu", "2vcpu"])
@pytest.mark.parametrize("fio_mode", ["randread"])
@pytest.mark.parametrize("fio_block_size", [4096, 65536], ids=["bs4096", "bs65536"])
@pytest.mark.parametrize("fio_engine", ["libaio", "sync"])
def test_block_vhost_user_performance(
    microvm_factory,
    guest_kernel_acpi,
    rootfs,
    vcpus,
    fio_mode,
    fio_block_size,
    fio_engine,
    metrics,
):
    """
    Execute block device emulation benchmarking scenarios.
    """

    if fio_engine == "sync" and vcpus != 1 and fio_block_size != 4096:
        pytest.skip("Run sync tests only for 1 vcpu and 4k blocks to measure FC latency overhead")
    if fio_block_size == 65536 and vcpus != 2:
        pytest.skip("Run 64k blocks tests only for 2 vcpus to measure max throughput")
    run_block_performance_test(
        "test_block_vhost_user_performance",
        microvm_factory,
        guest_kernel_acpi,
        rootfs,
        vcpus,
        fio_mode,
        fio_block_size,
        fio_engine,
        "vhost-user",
        metrics,
    )
