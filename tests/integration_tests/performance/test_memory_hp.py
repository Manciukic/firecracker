# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the performance of memory hotplugging."""

import framework.utils as utils

import pytest
import time

def install_udev_rules(uvm):
    """HACK: this should be in the rootfs but I'm lazy"""
    uvm.ssh.check_output("""echo "#!/bin/python3
import sys
import time

boot_time = time.clock_gettime(time.CLOCK_BOOTTIME)
dev = sys.argv[2]
action = sys.argv[1]
extra = sys.argv[3] if len(sys.argv) > 3 else ''
with open('/tmp/memory-hp.log', 'a') as f:
    f.write(f'[{boot_time:.6f}][{dev}] New memory was {action} ({extra})\\n')
" > /sbin/log-memory-hp
""")
    uvm.ssh.check_output("chmod +x /sbin/log-memory-hp")
    uvm.ssh.check_output("""echo 'SUBSYSTEM=="memory", ACTION=="add", RUN+="/sbin/log-memory-hp add %k"' > /etc/udev/rules.d/99-memory-hp.rules""")
    uvm.ssh.check_output("""echo 'SUBSYSTEM=="memory", ACTION=="remove", RUN+="/sbin/log-memory-hp remove %k"' >> /etc/udev/rules.d/99-memory-hp.rules""")
    uvm.ssh.check_output("""echo 'SUBSYSTEM=="memory", ATTR{state}=="online", RUN+="/sbin/log-memory-hp online %k %s{state}"' >> /etc/udev/rules.d/99-memory-hp.rules""")
    uvm.ssh.check_output("""echo 'SUBSYSTEM=="memory", ATTR{state}=="offline", RUN+="/sbin/log-memory-hp offline %k %s{state}"' >> /etc/udev/rules.d/99-memory-hp.rules""")
    uvm.ssh.check_output("udevadm control --reload-rules")
    uvm.ssh.check_output("udevadm settle")

@pytest.fixture
def hp_microvm(request, microvm_factory, guest_kernel_linux_6_1, rootfs_rw):
    """Creates a microvm with the networking setup used by the performance tests in this file.
    This fixture receives its vcpu count via indirect parameterization"""
    vcpu_count = 2
    mem_size_mib=1024
    state, hp_size = request.param
    boot_args = f"memhp_default_state={state}"

    vm = microvm_factory.build(guest_kernel_linux_6_1, rootfs_rw, monitor_memory=False)
    vm.help.enable_console()
    vm.spawn(log_level="Info", emit_metrics=True)
    vm.basic_config(vcpu_count=vcpu_count, mem_size_mib=mem_size_mib, boot_args=boot_args)
    vm.add_net_iface()
    vm.api.memory_hp.put(total_size_mib=hp_size)
    vm.start()
    vm.pin_threads(0)

    install_udev_rules(vm)

    return vm

def time_of_last_message(logs, pattern):
    try:
        return max(
            float(line.split("]")[0].strip("[")) for line in logs if pattern in line
        )
    except ValueError:
        return 0

def fetch_guest_kern_logs(uvm):
    logs = uvm.ssh.check_output("dmesg").stdout
    return logs.splitlines()

def fetch_guest_memory_hp_logs(uvm):
    logs = uvm.ssh.check_output("cat /tmp/memory-hp.log").stdout
    return logs.splitlines()

def timed_memory_hotplug(uvm, size):
    """Wait for all memory hotplug events to be processed"""
    start_api = time.time()
    uvm.api.memory_hp.patch(requested_size_mib=size)
    end_api = time.time()
    while uvm.api.memory_hp.get().json()["plugged_size_mib"] != size:
        time.sleep(0.001)
    end_plug = time.time()
    return (end_api - start_api, end_plug - start_api)

def measure_guest_time(uvm, hotplug):
    guest_start = time_of_last_message(
        fetch_guest_kern_logs(uvm), "requested size:"
    )
    # ensure the guest had enough time to hotplug
    time.sleep(1)
    guest_end = time_of_last_message(
        fetch_guest_memory_hp_logs(uvm), "New memory was online" if hotplug else "New memory was remove"
    )
    return guest_end - guest_start

def get_rss_from_pmap(uvm):
    _, output, _ = utils.check_output("pmap -X {}".format(uvm.firecracker_pid))
    return int(output.split("\n")[-2].split()[1], 10)

@pytest.mark.nonci
@pytest.mark.parametrize("hp_microvm", [
        ("online_movable", 1024),
        ("online_movable", 2048),
        ("online_movable", 4096),
        ("online_movable", 8192),
    ], indirect=True)
def test_hotplug_latency(hp_microvm, metrics):
    """Test the latency of hotplugging memory"""
    uvm = hp_microvm
    hp_size = uvm.api.memory_hp.get().json()["total_size_mib"]

    rss_before = get_rss_from_pmap(uvm)
    api_time, plug_time = timed_memory_hotplug(uvm, hp_size)
    print(uvm.ssh.check_output("free -h").stdout)
    guest_online_time = measure_guest_time(uvm, True)
    rss_after_hotplug = get_rss_from_pmap(uvm)

    print()
    print(f"HotPlug API time: {api_time*1000:.2f}ms")
    print(f"HotPlug Plug time: {plug_time*1000:.2f}ms")
    print(f"HotPlug Online time: {guest_online_time*1000:.2f}ms")

    api_time, unplug_time = timed_memory_hotplug(uvm, 0)
    guest_offline_time = measure_guest_time(uvm, False)
    rss_after_hotunplug = get_rss_from_pmap(uvm)

    print(f"HotUnPlug API time: {api_time*1000:.2f}ms")
    print(f"HotUnPlug Unplug time: {unplug_time*1000:.2f}ms")
    print(f"HotUnPlug Offline time: {guest_offline_time*1000:.2f}ms")

    api_time, plug_time = timed_memory_hotplug(uvm, hp_size)
    guest_online_time = measure_guest_time(uvm, True)
    rss_after_second_hotplug = get_rss_from_pmap(uvm)

    print(f"HotPlug API time: {api_time*1000:.2f}ms")
    print(f"HotPlug Plug time: {plug_time*1000:.2f}ms")
    print(f"HotPlug Online time: {guest_online_time*1000:.2f}ms")

    print(f"RSS before: {rss_before}kB")
    print(f"RSS after hotplug: {rss_after_hotplug}kB")
    print(f"RSS after hotunplug: {rss_after_hotunplug}kB")
    print(f"RSS after 2nd hotplug: {rss_after_second_hotplug}kB")