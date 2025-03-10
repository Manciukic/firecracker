<picture>
   <source media="(prefers-color-scheme: dark)" srcset="docs/images/fc_logo_full_transparent-bg_white-fg.png">
   <source media="(prefers-color-scheme: light)" srcset="docs/images/fc_logo_full_transparent-bg.png">
   <img alt="Firecracker Logo Title" width="750" src="docs/images/fc_logo_full_transparent-bg.png">
</picture>

Our mission is to enable secure, multi-tenant, minimal-overhead execution of
container and function workloads.

Read more about the Firecracker Charter [here](CHARTER.md).

## PCI Proof-of-Concept

### How to passthrough a PCI device

First of all, you need to enable the IOMMU with a kernel command line argument 
(tested on Intel only):
```
$ sudo grubby --update-kernel ALL --args "intel_iommu=on"
$ sudo reboot
```

In order to be able to use the device, you first need to attach it to the vfio
driver:

```
# All commands below require root privileged
# Load the vfio driver
$ modprobe vfio-pci

# Find the device vendor and id
$ lspci -n -s 0000:18:00.0
18:00.0 0302: 10de:1eb8 (rev a1)

# Unbind from current driver (if no driver is attached, this will fail but it's ok)
$ echo 0000:18:00.0 > /sys/bus/pci/devices/0000:18:00.0/driver/unbind

# Bind to vfio driver
# alternatively, you can use a kernel command line argument: vfio-pci.ids=10de:1eb8
echo 10de 1eb8 > /sys/bus/pci/drivers/vfio-pci/new_id
```

After that, you can start firecracker without jailer or seccomp using vmconfig
json (no HTTP API is supported atm) as follows:

```json
{
  "pci": { 
    "enabled": true, 
    "vfio_devices": [
      { "path": "/sys/bus/pci/devices/0000:18:00.0/" } 
    ] 
  },
  // [...]
}
```

### How to use a NVIDIA GPU inside the Guest

This instructions use Ubuntu 24.04 (Noble):

```
wget https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.tar.gz
tar xvf noble-server-cloudimg-amd64.tar.gz
truncate -s20G noble-server-cloudimg-amd64.img
e2fsck -f noble-server-cloudimg-amd64.img
resize2fs noble-server-cloudimg-amd64.img

mkdir -p mnt
sudo mount noble-server-cloudimg-amd64.img mnt/

ssh-keygen -f id_rsa -N ""
sudo cp -v id_rsa.pub mnt/root/.ssh/authorized_keys

sudo chroot mnt/
# inside the chroot
passwd -d root

mv /etc/resolv.conf /etc/resolv.conf.bck
echo "nameserver 8.8.8.8" > /etc/resolv.conf

apt update
DRIVER_BRANCH=570
SERVER=-server
LINUX_FLAVOUR=generic
apt install -y linux-modules-nvidia-${DRIVER_BRANCH}${SERVER}-${LINUX_FLAVOUR}
apt install -y nvidia-driver-${DRIVER_BRANCH}${SERVER}
apt install -y nvidia-utils-${DRIVER_BRANCH}${SERVER}
apt install -y nvidia-cuda-toolkit nvidia-cuda-samples

# I'm using the getting started guide IPs
cat > /etc/netplan/01-ens2.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ens2:
      addresses:
        - 172.16.0.2/24
      routes:
        - to: default
          via: 172.16.0.1
      nameservers:
          search: []
          addresses: [8.8.8.8]
EOF

mv /etc/resolv.conf.bck /etc/resolv.conf
exit
# outside the chroot

sudo umount mnt/

# Setup networking
TAP_DEV="tap0"
TAP_IP="172.16.0.1"
MASK_SHORT="/30"

# Setup network interface
sudo ip link del "$TAP_DEV" 2> /dev/null || true
sudo ip tuntap add dev "$TAP_DEV" mode tap
sudo ip addr add "${TAP_IP}${MASK_SHORT}" dev "$TAP_DEV"
sudo ip link set dev "$TAP_DEV" up

# Enable ip forwarding
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo iptables -P FORWARD ACCEPT

# This tries to determine the name of the host network interface to forward
# VM's outbound network traffic through. If outbound traffic doesn't work,
# double check this returns the correct interface!
HOST_IFACE=$(ip -j route list default |jq -r '.[0].dev')

# Set up microVM internet access
sudo iptables -t nat -D POSTROUTING -o "$HOST_IFACE" -j MASQUERADE || true
sudo iptables -t nat -A POSTROUTING -o "$HOST_IFACE" -j MASQUERADE

cat > vm_config.json << EOF
{
  "pci": {
    "enabled": true,
    "vfio_devices": [
      { "path": "/sys/bus/pci/devices/0000:18:00.0/" }
    ]
  },
  "boot-source": {
    "kernel_image_path": "vmlinux",
    "boot_args": "console=ttyS0 reboot=k panic=1 iommu=off loglevel=8",
    "initrd_path": null
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "partuuid": null,
      "is_root_device": true,
      "cache_type": "Unsafe",
      "is_read_only": false,
      "path_on_host": "noble-server-cloudimg-amd64.img",
      "io_engine": "Sync",
      "rate_limiter": null,
      "socket": null
    }
  ],
  "machine-config": {
    "vcpu_count": 2,
    "mem_size_mib": 4096,
    "smt": false,
    "track_dirty_pages": false,
    "huge_pages": "None"
  },
  "cpu-config": null,
  "balloon": null,
  "network-interfaces": [
    {
        "iface_id": "net1",
        "guest_mac": "06:00:AC:10:00:02",
        "host_dev_name": "tap0"
    }
  ],
  "vsock": null,
  "logger": null,
  "metrics": null,
  "mmds-config": null,
  "entropy": null
}
EOF

# prepare the ubuntu kernel
wget https://raw.githubusercontent.com/torvalds/linux/refs/heads/master/scripts/extract-vmlinux
sudo bash extract-vmlinux mnt/boot/vmlinuz > vmlinux

sudo firecracker --config-file vm_config.json --no-api --no-seccomp

# login into the VM with username "root"
# check that nvidia drivers are working
nvidia-smi

# check that we can run an example from cuda samples
cd /usr/share/doc/nvidia-cuda-toolkit/examples/Samples/6_Performance/transpose
make NVCC=$(which nvcc) run
```

### What works

- multiple vfio devices (PF) can be passed through (no P2P)
- virtio-pci devices are supported (only block and net have been tested)

### Known issues

- BARs get relocated if the VM memory is less than 4GB due to a (unknown)
  conflict
- no support for ARM. It should be pretty easy to add it with a new FDT entry.
- no support for snapshot/resume (not even for virtio-pci devices).
- no support for vhost-user-blk.
- a legacy PCI bus is used instead of a PCIe root port. We should really go
  straight for a PCIe layout in the production implementation as it will
  simplify the passthrough of PCIe devices and device hotplugging.
- the entire guest physical memory is pre-allocated on boot if a vfio device is
  present (no plans to fix in PoC).
- it's not possible to toggle PCI support through HTTP API (only vmconfig json
  is supported at the moment).
- unit tests are not working.
- integration tests are not working, except
  `performance/test_{block,network}_ab.py`.

### Out of scope

- virtual iommu to avoid allocating the entire guest physical memory on boot
- PCI P2P between vfio devices
- passthrough of virtual functions

## What is Firecracker?

Firecracker is an open source virtualization technology that is purpose-built
for creating and managing secure, multi-tenant container and function-based
services that provide serverless operational models. Firecracker runs workloads
in lightweight virtual machines, called microVMs, which combine the security and
isolation properties provided by hardware virtualization technology with the
speed and flexibility of containers.

## Overview

The main component of Firecracker is a virtual machine monitor (VMM) that uses
the Linux Kernel Virtual Machine (KVM) to create and run microVMs. Firecracker
has a minimalist design. It excludes unnecessary devices and guest-facing
functionality to reduce the memory footprint and attack surface area of each
microVM. This improves security, decreases the startup time, and increases
hardware utilization. Firecracker has also been integrated in container
runtimes, for example
[Kata Containers](https://github.com/kata-containers/kata-containers) and
[Flintlock](https://github.com/liquidmetal-dev/flintlock).

Firecracker was developed at Amazon Web Services to accelerate the speed and
efficiency of services like [AWS Lambda](https://aws.amazon.com/lambda/) and
[AWS Fargate](https://aws.amazon.com/fargate/). Firecracker is open sourced
under [Apache version 2.0](LICENSE).

To read more about Firecracker, check out
[firecracker-microvm.io](https://firecracker-microvm.github.io).

## Getting Started

To get started with Firecracker, download the latest
[release](https://github.com/firecracker-microvm/firecracker/releases) binaries
or build it from source.

You can build Firecracker on any Unix/Linux system that has Docker running (we
use a development container) and `bash` installed, as follows:

```bash
git clone https://github.com/firecracker-microvm/firecracker
cd firecracker
tools/devtool build
toolchain="$(uname -m)-unknown-linux-musl"
```

The Firecracker binary will be placed at
`build/cargo_target/${toolchain}/debug/firecracker`. For more information on
building, testing, and running Firecracker, go to the
[quickstart guide](docs/getting-started.md).

The overall security of Firecracker microVMs, including the ability to meet the
criteria for safe multi-tenant computing, depends on a well configured Linux
host operating system. A configuration that we believe meets this bar is
included in [the production host setup document](docs/prod-host-setup.md).

## Contributing

Firecracker is already running production workloads within AWS, but it's still
Day 1 on the journey guided by our [mission](CHARTER.md). There's a lot more to
build and we welcome all contributions.

To contribute to Firecracker, check out the development setup section in the
[getting started guide](docs/getting-started.md) and then the Firecracker
[contribution guidelines](CONTRIBUTING.md).

## Releases

New Firecracker versions are released via the GitHub repository
[releases](https://github.com/firecracker-microvm/firecracker/releases) page,
typically every two or three months. A history of changes is recorded in our
[changelog](CHANGELOG.md).

The Firecracker release policy is detailed [here](docs/RELEASE_POLICY.md).

## Design

Firecracker's overall architecture is described in
[the design document](docs/design.md).

## Features & Capabilities

Firecracker consists of a single micro Virtual Machine Manager process that
exposes an API endpoint to the host once started. The API is
[specified in OpenAPI format](src/firecracker/swagger/firecracker.yaml). Read
more about it in the [API docs](docs/api_requests).

The **API endpoint** can be used to:

- Configure the microvm by:
  - Setting the number of vCPUs (the default is 1).
  - Setting the memory size (the default is 128 MiB).
  - Configuring a [CPU template](docs/cpu_templates/cpu-templates.md).
- Add one or more network interfaces to the microVM.
- Add one or more read-write or read-only disks to the microVM, each represented
  by a file-backed block device.
- Trigger a block device re-scan while the guest is running. This enables the
  guest OS to pick up size changes to the block device's backing file.
- Change the backing file for a block device, before or after the guest boots.
- Configure rate limiters for virtio devices which can limit the bandwidth,
  operations per second, or both.
- Configure the logging and metric system.
- `[BETA]` Configure the data tree of the guest-facing metadata service. The
  service is only available to the guest if this resource is configured.
- Add a [vsock socket](docs/vsock.md) to the microVM.
- Add a [entropy device](docs/entropy.md) to the microVM.
- Start the microVM using a given kernel image, root file system, and boot
  arguments.
- [x86_64 only] Stop the microVM.

**Built-in Capabilities**:

- Demand fault paging and CPU oversubscription enabled by default.
- Advanced, thread-specific seccomp filters for enhanced security.
- [Jailer](docs/jailer.md) process for starting Firecracker in production
  scenarios; applies a cgroup/namespace isolation barrier and then drops
  privileges.

## Tested platforms

We test all combinations of:

| Instance       | Host OS & Kernel | Guest Rootfs | Guest Kernel |
| :------------- | :--------------- | :----------- | :----------- |
| c5n.metal      | al2 linux_5.10   | ubuntu 24.04 | linux_5.10   |
| m5n.metal      | al2023 linux_6.1 |              | linux_6.1    |
| m6i.metal      |                  |              |              |
| m6a.metal      |                  |              |              |
| m7a.metal-48xl |                  |              |              |
| m6g.metal      |                  |              |              |
| m7g.metal      |                  |              |              |

## Known issues and Limitations

- The `pl031` RTC device on aarch64 does not support interrupts, so guest
  programs which use an RTC alarm (e.g. `hwclock`) will not work.

## Performance

Firecracker's performance characteristics are listed as part of the
[specification documentation](SPECIFICATION.md). All specifications are a part
of our commitment to supporting container and function workloads in serverless
operational models, and are therefore enforced via continuous integration
testing.

## Policy for Security Disclosures

The security of Firecracker is our top priority. If you suspect you have
uncovered a vulnerability, contact us privately, as outlined in our
[security policy document](SECURITY.md); we will immediately prioritize your
disclosure.

## FAQ & Contact

Frequently asked questions are collected in our [FAQ doc](FAQ.md).

You can get in touch with the Firecracker community in the following ways:

- Security-related issues, see our [security policy document](SECURITY.md).
- Chat with us on our
  [Slack workspace](https://join.slack.com/t/firecracker-microvm/shared_invite/zt-2tc0mfxpc-tU~HYAYSzLDl5XGGJU3YIg)
  _Note: most of the maintainers are on a European time zone._
- Open a GitHub issue in this repository.
- Email the maintainers at
  [firecracker-maintainers@amazon.com](mailto:firecracker-maintainers@amazon.com).

When communicating within the Firecracker community, please mind our
[code of conduct](CODE_OF_CONDUCT.md).
