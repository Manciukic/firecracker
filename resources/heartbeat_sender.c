// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Sends heartbeat byte (0xB7) to the host over vsock port 9000.
// Used in enclave initramfs to signal successful boot.
//
// When run as PID 1 (init), mounts essential filesystems first and
// sleeps forever after sending the heartbeat to keep the enclave alive.

#include <sys/mount.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <unistd.h>

#define HEARTBEAT_PORT 9000
#define HEARTBEAT_BYTE 0xB7
#define HOST_CID 3

static void send_heartbeat(void) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0)
        return;

    struct sockaddr_vm addr = {
        .svm_family = AF_VSOCK,
        .svm_port = HEARTBEAT_PORT,
        .svm_cid = HOST_CID,
    };

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return;
    }

    unsigned char byte = HEARTBEAT_BYTE;
    write(fd, &byte, 1);

    // Read the echo back
    read(fd, &byte, 1);

    close(fd);
}

int main(void) {
    // If running as init (PID 1), mount essential filesystems
    if (getpid() == 1) {
        mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
        mount("none", "/proc", "proc", 0, NULL);
        mount("none", "/sys", "sysfs", 0, NULL);
    }

    send_heartbeat();

    // If running as init, sleep forever to keep the enclave alive
    if (getpid() == 1)
        for (;;)
            pause();

    return 0;
}
