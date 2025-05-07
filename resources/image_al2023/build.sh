#!/bin/bash

set -euxo pipefail

docker build . -t firecracker/al2023
CTR_ID=$(docker create firecracker/al2023)

BUILD_DIR="../../build/al2023.rootfs"
OUT_DIR="../../build/img/$(uname -m)"
sudo rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR
docker export $CTR_ID | tar -C $BUILD_DIR --exclude='dev/*' --exclude 'etc/*shadow-' --exclude '.pwd.lock' -xf -

rm -f $OUT_DIR/al2023.squashfs
mksquashfs $BUILD_DIR $OUT_DIR/al2023.squashfs -all-root -noappend -comp zstd

rm -f $OUT_DIR/al2023.ext4
truncate --size=1G $OUT_DIR/al2023.ext4
mkfs.ext4 -b 4k -L / -m 0 -d $BUILD_DIR -F $OUT_DIR/al2023.ext4
MNT_DIR=$(mktemp -d /tmp/mnt.XXXXXX)
sudo mount $OUT_DIR/al2023.ext4 $MNT_DIR
sudo chown -R root:root $MNT_DIR
sudo umount $MNT_DIR

docker rm $CTR_ID || true

rm -f $OUT_DIR/al2023.id_rsa
cp id_rsa $OUT_DIR/al2023.id_rsa

rm -f $OUT_DIR/al2023.id_rsa.pub
cp id_rsa.pub $OUT_DIR/al2023.id_rsa.pub