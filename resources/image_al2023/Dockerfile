FROM public.ecr.aws/amazonlinux/amazonlinux:2023

RUN dnf swap -y openssl-libs openssl-snapsafe-libs
RUN dnf install -y systemd openssh-server tmux fio iproute socat vim passwd openssl
RUN echo fc-uvm > /etc/hostname
RUN ssh-keygen -A
# RUN yes C0maM1erda | passwd root
RUN passwd -d root

# for console in ttyS0; do
#     mkdir "/etc/systemd/system/serial-getty@$console.service.d/"
#     cat <<'EOF' > "/etc/systemd/system/serial-getty@$console.service.d/override.conf"
# [Service]
# # systemd requires this empty ExecStart line to override
# ExecStart=
# ExecStart=-/sbin/agetty --autologin root -o '-p -- \\u' --keep-baud 115200,38400,9600 %I dumb
# EOF
# done

COPY ./overlay/ / 
# Setup fcnet service. This is a custom Firecracker setup for assigning IPs
# to the network interfaces in the guests spawned by the CI.
RUN ln -s /etc/systemd/system/fcnet.service /etc/systemd/system/sysinit.target.wants/fcnet.service

# Disable resolved and ntpd
#
RUN rm -f /etc/systemd/system/multi-user.target.wants/systemd-resolved.service
RUN rm -f /etc/systemd/system/dbus-org.freedesktop.resolve1.service
RUN rm -f /etc/systemd/system/sysinit.target.wants/systemd-timesyncd.service

# # make /tmp a tmpfs
# RUN ln -s /usr/share/systemd/tmp.mount /etc/systemd/system/tmp.mount
# RUN systemctl enable tmp.mount

# don't need this
# RUN systemctl disable e2scrub_reap.service
# RUN rm -vf /etc/systemd/system/timers.target.wants/*

# RUN systemctl enable var-lib-systemd.mount

COPY id_rsa.pub /root/.ssh/authorized_keys

RUN chmod 400 /etc/shadow 
RUN chmod 400 /etc/gshadow 