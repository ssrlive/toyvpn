#!/bin/bash

# 选一个不冲突的 tun 设备号.
TUN_NETWORK_DEV=tun0

# 自动获取当前网卡名称，形如 eth0
CURRENT_NETWORK_DEV=$(ip route | grep "default .* dhcp" | awk '{print $5}')

function check_root_account() {
    if [ `id -u` != 0 ]; then
        echo -e "当前账号不是 root 账号，请切换到 root 账号再运行本脚本。"
        echo -e "Current account is not root user, please switch to root user and re-execute this script."
        exit 1
    fi
}

function check_cmd_success() {
    if [ ${1} -ne 0 ]; then
        echo -e "Failed run '${2}', exiting..."
        exit -1
    fi
}

function main() {
    check_root_account

    echo 1 > /proc/sys/net/ipv4/ip_forward
    check_cmd_success $? 'echo 1 > /proc/sys/net/ipv4/ip_forward'

    iptables -t nat -A POSTROUTING -s 10.10.0.0/8 -o ${CURRENT_NETWORK_DEV} -j MASQUERADE
    check_cmd_success $? 'iptables -t nat -A POSTROUTING -s 10.10.0.0/8 -o ${CURRENT_NETWORK_DEV} -j MASQUERADE'

    ip tuntap add dev ${TUN_NETWORK_DEV} mode tun
    check_cmd_success $? 'ip tuntap add dev ${TUN_NETWORK_DEV} mode tun'

    ifconfig ${TUN_NETWORK_DEV} 10.10.0.1 dstaddr 10.10.0.2 up
    check_cmd_success $? 'ifconfig ${TUN_NETWORK_DEV} 10.10.0.1 dstaddr 10.10.0.2 up'

    # ./ToyVpnServer ${TUN_NETWORK_DEV} 8000 test -m 1400 -a 10.10.0.2 32 -d 8.8.8.8 -r 0.0.0.0 0
}

main $@

exit 0
