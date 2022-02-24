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

function install_tools() {
    source /etc/os-release

    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 6 ]]; then
        yum install net-tools -y > /dev/null
    elif [[ "${ID}" == "debian" || "${ID}" == "ubuntu" || "${ID}" == "linuxmint" ]]; then
        apt-get install net-tools -y > /dev/null
    else
        echo -e "Current system is ${ID} ${VERSION_ID}, it is not in the list of supported systems, installation is interrupted."
        exit -1
    fi
}

# parameters:
# ${1} return_value: last command return value.
# ${2} cmd_text: full command text.
# ${3} exit_script_if_failed: exit the script if failed.
function check_cmd_success() {
    if [ ${1} -ne 0 ]; then
        if [ "${3}" == true ]; then
            echo -e "Failed running \"${2}\", exiting..."
            exit -1
        else
            echo -e "Failed running \"${2}\", continue..."
        fi
    else
        echo -e "running \"${2}\" success, continue..."
    fi
}

function remove_tunnel_settings() {
    local cmd_info=""

    sleep 1
    cmd_info="ip tuntap del dev ${TUN_NETWORK_DEV} mode tun"
    ${cmd_info}
    check_cmd_success $? "${cmd_info}" true
    sleep 1
}

function create_tunnel_settings() {
    local cmd_info=""

    echo 1 > /proc/sys/net/ipv4/ip_forward
    check_cmd_success $? 'echo 1 > /proc/sys/net/ipv4/ip_forward' true

    cmd_info="iptables -t nat -A POSTROUTING -s 10.10.0.0/8 -o ${CURRENT_NETWORK_DEV} -j MASQUERADE"
    ${cmd_info}
    check_cmd_success $? "${cmd_info}" true

    cmd_info="ip tuntap add dev ${TUN_NETWORK_DEV} mode tun"
    ${cmd_info}
    check_cmd_success $? "${cmd_info}" true

    cmd_info="ifconfig ${TUN_NETWORK_DEV} 10.10.0.1 dstaddr 10.10.0.2 up"
    ${cmd_info}
    check_cmd_success $? "${cmd_info}" true

    echo "Please execute the following commands manually."
    cmd_info="./ToyVpnServer ${TUN_NETWORK_DEV} 8000 test -m 1400 -a 10.10.0.2 32 -d 8.8.8.8 -r 0.0.0.0 0 &"
    echo ${cmd_info}
}

function main() {
    check_root_account
    install_tools
    remove_tunnel_settings
    create_tunnel_settings

    echo -e "Configurate success."
}

main $@

exit 0
