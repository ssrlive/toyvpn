#!/bin/bash

build_type=${1}

if [[ ${build_type} == "release" ]]; then
cargo build --${build_type}
else
build_type=debug
cargo build
fi

ext=$?
if [[ ${ext} -ne 0 ]]; then
    exit ${ext}
fi

CARGO_TARGET_DIR=`pwd`/target

sudo setcap cap_net_admin=eip ${CARGO_TARGET_DIR}/${build_type}/toyvpn
${CARGO_TARGET_DIR}/${build_type}/toyvpn &
pid=$!
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
trap "kill ${pid}" INT TERM
wait ${pid}
