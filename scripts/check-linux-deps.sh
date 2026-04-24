#!/usr/bin/env bash
# Probe which Linux packages are present / missing for a Wireshark
# source build. Lists one per line with OK / MISS prefix so you can
# grep MISS to see what to `sudo apt install`.

for p in \
    build-essential cmake ninja-build pkg-config python3 perl flex bison \
    libglib2.0-dev libgcrypt20-dev libgnutls28-dev libc-ares-dev \
    libpcap-dev libxml2-dev liblua5.4-dev liblz4-dev libminizip-dev \
    libzstd-dev libnghttp2-dev libnghttp3-dev libsmi2-dev libsnappy-dev \
    libspandsp-dev libbrotli-dev libssh-dev libkrb5-dev libmaxminddb-dev \
    libilbc-dev libopus-dev libsbc-dev libspeexdsp-dev libpcre2-dev
do
    if dpkg -s "$p" 2>/dev/null | grep -q 'Status: install'; then
        echo "OK    $p"
    else
        echo "MISS  $p"
    fi
done
