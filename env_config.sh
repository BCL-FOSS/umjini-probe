#!/bin/sh
set -e

setup_probe_dir() {
    DISTRO=$1
    echo "Configuring probe directory..."

    case "$DISTRO" in
        debian|ubuntu)
            sudo chown $USER:$USER .env
            sudo chmod 700 .env
}

setup_log_dir() {
    DISTRO=$1
    echo "Configuring log directory..."

    case "$DISTRO" in
        debian|ubuntu)
            sudo mkdir -p /var/log/umj
            sudo chown $USER:$USER /var/log/umj
            sudo chmod 744 /var/log/umj
}

get_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /usr/share/man/man1/freebsd-update.1.gz ]; then
        echo "freebsd"
    else
        echo "unknown"
    fi
}

DISTRIBUTION=$(get_distro)
setup_log_dir "$DISTRIBUTION"