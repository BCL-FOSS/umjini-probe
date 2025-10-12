#!/bin/sh
set -e

WRKDIR="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="bcl-umj-probe"
VERSION="1.0.0"
ARCH="all"
BUILD_DIR="$WRKDIR/bcl_umj_probe"
MAINTAINER="derekb@baughcl.com"
DESCRIPTION="umjiniti probe for network monitoring, mapping & troubleshooting."

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

install_py_dependencies() {
    DISTRO=$1
    echo "Updating package repository..."

    case "$DISTRO" in
        debian|ubuntu)
            sudo apt update -y
            PACKAGE_MANAGER="apt"
            ;;
        *)
            echo "Unknown or unsupported distribution. Exiting."
            exit 1
            ;;
    esac

    echo "Install python-venv if not installed already"
    sudo $PACKAGE_MANAGER install -y python3.12-venv

    echo "Creating Python venv inside build staging..."
    sudo python3 -m venv "$BUILD_DIR/venv"
    sudo "$BUILD_DIR/venv/bin/pip" install --upgrade pip
    sudo "$BUILD_DIR/venv/bin/pip" install -r requirements.txt
    sudo "$BUILD_DIR/venv/bin/pip" install .

    echo "Installation of dependencies completed."
}

DISTRIBUTION=$(get_distro)
install_py_dependencies "$DISTRIBUTION"

echo "umjiniti-probe built successfully."
