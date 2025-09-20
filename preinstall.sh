#!/bin/sh

open_firewall_port() {
    DISTRO=$1
    echo "Opening port 8000 on $DISTRO..."

    case "$DISTRO" in
        debian|ubuntu)
            # UFW setup
            if command -v ufw > /dev/null 2>&1; then
                sudo ufw allow 8000/tcp
                echo "Port 8000 opened in UFW."
            else
                echo "UFW not installed. Skipping UFW rule."
            fi

            # iptables setup
            if command -v iptables > /dev/null 2>&1; then
                sudo iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
                echo "Port 8000 opened in iptables."

                # Persist iptables rules if iptables-persistent is available
                if command -v iptables-save > /dev/null 2>&1 && [ -d /etc/iptables ]; then
                    sudo sh -c "iptables-save > /etc/iptables/rules.v4"
                    echo "iptables rules saved to /etc/iptables/rules.v4."
                fi
            else
                echo "iptables not installed. Skipping iptables rule."
            fi
            ;;
        rhel|centos|fedora|rocky|almalinux)
            if systemctl is-active --quiet firewalld; then
                sudo firewall-cmd --permanent --add-port=8000/tcp
                sudo firewall-cmd --reload
                echo "Port 8000 opened in firewalld."
            else
                echo "firewalld not active. Skipping firewall rule."
            fi
            ;;
        *)
            echo "Unknown or unsupported distribution. Skipping firewall setup."
            ;;
    esac
}


install_dependencies() {
    DISTRO=$1
    echo "Updating package repository..."

    case "$DISTRO" in
        debian|ubuntu)
            sudo apt update

            if ! command -v redis-server > /dev/null 2>&1; then
                echo "Installing Redis..."
                sudo apt-get install lsb-release curl gpg
                curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
                sudo chmod 644 /usr/share/keyrings/redis-archive-keyring.gpg
                echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list
                sudo apt-get update
                sudo apt-get install redis
            
                echo "Enabling and starting Redis service..."
                sudo systemctl enable redis-server
                sudo systemctl start redis-server
            else
                echo "redis-server is already installed."
            fi

            PACKAGE_MANAGER="apt"
            PACKAGE_LIST="tshark tcpdump gpsd gpsd-clients iputils-ping iperf3 aircrack-ng libpcap-dev p0f traceroute graphviz"
            ;;
        rhel|centos|fedora|rocky|almalinux)
            sudo dnf update

            if ! command -v redis > /dev/null 2>&1; then
                echo "Installing redis..."
                sudo yum install redis || sudo dnf install redis

                sudo systemctl enable redis
                sudo systemctl start redis
            else
                echo "traceroute is already installed."
            fi
            PACKAGE_MANAGER="dnf"
            PACKAGE_LIST="tshark tcpdump gpsd gpsd-clients iputils-ping iperf3 aircrack-ng libpcap-dev p0f traceroute graphviz"
            ;;
        *)
            echo "Unknown or unsupported distribution. Exiting."
            exit 1
            ;;
    esac

    echo "Installing packages: $PACKAGE_LIST"
    sudo $PACKAGE_MANAGER install -y $PACKAGE_LIST

    # Python setup
    echo "Checking for Python installation..."
    if ! command -v python3 > /dev/null 2>&1; then
        echo "Installing Python3..."
        case "$DISTRO" in
            debian|ubuntu) sudo apt install -y python3 ;;
            rhel|centos|fedora|rocky|almalinux) sudo yum install -y python3 || sudo dnf install -y python3 ;;
        esac
    fi

    # pip setup
    if ! command -v pip3 >/dev/null 2>&1 || ! command -v pip >/dev/null 2>&1; then
        echo "Installing pip3..."
        case "$DISTRO" in
            debian|ubuntu) sudo apt install -y python3-pip ;;
            rhel|centos|fedora|rocky|almalinux) sudo yum install -y python3-pip || sudo dnf install -y python3-pip ;;
        esac
    fi

    # python3-venv setup
    echo "Checking for python3-venv installation..."
    if ! python3 -m venv > /dev/null 2>&1; then
        echo "Installing python3.12-venv..."
        case "$DISTRO" in
            debian|ubuntu) sudo apt install -y python3.12-venv ;;
            rhel|centos|fedora|rocky|almalinux) sudo yum install -y python3.12-venv || sudo dnf install -y python3.12-venv ;;
        esac
    fi

    echo "Installation of dependencies completed."
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
install_dependencies "$DISTRIBUTION"
open_firewall_port "$DISTRIBUTION"