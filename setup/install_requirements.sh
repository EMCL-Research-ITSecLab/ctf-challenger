#!/bin/bash
set -e

DEBIAN_VERSION_FULL=$(grep -oP '(?<=^DEBIAN_VERSION_FULL=).*' /etc/os-release | tr -d '"')
echo "Detected Debian version: $DEBIAN_VERSION_FULL"

if dpkg --compare-versions "$DEBIAN_VERSION_FULL" "ge" "13.0"; then
    echo "Debian >= 13.0 detected, installing ntpsec-ntpdate"
    apt update
    apt install -y ntpsec-ntpdate
else
    echo "Debian < 13.0 detected, installing legacy ntpdate"
    apt update
    apt install -y ntpdate
fi

ntpdate time.google.com

apt update
apt install -y \
    python3 \
    python3-pip \
    python3-psycopg2 \
    python3-dotenv \
    python3-tenacity

pip3 install -r requirements.txt --break-system-packages
