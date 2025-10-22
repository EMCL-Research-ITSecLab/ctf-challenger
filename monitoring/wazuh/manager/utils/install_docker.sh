#!/bin/bash

DIV="------------------------------------------------------"

if [ $(id -u) -ne 0 ]
then
    echo "Please run this script as root or using sudo!"
    exit 0
fi

function print_divider () {
    terminal=/dev/pts/1
    columns=$(stty -a <"$terminal" | grep -Po '(?<=columns )\d+')
    printf "%${columns}s\n" | tr " " "-"
}

function section_header () {
    print_divider
    echo "${1}..."
    print_divider
}

function section_footer () {
    echo ""
}

if [ $SUDO_USER ]
then
    user=$SUDO_USER
else
    user=`whoami`
fi

section_header "Add docker requirements and certificates"
apt-get update
apt-get -y install ca-certificates curl sudo
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
section_footer

section_header "Add docker apt repository"
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update
section_footer

section_header "Install docker packages"
apt-get -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
section_footer

section_header "Add docker service and start it"
sudo systemctl enable docker.service
sudo systemctl enable containerd.service
sudo systemctl start docker
section_footer

section_header "Add docker group and add active user $user to docker group"
groupadd docker
usermod -aG docker $user
echo "Done. You might need to log out for group changes to take effect."
section_footer

section_header "Add docker-compose standalone binary"
curl -SL https://github.com/docker/compose/releases/download/v2.33.1/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
section_footer

echo "Docker installed successfully."
echo ""