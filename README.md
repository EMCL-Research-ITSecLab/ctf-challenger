
# CTF-Challenger

## Setup

To set up the service, follow these steps:
1. Disable the Proxmox VE repositories to prevent error output from apt update
2. Clone this repository into `/root/`
3. `cd /root/ctf-challenger/setup/`
4. Edit the `/root/ctf-challenger/setup/.env` variables to suit the environment of the Proxmox installation and the desired values
5. Install pre-requisites by running `bash /root/ctf-challenger/setup/install_requirements.sh`
6. Run the setup by executing `python3 /root/ctf-challenger/setup/setup.py`
7. Wait for the setup to complete, which may take a while (~10 minutes)
8. After the setup is complete, you can access the service at `http://localhost/` or `http://<external-proxmox-ip>/`


## Dummy .env file

```env
PROXMOX_HOST='10.0.0.1'
PROXMOX_USER='root@pam'
PROXMOX_PASSWORD='admin123'
PROXMOX_PORT='8006'
BACKEND_PORT='8000'
PROXMOX_INTERNAL_IP='10.0.3.4'
PROXMOX_EXTERNAL_IP='10.0.3.4'
PROXMOX_HOSTNAME='pve'
PROXMOX_LVM_STORAGE='local-lvm'
PROXMOX_SSH_KEYFILE='/root/.ssh/id_rsa'

UBUNTU_BASE_SERVER_URL='ChangeMeToYourMirror'
SSL_TLS_CERTS_DIR='/root/ctf-challenger/setup/certs'
DNSMASQ_BACKEND_DIR='/etc/dnsmasq-backend'

DATABASE_FILES_DIR='/root/ctf-challenger/database'
DATABASE_NAME='ctf_challenger'
DATABASE_USER='postgres'
DATABASE_PASSWORD='ChangeMe123!'
DATABASE_PORT='5432'
DATABASE_HOST='10.0.0.102'

WEBSERVER_FILES_DIR='/root/ctf-challenger/webserver'
WEBSERVER_USER='www-data'
WEBSERVER_GROUP='www-data'
WEBSERVER_ROOT='/var/www/html'
WEBSERVER_HOST='10.0.0.101'
WEBSERVER_HTTP_PORT='80'
WEBSERVER_HTTPS_PORT='443'

WEBSERVER_DATABASE_USER='api_user'
WEBSERVER_DATABASE_PASSWORD='ChangeMe123!'

BACKEND_FILES_DIR='/root/ctf-challenger/backend'
BACKEND_LOGGING_DIR='/var/log/backend'

OPENVPN_SUBNET='10.64.0.0/16'
OPENVPN_SERVER_IP='10.64.0.1'

BACKEND_NETWORK_SUBNET='10.0.0.1/24'
BACKEND_NETWORK_ROUTER='10.0.0.1'
BACKEND_NETWORK_DEVICE='backend'
BACKEND_NETWORK_HOST_MIN='10.0.0.2'
BACKEND_NETWORK_HOST_MAX='10.0.0.254'

DATABASE_MAC_ADDRESS='0E:00:00:00:00:01'
WEBSERVER_MAC_ADDRESS='0E:00:00:00:00:02'

WEBSITE_ADMIN_USER='admin'
WEBSITE_ADMIN_PASSWORD='ChangeMe123!'

BACKEND_AUTHENTICATION_TOKEN='api-token'

CHALLENGES_ROOT_SUBNET='10.128.0.0'
CHALLENGES_ROOT_SUBNET_MASK='255.128.0.0'

MONITORING_VPN_INTERFACE='ctf_monitoring'
MONITORING_DMZ_INTERFACE='dmz_monitoring'

MONITORING_VM_MAC_ADDRESS='0E:00:00:00:00:03'
MONITORING_HOST='10.0.0.103'
MONITORING_VM_USER='ubuntu'
MONITORING_VM_PASSWORD='ChangeMe123!'
BANNER_SERVER_PORT='80'
MONITORING_VM_ID='9000'
MONITORING_VM_NAME='monitoring-vm'
MONITORING_VM_MEMORY='10240'
MONITORING_VM_CORES='2'
MONITORING_VM_DISK='32G'
MONITORING_FILES_DIR='/root/ctf-challenger/monitoring'

GRAFANA_PORT='3000'
GRAFANA_USER='admin'
GRAFANA_PASSWORD='ChangeMe123!'
GRAFANA_FILES_SETUP_DIR='/root/ctf-challenger/monitoring/grafana'
GRAFANA_FILES_DIR='/etc/grafana'

PROMETHEUS_PORT='9090'
POSTGRES_EXPORTER_PORT='9187'
POSTGRES_EXPORTER_PASSWORD='ChangeMe123!'
PROXMOX_EXPORTER_PORT='9221'
MONITORING_VM_EXPORTER_PORT='9100'
DATABASE_VM_EXPORTER_PORT='9100'
WEBSERVER_VM_EXPORTER_PORT='9100'
WEBSERVER_APACHE_EXPORTER_PORT='9117'
PROXMOX_EXPORTER_TOKEN_NAME='pve_exporter_token'
PVE_EXPORTER_DIR='/etc/pve-exporter'

WAZUH_MANAGER_PORT='9200'
WAZUH_API_USER='wazuh-wui'
WAZUH_API_PASSWORD='ChangeMe123!'
WAZUH_DASHBOARD_USER='kibanaserver'
WAZUH_DASHBOARD_PASSWORD='ChangeMe123!'
WAZUH_INDEXER_USER='admin'
WAZUH_INDEXER_PASSWORD='ChangeMe123!'
WAZUH_ENROLLMENT_PASSWORD='ChangeMe123!'
WAZUH_API_PORT='55000'
WAZUH_NETWORK_DEVICE='vrtmon'
WAZUH_NETWORK_DEVICE_IPV6='fd12:3456:789a:1::1'
WAZUH_NETWORK_DEVICE_CIDR='64'
WAZUH_NETWORK_SUBNET='fd12:3456:789a:1::/64'
WAZUH_MANAGER_IPV6='fd12:3456:789a:1::101/64'
WAZUH_FILE_DIR='/root/ctf-challenger/monitoring/wazuh'
WAZUH_REGISTRATION_PORT='1515'
WAZUH_COMMUNICATION_PORT='1514'

CLICKHOUSE_HTTPS_PORT='8443'
CLICKHOUSE_NATIVE_PORT='9440'
CLICKHOUSE_USER='default'
CLICKHOUSE_PASSWORD='ChangeMe123!'
CLICKHOUSE_SQL_DIR='/root/ctf-challenger/monitoring/clickhouse/sql'
MONITORING_DNS='clickhouse.local'

VECTOR_FILES_DIR='/root/ctf-challenger/monitoring/vector'
VECTOR_DIR='/etc/vector'

SURICATA_LOG_DIR='/var/log/suricata'
SURICATA_FILES_DIR='/etc/suricata'
SURICATA_RULES_DIR='/var/lib/suricata/rules'

ZEEK_SITE_DIR='/opt/zeek/share/zeek/site'

CLOUD_INIT_NETWORK_DEVICE='vmbr-cloud'
CLOUD_INIT_NETWORK_DEVICE_IP='10.32.0.1'
CLOUD_INIT_NETWORK_DEVICE_CIDR='20'
CLOUD_INIT_NETWORK_SUBNET='10.32.0.0/20'

ROTATE_DAYS='90'
LOGROTATE_CONFIG_DIR='/etc/logrotate.d'
PCAP_ROTATION_INTERVAL='*/15'

IPTABLES_FILE='/etc/iptables-backend/iptables.sh'
```
