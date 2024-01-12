# Basics
sudo apt install -y gnupg curl ca-certificates curl software-properties-common git
# MongoDB
curl -fsSL https://pgp.mongodb.com/server-7.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt-get install -y mongodb-org
sudo systemctl start mongod
sudo systemctl enable mongod
# NodeJS
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" | sudo tee /etc/apt/sources.list.d/nodesource.list
sudo apt-get install nodejs
# Open5gs
sudo add-apt-repository ppa:open5gs/latest
sudo apt-get -y update && apt install -y open5gs
# Restart the system
# Open5gs - WebUI
curl -fsSL https://open5gs.org/opten5gs/assets/webui/install | sudo -E bash -
# Check of of WebUI
systemctl status open5gs-webui.service | grep 'Ready on'

# Open5g Network settings
sudo touch /etc/init.d/open5g_startup.sh
sudo bash -c "echo -e 'sysctl -w net.ipv4.ip_forward=1; sysctl -w net.ipv6.conf.all.forwarding=1; iptables -t nat -A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE; ip6tables -t nat -A POSTROUTING -s 2001:db8:cafe::/48 ! -o ogstun -j MASQUERADE; ufw disable; iptables -I INPUT -i ogstun -j ACCEPT; iptables -I INPUT -s 10.45.0.0/16 -j DROP; ip6tables -I INPUT -s 2001:db8:cafe::/48 -j DROP' > /etc/init.d/open5g_startup.sh"
sudo chmod 700 /etc/init.d/open5g_startup.sh

# Download configuration files
sudo rm /etc/open5gs/upf.yaml /etc/open5gs/amf.yaml
sudo wget -P /etc/open5gs/ https://open5gs-ui.readthedocs.io/en/latest/_downloads/631b3452d949bb64b2ef1bc7ea24425f/amf.yaml
sudo wget -P /etc/open5gs/ https://open5gs-ui.readthedocs.io/en/latest/_downloads/772cdda825a53a95ddd4cae6821baf8c/upf.yaml