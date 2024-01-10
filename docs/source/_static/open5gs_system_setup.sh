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
systemctl status open5gs-webui.service | grea 'Ready on'