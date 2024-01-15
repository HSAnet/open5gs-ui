PYTHON_VERSION=3.12
# clone app
mkdir ~/client_app
git clone https://github.com/HSAnet/open5gs-ui.git ~/client_app
# Installing Libpcap-dev
sudo apt install -y libpcap-dev
# Installing python
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update
sudo apt install -y python$PYTHON_VERSION python$PYTHON_VERSION-venv
# create virtual environment
python$PYTHON_VERSION -m venv ~/client_app/venv
source ~/client_app/venv/bin/activate
pip install --upgrade pip
# Installing packages
python -m pip install regex libpcap argparse pandas
pip install -e ~/client_app
# Network traffic can only be captured executing the application as root-user
APP_DIR=/home/$(whoami)/client_app/app
sudo bash -c "cd ${APP_DIR}; source ../venv/bin/activate; python main.py"