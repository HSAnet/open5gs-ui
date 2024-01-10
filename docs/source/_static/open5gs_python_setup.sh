# clone app
mkdir ~/client_app
git clone https://github.com/HSAnet/open5gs-ui.git ~/client_app
# Installing python
sudo add-apt-repository universe
sudo apt update
VERSION=3.11
sudo apt install python$VERSION
sudo apt install python$VERSION-venv
# create virtual environment
python$VERSION -m venv ~/client_app/venv
source ~/client_app/venv/bin/activate
# Installing packages
python -m pip install regex libpcap argparse pandas
# Installing Libpcap-dev
sudo apt install libpcap-dev