CMAKE_VERSION="3.27.9"

# Setup System
sudo apt update
sudo apt upgrade
sudo apt install make gcc g++ libsctp-dev lksctp-tools iproute2 libssl-dev git -y

# Install cmake (APT version is too old!)
function install_cmake () {
  wget -qO- https://github.com/Kitware/CMake/releases/download/v$CMAKE_VERSION/cmake-$CMAKE_VERSION.tar.gz | tar xvz -C ~/Downloads/
  cd ~/Downloads/cmake-$CMAKE_VERSION/ || return
  ./configure --prefix=/opt/cmake
  gmake -j4
  sudo make -j4 install
  rm -rf ~/Downloads/cmake-$CMAKE_VERSION
}
install_cmake


# Export CMAKE-Path to environment
sudo echo "$(echo "PATH=\"")""$(cat /etc/environment|grep -oP 'PATH="\K[^"]+')""$(echo ":/opt/cmake/bin")""$(echo "\"")" > /etc/environment
export PATH=$PATH:/opt/cmake/bin

# Install Uransim
git clone https://github.com/aligungr/UERANSIM ~/UERANSIM
~/UERANSIM/make -j4

# create alias to startup ueransim with configuration
echo -e "function start_ueransim() {\n\t~/UERANSIM/build/nr-gnb -c ~/UERANSIM/config/gnb1.yaml\n\t~/UERANSIM/build/nr-ue -c ~/UERANSIM/config/ue1.yaml\n\tsudo ip r add default dev uesimtun0\n}" >> ~/.bashrc
# A network application can be executed like this
# ~/UERANSIM/build/nr-binder 10.45.0.3 firefox

# Restart System
sudo systemctl reboot

# sudo ip r add default dev uesimtun0