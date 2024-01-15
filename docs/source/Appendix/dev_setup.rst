Test Setup
==========

The project utilizes `Open5GS`_, a GNodeB, and User Equipments (UEs) to emulate a complete 5G system. GNodeB and
UEs can be simulated using `UERANSIM`_. While both can be set up locally, this project enhances simulation realism
by installing Open5GS and UERANSIM on distinct virtual machines. The base OS for both machines are Ubuntu/Debian.

.. Open5GS: https://open5gs.org/
.. UERANSIM: https://github.com/aligungr/UERANSIM

VM-Setup
--------

`VirtualBox`_ is used to create the virtual machines. To enable communication between these machines,
a ``Network Manager`` needs to be established.

.. _VirtualBox: https://www.virtualbox.org/

.. figure:: /media/vbox_network_manager.png
   :alt: Image of Virtualbox Network manager

   Virtual Box Network Manager configuration

Upon establishing a Host-Network using the Network Manager, the network needs to be assigned as a network adapter
to both machines. The Open5GS machine necessitates a secondary adapter for this purpose, whereas the UERANSIM machine
only requires this single adapter as it should not access the internet through the default adapter.

.. figure:: /media/vbox_open5g_net.png
   :alt: Image network setup Open5GS machine

   Open5GS network adapter settings

.. figure:: /media/vbox_ueransim_net.png
   :alt: Image Network setup UERANSIM machine

   UERANSIM network adapter settings

Open5GS
-------

System setup
++++++++++++

To begin, essential developer tools like git, curl, and others need to be installed. Open5GS necessitates MongoDB,
while the Open5GS-webUI demands Node.js. After configuring all dependencies, Open5GS can be installed using the
apt-packet-manager.

.. code-block:: sh
   :caption: Install Open5GS and components (except webUI)

   sudo apt install -y gnupg curl ca-certificates curl software-properties-common git
   # MongoDB
   curl -fsSL https://pgp.mongodb.com/server-7.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor
   echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
   sudo apt-get install -y mongodb-org
   sudo systemctl start mongod
   sudo systemctl enable mongod
   # NodeJS
   sudo mkdir -p /etc/apt/keyrings
   curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - &&\
   sudo apt-get install -y nodejs
   # Open5gs
   sudo add-apt-repository ppa:open5gs/latest -y
   sudo apt-get -y update && apt install -y open5gs
   # restart the system
   sudo restart

Installing Open5GS might temporarily disrupt network connectivity. While restarting the system isn't strictly
mandatory, it's the simplest way to refresh and update the operating system. After rebooting, the Open5GS-webUI
can be installed and accessed.

.. code-block:: sh
   :caption: Install webUI and retrieve address

   # Open5gs - WebUI
   curl -fsSL https://open5gs.org/open5gs/assets/webui/install | sudo -E bash -
   # Check of of WebUI
   journalctl -u open5gs-webui.service | grep 'Ready on'

   # example output
   $ Jan 15 07:19:04 open5g-VirtualBox node[3531]: > Ready on http://localhost:9999

Upon accessing the webUI via a web browser, a new subscriber must be provisioned. For a new subscriber,
only the SUPI from the `GNodeB configuration`_ file is required.

Configuration
+++++++++++++

Once the entire setup is complete and the system is running, the Open5GS **amf.yaml** and **upf.yaml** configuration
files require editing. By default, these files are located in the ``/etc/open5gs/`` directory.

.. code-block:: yaml
   :caption: Open5GS config amf.yaml
   :emphasize-lines: 3
   :linenos:

   ngap:
    server:
      - address: 192.168.56.6

In the above extract from the ``amf.yaml`` the ngap-server-address needs to be replaced with the IP-Address
assigned to the machine by the Host-Network.

.. code-block:: yaml
   :caption: Open5GS config upf.yaml
   :emphasize-lines: 3
   :linenos:

   gtpu:
    server:
      - address: 192.168.56.6

In the above extract from the ``upf.yaml`` the gtpu-server-address needs to be replaced with the IP-Address
assigned to the machine by the Host-Network.

At this stage the `Client App`_ can be installed and run.

Ueransim
--------

System Setup
++++++++++++

To commence, fundamental developer tools like Git and gcc need to be installed. UERANSIM necessitates a more
recent CMake version than the apt-packet-manager offers. Consequently, version 3.27.9 requires manual compilation
and configuration.

.. code-block:: sh
   :caption: Install UERANSIM and components

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

   # reboot system
   sudo reboot

Config
++++++

The UERANSIM configuration files reside in the ``~/UERANSIM/config/`` directory. To facilitate consistent reuse,
copying and renaming the default files ``custom-gnb.yaml`` and ``custom-ue.yaml`` to ``gnb1.yaml`` and ``ue1.yaml``
is recommended.

.. code-block:: sh

   cp custom-gnb.yaml gnb1.yaml
   cp custom-ue.yaml ue1.yaml

GNodeB configuration
____________________

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 1, 2, 6
   :caption: GNodeB config extract

   ngapIp: 192.168.56.4   # gNB's local IP address for N2 Interface (Host-adapter IP-Address)
   gtpIp: 192.168.56.4    # gNB's local IP address for N3 Interface (Host-adapter IP-Address)

   # List of AMF address information
   amfConfigs:
     - address: 192.168.56.6  # Open5GS IP-Address given by Host-Adapter
       port: 38412


UE configuration
________________

The UEconfig ~/UERANSIM/config/custom-ue.yaml contains the supi, which is required to setup a subscriber
with the Open5GS webUI.

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 2
   :caption: UE config extract

   # IMSI number of the UE. IMSI = [MCC|MNC|MSISDN|] (In total 15 digits)
   supi: 'imsi-28601000000001'

Start
+++++

.. code-block:: sh
   :linenos:
   :emphasize-lines: 5

   ~/UERANSIM/build/nr-gnb -c ~/UERANSIM/config/gnb1.yaml
   sudo ~/UERANSIM/build/nr-ue -c ~/UERANSIM/config/ue1.yaml

   # UE output
   [2024-01-15 10:12:56.809] [app] [info] Connection setup for PDU session[1] is successful, TUN interface[uesimtun0, 10.45.0.3] is up.

The UERANSIM ``nr-ue`` tool emits numerous messages to the console. As evident from the extract above, it records the
IP address of the uesimtun0 interface, which can then be employed to establish an internet connection through Open5GS.
In order to resolve any IP-Address a default gateway needs to be employed as show in the example below.

.. code-block:: sh

   sudo ip r add default dev uesimtun0

.. code-block:: sh

   ~/UERANSIM/build/nr-binder 10.45.0.3 firefox

Once everything is setup, the UERANSIM ``nr-binder`` tool can be used with many networking applications, using the
tunnel interface.

Client App
----------

Install and start client app
++++++++++++++++++++++++++++

The client application is developed using Python 3.12, which is not available through the apt-package manager at
the time of writing. Therefore, the official Python ``ppa:deadsnake/ppa`` repository is added to provide access to
this version. Additionally, the application requires root privileges to capture network traffic. To achieve this,
the command in line 20 launches a new shell and executes the application with root permissions.

.. literalinclude:: ../_static/open5gs_python_setup.sh
   :language: sh
   :caption: Downloading and starting the client-application
   :emphasize-lines: 20

.. code-block:: sh
   :caption: example console output

      Direction       Source_ip    Source_Host  Destination_ip      Dest_Host       Size
   0         UP       10.45.0.4   Unknown Host   142.251.37.10  muc11s23-i...  364 bytes
   1         UP       10.45.0.4   Unknown Host   34.107.243.93  93.243.107...       1 KB
   2         UP       10.45.0.4   Unknown Host  34.149.100.209  209.100.14...  100 bytes
   3         UP       10.45.0.4   Unknown Host         8.8.8.8     dns.google  557 bytes
   4       Down   142.251.37.10  muc11s23-i...       10.45.0.4   Unknown Host       1 KB
   5       Down   34.107.243.93  93.243.107...       10.45.0.4   Unknown Host       4 KB
   6       Down  34.149.100.209  209.100.14...       10.45.0.4   Unknown Host       1 KB
   7       Down         8.8.8.8     dns.google       10.45.0.4   Unknown Host       1 KB

