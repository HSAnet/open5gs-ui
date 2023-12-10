Network capture
***************

Unfortunately, the availability of Python modules specifically designed for capturing network traffic
is limited. Scapy, the only native Python tool for this purpose, struggles to handle large volumes of
data, leading to packet loss. Alternatively, executing tcpdump or tshark through subprocess creates a
fragmented stream, hindering continuous data analysis. As a result, libpcap emerges as the only viable
option. Despite its slim Python wrapper and absence of direct documentation, libpcap can be effectively
utilized with the aid of C-level documentation and comprehensive tutorials available on `tcpdump's website`_.

.. _tcpdump's website: https://www.tcpdump.org/index.html#documentation

Libpcap
=======

Installation
------------

Since there are numerous versions of libpcap available on pip and Anaconda, it's essential to install
the correct version of libpcap for the application to function correctly. To achieve this, libpcap
needs to be installed on the system first. Afterwards, it can be installed using either pip or conda,
following the specified commands.

.. code-block:: console

   sudo apt-get install libpcap-dev
   pip install libpcap
   conda install -c conda-forge libpcap

Required python modules
-----------------------

.. code-block::

   import libpcap as pcap
   import ctypes as ct

Creating network device
-----------------------

.. code-block::
   :linenos:

   err_buf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
   device: bytes = str.encode(device_name)
   pd = pcap.create(device, err_buf)




   immediate: bool = True  # According to manpage, this should always be true if supported
   nonblock: int = 0
   snapshot_len: int = 262144
   timeout: int = 1000

   # Create Device
