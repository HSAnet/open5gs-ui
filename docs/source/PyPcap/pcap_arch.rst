Network Data Listener
*********************

The network listener embodies three crucial requirements. Firstly, it should be inherently accessible and extendable,
enabling seamless integration into various applications and facilitating future modifications. This calls for a
simplified architecture that minimizes complexity and promotes maintainability. Secondly, the listener must be
designed for efficiency, effectively capturing the entirety of network traffic without compromising performance.
This necessitates robust algorithms and optimized data handling techniques. Lastly, the captured data should be
readily accessible, allowing applications to seamlessly retrieve and process the captured information. This implies
implementing appropriate data storage mechanisms and providing convenient access interfaces.

Libpcap
=======

Unfortunately, the availability of Python modules specifically designed for capturing network traffic
is limited. Scapy, the only native Python tool for this purpose, struggles to handle large volumes of
data, leading to packet loss. Alternatively, executing tcpdump or tshark through subprocess creates a
fragmented stream, hindering continuous data analysis. As a result, libpcap emerges as the only viable
option. Despite its slim Python wrapper and absence of direct documentation, libpcap can be effectively
utilized with the aid of C-level documentation and comprehensive tutorials available on `tcpdump's website`_.

.. _tcpdump's website: https://www.tcpdump.org/index.html#documentation


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


Accessing network devices
-------------------------

Creating a network device with libpcap can be a challenging task, prone to errors, but following this
comprehensive guide will simplify the process and ensure a successful outcome.

.. code-block:: python
   :linenos:

   sys_net_devices: ct.POINTER = ct.POINTER(pcap.pcap_if_t)()
   err_buff = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
   pcap.findalldevs(ct.byref(sys_net_devices), err_buff)

Initially, we require a Cython pointer capable of managing a ``pcap_if_t`` structure and an error buffer to
capture any potential error messages. Feeding these arguments into the ``findalldevs()`` function will yield
either a return value of 0 or a non-zero value. If the return value is non-zero, an error has occurred.

To facilitate an accessible list of available devices, the following generator function iteratively yields each
device, encapsulated within a ``NetworkDevice`` object, enabling convenient access to device information.

.. code-block:: python
   :linenos:

   def __get_network_device() -> Generator[NetworkDevice, None, None]:
      sys_net_devices: ct.POINTER = ct.POINTER(pcap.pcap_if_t)()
      err_buff = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
      if not pcap.findalldevs(ct.byref(sys_net_devices), err_buff):
         it: ct.POINTER = sys_net_devices
         while it:
            it = it.contents
            yield NetworkDevice(it)
            it = it.next
         pcap.freealldevs(sys_net_devices)
      else:
         raise NetworkError(err_to_str(err_buff=err_buff))

NetworkDevice Object
====================

The ``ǸetworkDevice`` Object expects one parameter. A ``pcap_if`` struct, containing these fields (next, name, description, addresses and flags).
Each object has its default values for the device capturing setup.

- immediate (allays true): Starts capturing network traffic even if the device isn't ready yet and/or network-connection wasn't yet properly established.
- nonblock: This is an integer with boolean intention. 0 meaning False, 1 for True. If True, the function won't wait for the device. Instead it returns an error if the device wasn't ready.
- snapshot_len: Specifies the maximum length of packets to capture. If set too low, packet data may be lost. If set to high, unnecessary additional computation power is needed.
- timeout: The amount waited in milliseconds for the network device to become ready. May throw error if set too low.

.. code-block:: python

   class NetworkDevice:

    def __init__(self, device: pcap.pcap_if):
        self.__snapshot_len: int = 262444
        self.__nonblock: int = 0
        self.__timeout: int = 1000
        self.__name: str = device.name.decode('utf-8')
        self.__set_flags(device=device)
        self.__set_network_families(device=device)

        self.__pcap_dev = None
        self.__f_code = None


The ``__set_flags(``) method meticulously collects the device's operational flags, including (Connected, UP, Running, etc.),
and stores them as a list in the object's ``__flags`` attribute. The ``__set_network_families()`` method gathers information
regarding the device's network addresses (IPv4/IPv6) and organizes it as a dictionary.

To effectively retrieve the IP address and its corresponding mask from the ``pcap_if`` structure, the Python function
``struct.unpack_from()`` proves to be an useful tool.

.. code-block:: python

   addr_family = pcap_if.addresses.contents

   struct.unpack_from('<hH4s16sQ', addr_family.addr.contents)[2:4],
   struct.unpack_from('<hH4s16sQ', addr_family.netmask.contents)[2:4]

- **hH** - First two bytes (signed and unsigned) [sa_family + __pad1]
- **4s** - Bytes-Array with length 4 (IPv4) [ipv4-Addr/Mask]
- **16s** - Bytes-Array with length 16 (IPv6) [IPv6-Addr/Mask]
- **Q** - Padding (unsigned long) [__pad2]

Utilizing this string pattern and slicing the result from position ``[2:4]`` effectively retrieves the Address/Mask.
Up until now, the pattern can represent either IPv4 or IPv6 addresses. However, upon analyzing the results, it's
evident that the presence of any value within the IPv4 data conclusively indicates an IPv4 address and not an IPv6
address. Conversely, occasional occurrences of random values within the IPv6 data can be disregarded as they invariably
commence with illegal zero values. The following code example effectively identifies and flags these anomalies.

.. code-block:: python

   empty_array: Callable[[bytes], bool] = lambda arr: not any([b for b in arr if b != 0])
   if not empty_array(ip) and not empty_array(ip[:2]):
      continue


Once it is decided whether the program retrieved an IPv4 or IPv6 Address + Mask, the ``cdir`` `(Classless Inter-Domain Routing)`_
and ``Network-ID`` can be calculated.

.. _(Classless Inter-Domain Routing): https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing

.. role:: raw-html(raw)
   :format: html

.. code-block:: python

   'cdir': bin(bytes_to_int(mask)).count('1')
   'net_id': bytes_to_int(ip) >> ((32 if len(ip) <= 4 else 128) - bin(bytes_to_int(mask)).count('1'))

To determine the CIDR, the binary representation of the mask (byte-array) is analyzed, counting the number of 1s.
:raw-html:`<br />` For example: :raw-html:`<br />`
``255.255.255.0  -> 1111 1111  1111 1111  1111 1111  0000 0000 -> 24 (cdir value)``

To determine the Network ID, the integer-value of the IP address is bit-shifted rightwards by
(32 for IPv4 or 128 for IPv6) minus the CIDR value. This effectively extracts the network portion of the IP address.







Network-Listener Architecture
=============================

.. figure:: /media/network_arch.svg
   :alt: Image Network-Sniffer architecture


