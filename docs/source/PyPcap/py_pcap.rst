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

init()
------

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

Address families retrieval
++++++++++++++++++++++++++

To effectively retrieve the IP address and its corresponding mask from the ``pcap_if`` structure, the Python function
``struct.unpack_from()`` proves to be an useful tool.

.. code-block:: python

   addr_family = pcap_if.addresses.contents

   struct.unpack_from('<hH4s16sQ', addr_family.addr.contents)[2:4],
   struct.unpack_from('<hH4s16sQ', addr_family.netmask.contents)[2:4]

- hH - First two bytes (signed and unsigned) [sa_family + __pad1]
- 4s - Bytes-Array with length 4 (IPv4) [ipv4-Addr/Mask]
- 16s - Bytes-Array with length 16 (IPv6) [IPv6-Addr/Mask]
- Q - Padding (unsigned long) [__pad2]

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


Additional functionalities
--------------------------

setup()
+++++++

The ``setup()`` function allows for the NetworkDevice to be setup like a libpcap-device and used to capture packets.
At first the libpcap-device requires some basic information like the snapshot-length, the timeout and whether it should
capture immediately as mentioned above in `init()`_.

.. code-block:: python

   if 0 != (status := pcap.set_snaplen(self.__pcap_dev, self.__snapshot_len)):
      raise NetworkError(f'Device: {dev_to_str(self.__pcap_dev)}\nStatus: {str(status)}')
   try:
      pcap.set_immediate_mode(self.__pcap_dev, 1)
   except AttributeError as err:
      self.__pcap_logger.warning(f'Device: {dev_to_str(self.__pcap_dev)} does not support immediate mode!\n{str(err)}')
   if pcap.set_timeout(self.__pcap_dev, self.__timeout) != 0:
      raise NetworkError(f'Device: {dev_to_str(self.__pcap_dev)} - not able to set timeout!')

After initiating the device, it must be activated for live capturing.

.. code-block:: python

   if (status := pcap.activate(self.__pcap_dev)) < 0:
      raise NetworkError(f'Cannot activate device: {dev_to_str(self.__pcap_dev)}')
   elif status > 0:
      self.__pcap_logger.warning(f'Error occurred while Network device activation!\n'
                                 f'{dev_err(self.__pcap_dev)}')

Once the device is active, it is possible to add a BPF-capture-filter.
The Berkeley Packet Filter (BPF) operates at the network layer (Layer 3) of the Open Systems Interconnection (OSI)
model, enabling packet filtering based on source and destination addresses, ports, and other relevant fields.
IBM provides a comprehensive `cheat sheet`_ for beginners to effectively utilize BPF filters.

.. _cheat sheet: https://www.ibm.com/docs/en/qsip/7.5?topic=queries-berkeley-packet-filters

.. code-block:: python

   if pcap.compile(self.__pcap_dev, ct.byref(self.__f_code), str_to_bytes(' '.join(filter_bpf)), 1, pcap.PCAP_NETMASK_UNKNOWN) < 0:
      raise NetworkError(f'{dev_err(self.__pcap_dev)}')
   if pcap.setfilter(self.__pcap_dev, ct.byref(self.__f_code)) < 0:
      raise NetworkError(f'{dev_err(self.__pcap_dev)}')
   if pcap.setnonblock(self.__pcap_dev, self.__nonblock, err_buff) == -1:
      self.__pcap_logger.warning(f'{dev_err(self.__pcap_dev)}')


comp_net_id()
+++++++++++++

The ``comp_net_id()`` function enables a comprehensive comparison of any IP address (v4/v6) against the device's Network
ID to definitively ascertain whether the given IP address belongs to the device.

.. code-block:: python
   :linenos:

   i_net_types: Dict[str, int] = {'INET': 32, 'INET6': 128}
        try:
            ip_int: int = int.from_bytes(
                socket.inet_pton(
                    getattr(socket, f'AF_{(ip_type := list(i_net_types.keys())[0] if "." in ip_addr else list(i_net_types.keys())[1])}'),
                    ip_addr),
                byteorder='big', signed=False)
            return any([family['net_id'] ==
                        (ip_int >> (i_net_types[ip_type] - family['cdir']))
                        for family in self.__addr_families
                        if family['cdir'] <= i_net_types[ip_type]])
        except OSError:
            raise NetworkError(f'The IP-Address "{ip_addr}" does not seem to be valid!')

Lines 5 and 6 effectively determine whether the provided address is IPv4 or IPv6 by checking for the presence of a dot
in the string. Depending on the address type, the socket module provides two corresponding values: AF_INET (2) for IPv4
and AF_INET6 (10) for IPv6. These values are crucial for converting the string representation of the IP address to its
appropriate binary form. The ``getaddr()`` function conveniently retrieves the required address type value.

Once the address type and the corresponding socket value are established, line 4 uses the ``socket.inet_pton()``
function to convert the provided IP address string into a byte array. This byte array can then be further converted
into an integer value. This integer value is then shifted rightwards by either 32 bits for IPv4 or 128 bits for IPv6,
subtracting the CDIR value of the device. This process effectively extracts the network portion of the IP address.
Finally, the integer value is compared against the device's network ID to determine if the provided IP address belongs
to the device's network.


Packet Capture
==============

To initiate network traffic capture, the ``capture()`` function is invoked. It necessitates the specification of a network
device's name and, optionally, accepts a BPF filter represented as a list of strings.

.. code-block:: python
   :linenos:

   def capture(device_name: str, bpf_filter: List[str]):
      try:
         net_dev: NetworkDevice = [dev for dev in find_all_devs() if dev.name == device_name][0]
      if not net_dev.ready():
         raise NetworkError(f'Device "{device_name}" not ready for network capturing')
      else:
         net_dev.setup([''] if not bpf_filter else bpf_filter)
         capture_obj: Capture = Capture(_shared_mem)
         cap_proc: Process = Process(target=__capture, args=(Queue(-1), capture_obj, net_dev))
         cap_proc.start()
         return capture_obj

Upon confirming the device's existence on the system and its readiness for capture, the capture() function applies
the provided BPF filter and initiates the data capture process. Upon successful setup, it returns a `Capture-Object`_,
an intermediary data structure that provides access to the captured network traffic.

LibpCap Packet Handler
----------------------

.. code-block:: python
   :linenos:

   status = pcap.dispatch(net_dev.pcap_device, -1, __packet_handler, ct.cast(ct.pointer(packet_data), ct.POINTER(ct.c_ubyte)))

   @pcap.pcap_handler
   def __packet_handler(usr, header, packet):
      packet_data = ct.cast(usr, ct.POINTER(PacketData))
      packet_data.contents.ts = header.contents.ts.tv_sec
      packet_data.contents.cap_len = header.contents.caplen
      packet_data.contents.len = header.contents.len
      packet_data.contents.pkg = packet

Libpcap provides two functions to capture packets. The pcap_loop and the pcap_dispatch, both perform exactly
the same, except for the timeout. The dispatch function allows the handler to discard a packet if it cannot
be read, the loop function on the other hand does not time out.
The dispatch function expects the following arguments (There is no documentation for the python libpcap wrapper,
therefore the information are from the c-libpcap documentation/man-page).

.. list-table::
   :widths: 10 10 80
   :header-rows: 1

   * - type
     - parameter
     - description
   * - pcap_t*
     - p
     - A prior setup network device (In python it is just stored in a variable not pointer required)
   * - int
     - cnt
     - 0 capture till error or EOF occurs, -1 infinit loop
   * - pcap_handler
     - callback
     - A function with wrapper **@pcap.pcap_handler** (Will be compiled and cannot be a method)
   * - u_char*
     - user
     - A variable that will be passed to the handler (must be Pointer, in python too!)

The Callback-function in row 3 has three parameters, the arguments will be provided by libpcap.

#. user - The variable passed with the dispatch-function
#. header - The Ethernet header containing the amount of bytes captured and the actual length of the package
#. packet - The Ethernet frame

Capturing Process
-----------------

The capturing process initiates the parsing procedure and enters an infinite loop to continuously capture packets.

.. code-block:: python
   :linenos:

   parse_proc: Process = Process(target=__packet_parser, args=(q_in, c_obj, net_dev))
   parse_proc.start()

   while True:
      packet_data = PacketData()
      status = pcap.dispatch(net_dev.pcap_device, -1, __packet_handler, ct.cast(ct.pointer(packet_data), ct.POINTER(ct.c_ubyte)))
      if status < 0:
         break
      if status != 0:
         q_in.put({
             'hdr': {
                 'ts': packet_data.ts,
                 'cap_len': packet_data.cap_len,
                 'len': packet_data.len
             },
             'pkg': bytes(packet_data.pkg[:packet_data.cap_len])
         })
         del packet_data

Each loop a C-like-structure called ``PacketData()`` is created to retrieve data from lippcaps ``pcap_handler()``
callback function. The struct contains:

.. code-block:: python

   class PacketData(ct.Structure):
      _fields_ = [
        ('ts', ct.c_longlong),
        ('cap_len', ct.c_uint),
        ('len', ct.c_uint),
        ('pkg', ct.POINTER(ct.c_ubyte))
      ]

- ts: TimeStamp when the packet was captured
- cap_len: The amount of bytes captured
- len: The actual length of the packet (Exceeds the cap_len if not captured completely)
- pkg: The packet data as a pointer to the first byte of a byte-array

From line 10 to 16 the struct is deconstructed into a python dictionary an put into a queue for the `Packet-Parser`_

Packet-Parser
=============

The ``__packet_parser()`` Function has 3 Parameters a Queue, a `Capture-Object`_ and a `NetworkDevice Object`_.
The Queue is filled by the capturing process with packet information as described above. The Capture-Object is the
same Object being returned by ``capture()``. The NetworkDevice Object contains all the information about device
used to capture traffic on.

.. code-block:: python
   :linenos:

   def __packet_parser(q_in: Queue, c_obj: Capture, net_dev: NetworkDevice):
      parse_packet(packet, ex_data)

The parsing process mainly passes the data received in the Queue towards the ``parse_packet()`` function.

parse_packet()
--------------

The ``parse_packet()`` function at first parses the EtherType.

.. code-block:: python

   __parse_ethernet_frame(packet_data, ex_packet_data)

   # Inside __parse_ethernet_frame()
   dst_mac, src_mac, eth_type = struct.unpack_from('>6s6sH', data)

The first bytes from the captured data are formatted with the aid of the Python function struct.
This function necessitates the specification of a format string, which dictates the structure of the
data being processed. In this instance, the format string **>6s6sH** instructs the struct function to
interpret the data in a Little-Endian manner, searching for two individual 6-byte strings terminated by
a null byte (representing the destination and source MAC addresses) followed by an unsigned short
representing the Ethernet type (EtherType).

The socket module support 4 different EtherTypes, stored as constants inside ``_sockets`` module.

- ETHERTYPE_ARP = 2054
- ETHERTYPE_IP = 2048
- ETHERTYPE_IPV6 = 34525
- ETHERTYPE_VLAN = 33024

While there exist numerous EtherTypes, comprehensive information can be found on `Wikipedia`_. For the purposes of
this project, however, the focus will be on parsing packets of the following types: IPv4, IPv6, and ARP.

.. _Wikipedia: https://en.wikipedia.org/wiki/EtherType

Therefore the EtherType can be validated and further used to parse the different packets.

.. code-block:: python

   socket_eth_types: Dict[str, int] = {key: value for (key, value) in socket.__dict__.items() if 'ETHERTYPE' in key}

   # Inside parse_packet()
   eth_type_str = [key.rsplit('_')[-1].lower() for key, value in socket_eth_types.items() if
                        ex_packet_data[Packet.ETHERTYPE.value] == value][0]
   globals()[f'__parse_{eth_type_str}_packet'](packet_data[14:], ex_packet_data)

The code snippet above constructs a dictionary of the socket.ETHERTYPE constants, eliminating the need to repeatedly
retrieve these constants for each packet. This facilitates efficient packet processing. Afterwards, a helper string
is generated based on the retrieved EtherType. This string serves as a key to invoke the appropriate parsing function
for the specific packet type.

IPv4 Packet
+++++++++++

.. figure:: /media/ipv4_pkg.svg
   :alt: Image of ipv4 packet

.. code-block:: python

   v_ihl, tos, ttl_len, p_id, fg_fo, ttl, prot, check, src_ip, dst_ip = struct.unpack_from('>BBHHBBII', data)
   ip_header_len = ((v_ihl & 15) * 32) // 8

To extract the individual data fields from the captured byte array, the ``struct.unpack_from()`` method is employed once
more. The IPv4 packet encompasses several such fields, as depicted in the image above. However, the Options field,
being variable in length, necessitates the computation of the header length to determine the beginning of
the attached data. Accessing the data is mandatory because it contains the source and destination ports.

IPv6 Packet
+++++++++++

.. figure:: /media/ipv6_pkg.svg
   :alt: Image of ipv6 packet

.. code-block:: python

   vtfl, payload_len, nxt_head, hop_lmt, src_ip, dst_ip = struct.unpack_from('>IHBB16s16s', data)

Compared to IPv4, IPv6 packs an abundance of upgrades. It condenses the header information to a mere 64 bits, making
it a compact and efficient alternative. Additionally, IPv6 simplifies data retrieval by maintaining a fixed header
length of 40 bytes.

ARP Packet
++++++++++

The ARP Packet is not mandatory for this project, since it is used for internal mapping and the project tries to
measure network traffic and connections. For educational reasons however, it is implemented.

.. code-block:: python

   hw_type, prot_type, hw_addr_len, prot_addr_len, op = struct.unpack_from('>IIBBI', data[:9])

Packet Index
++++++++++++

To allow efficient data manipulation during subsequent processing stages, the following Enum provides a readily
accessible static indexing scheme for each information type. The ``d_type()`` property function seamlessly converts an
index to the corresponding Pandas.Dataframe DataType, enabling seamless data handling. Each information retrieved
by the above parsing functions is stored in a list-reference using these indexes.

.. code-block:: python

   class Packet(Enum):
      TIMESTAMP = 0
      ETHERTYPE = 1
      DIRECTION = 2
      SOURCE_MAC = 3
      DESTINATION_MAC = 4
      SOURCE_IP = 5
      SOURCE_PORT = 6
      DESTINATION_IP = 7
      DESTINATION_PORT = 8
      PROT_TYPE = 9
      OPERATION = 10
      SIZE = 11

      @property
      def d_type(self):
        return pd.StringDtype() if self.value in [0, 2, 3, 4, 5, 7, 9] else 'Int64'

Once the packet is parsed, the timestamp and size of packet are added to the resulting list (``ex_data``)
Using the NetworkDevice function ``comp_net_id`` to determine, whether the source or destination IP-address of the packet
belongs to the network device, the direction (Up or Download) is determined.

Due to the ``parse_packet()`` function returning an empty list upon encountering an error, further processing is deemed
unnecessary [Line 4].
After successfully parsing the packet, the timestamp and size of the packet are added to the resulting list (``ex_data``).
To determine the direction of the packet (Up or Download), the NetworkDevice function `comp_net_id()`_ is employed to
assess whether the source or destination IP address of the packet belongs to the network device.

.. code-block:: python
   :linenos:

   def __packet_parser(q_in: Queue, c_obj: Capture, net_dev: NetworkDevice):
      # ...

      if not all(entry is None for entry in ex_data):
         ex_data[Packet.TIMESTAMP.value] = datetime.fromtimestamp(header['ts'])
         ex_data[Packet.SIZE.value] = header['len']
         direction: int = [net_dev.comp_net_id(ip) for ip in [ex_data[Packet.SOURCE_IP.value], ex_data[Packet.DESTINATION_IP.value]]].index(True)
         ex_data[Packet.DIRECTION.value] = 'UP' if direction == 0 else 'Down' if direction == 1 else ''


Interprocess communication
--------------------------

Multiple approaches can be employed to establish inter-process communication (IPC) in Python. However, allocating a
random byte in memory using ``mmap`` and writing predefined Flag values into it proves to be the most efficient method
for exchanging small amounts of data. Consequently, the following Enum is utilized to represent these Flag values.

.. code-block:: python

   class SharedFlags(Enum):
    FLAG_GET = 1
    FLAG_PUT = 2
    FLAG_NONE = 0
    FLAG_ERROR = 3

To ensure that writing and reading operations are always performed on the same designated byte, the code snippet
employs the Singleton design pattern. The ``__new__()`` method is invoked whenever the class is instantiated, and since
the ``_instance`` variable is initialized only on the first iteration, the same instance is returned consistently.
Additionally, mmap's ``write_byte()/read_byte()`` operations modify the memory address, necessitating their reset before
subsequent reading or writing activities on the same byte.

.. code-block:: python

   class LibpcapShare:
      _instance = None

   def __new__(cls):
      if cls._instance is None:
         cls._instance = super(LibpcapShare, cls).__new__(cls)
         cls._instance.__sh_mem = mmap.mmap(-1, 1)
      return cls._instance

    def write(self, flag: SharedFlags) -> None:
        self.__sh_mem.seek(0)
        self.__sh_mem.write_byte(flag.value)

    def read(self) -> int:
        self.__sh_mem.seek(0)
        return self.__sh_mem.read_byte()

    def close(self) -> None:
        None if self.__sh_mem.closed else self.__sh_mem.close()

By utilizing shared memory, it becomes remarkably straightforward to communicate with any running process that
has access to this designated byte. This mechanism extends beyond the ``py_pcap`` module and is also employed whenever
the `Capture-Object`_\ s method ``get()`` is invoked. The function caller is spared the need to directly access or modify
internal data to retrieve network traffic.

Capture-Object
--------------

The Capture-Object is returned ``pcap.capture()`` (`Packet Capture`_). The caller then can use its get() and error()
methods to either retrieve collected network data or to check if an error occurred and process was terminated.

The Capture-Object instance is returned by the ``pcap.capture()`` function (`Packet Capture`_). The caller can then utilize
its ``get()`` and ``error()`` methods to either obtain the captured network data or verify if an error has occurred, causing the
process to terminate prematurely.

.. code-block:: python

   class Capture:

      def get(self):
         if not self.error():
            self.__shared_mem.write(SharedFlags.FLAG_GET)
            while self.__shared_mem.read() != SharedFlags.FLAG_PUT.value:
               pass
         self.__shared_mem.write(SharedFlags.FLAG_NONE)
         return self.__queue.get()

      def put(self, data):
         self.__queue.put(data)

      def error(self):
         if self.__shared_mem.read() == SharedFlags.FLAG_ERROR:
            return True


.. code-block:: python

   # Parsing Process (infinite loop)
   if _shared_mem.read() == SharedFlags.FLAG_GET.value:
      c_obj.put(pd.DataFrame({col.name.capitalize(): pd.Series(data=packet_lst[index], dtype=col.d_type) for index, col in enumerate(Packet)}))

      _shared_mem.write(SharedFlags.FLAG_PUT)
      packet_lst = [[] for _ in range(len(Packet.__members__))]

The Capture-Object's get() function internally writes a GET-flag into the shared memory, which is then detected and
acted upon by the Parsing-Process. The Parsing-Process reassembles the collected packet data into a pandas.DataFrame,
placing it into a queue. The get() function then empties the queue, retrieving the compiled DataFrame and returning
it to the caller.


Architecture and Usage
======================

.. figure:: /media/network_arch.svg
   :alt: Image Network-Sniffer architecture

Using the py_pcap module is remarkably straightforward. To initiate the capture process, create a Capture-Object
instance using the ``pcap.capture()`` function, specifying the network device's name and an optional BPF filter. If any
critical error occurs during the device setup, the ``pcap.capture()`` function will raise an ``pcap._utils.NetworkError``
exception. However, once a successful Capture instance is obtained, network traffic can be continuously retrieved
using the instance's ``get()`` method. To ensure the process hasn't encountered an irresolvable issue and prematurely
terminated, it's advisable to check the ``error()`` method before accessing ``get()`` to handle any error messages.


.. code-block:: python
   :linenos:

   import py_pcap as pcap
   import pandas as pd
   import time

   pd.set_option('display.max_columns', 500)
   pd.set_option('display.width', 2000)

   if __name__ == '__main__':
      try:
         a_obj: pcap.Capture = pcap.capture('ogstun', [])
         while True:
            time.sleep(5)
            if a_obj.error():
               # handle error
               print(a_obj.get())
            else:
               # proceed with data
               print(a_obj.get())
      except pcap._utils.NetworkError as ne:
         # Handle device setup errors
         print(ne)

The code snippet above demonstrates the ability to retrieve captured network traffic data at any given point in time by
delaying the process for five seconds in line 12.
