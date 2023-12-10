Ethernet frame and IP-Packets
*****************************

The application listens for packets on a predefined network adapter. The default device
for Open5gs is **ogstun**. The following illustrations are fundamental to comprehending how
to deconstruct a captured packet.

Internet Frame/Packet architecture
==================================

.. figure:: /media/inet_pkg.svg
   :alt: Image of Internet packet architecture

   Image 1: Showing a simplified version of an internet packet architecture.

The image shows the different parts of a captured package. In the first step, it is necessary to
access the **EtherType** field. This field indicates the protocol type of the payload, which is the
data contained within the frame. The EtherType value is a two-octet field, and it is used by the
network layer for packet demultiplexing. The EtherType for IPv4 is **0x0800**, which indicates that
the payload contains an IPv4 packet. The EtherType for IPv6 is **0x86DD**, which signifies that the
payload is an IPv6 packet. There are several other types of EtherType values, but they are not
important for this project. More about EtherType on `Wikipedia`_.

.. _Wikipedia: https://en.wikipedia.org/wiki/EtherType

.. code-block:: python
   :linenos:

   pcap.dispatch(pd, -1, handle_pkg, None)

   @pcap.pcap_handler
   def handle_pkg(usr, header, packet):
      header.contents.caplen >= 14:

Libpcap provides two functions to capture packets. The pcap_loop and the pcap_dispatch, both perform exactly
the same, except for the timeout. The dispatch function allows the handler to discard a packet if it cannot
be read, the loop function on the other hand does not time out. The dispatch function expects the following
arguments (There is no documentation for the python libpcap wrapper therefore I will refer to the c-libpcap).
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

The Callback-function in row 4 has three parameters, the arguments will be provided by libpcap.

#. user - The variable passed with the dispatch-function
#. header - The Ethernet header containing the amount of bytes captured and the actual length of the package
#. packet - The Ethernet frame

Ethernet Frame
==============

.. figure:: /media/ether_two_frame.svg
   :alt: Image of Ethernet frame

.. code-block:: python

   dest_mac, src_mac, eth_type = struct.unpack_from('!6s6sH', bytes(package[:14]))

Upon capturing a packet, the first 14 bytes are formatted with the aid of the Python function struct.
This function necessitates the specification of a format string, which dictates the structure of the
data being processed. In this instance, the format string **!6s6sH** instructs the struct function to
interpret the data in a Big-Endian manner, searching for two individual 6-byte strings terminated by
a null byte (representing the destination and source MAC addresses) followed by an unsigned short
representing the Ethernet type (EtherType).

IP Packet
=========

IPv4
----

.. figure:: /media/ipv4_pkg.svg
   :alt: Image of ipv4 packet

The IPv4 Packet comprises 96 bits of information at the outset. However, the application solely
requires the source and destination IP addresses. While there is no single format character that
directly represents 96 bits, the combination of 'Q' (64 bits) and 'L' (32 bits) effectively
conveys this length. The addresses themselves can be unpacked with the 'I' (32 bits) character.
Once the addresses are extracted, the ipaddress module is used to transform the byte sequences
into human-readable IPv4 forms, such as *192.168.1.1*.

.. code-block:: python
   :linenos:

   _, _, src_address, dst_address = struct.unpack_from('>QLII',
                                                       bytes(package[14:header.contents.caplen])
   ipaddress.ip_address(src_address)
   ipaddress.ip_address(dst_address)

IPv6
----

.. figure:: /media/ipv6_pkg.svg
   :alt: Image of ipv6 packet

The IPv6 Packet resembles the IPv4 structure, but it only contains 64 bits of information at the beginning.
This information can be extracted using the 'Q' format character. The IP addresses are stored as 16-character
byte arrays terminated by a null byte. This format can be unpacked using the combination of '16' and 's'.
The extracted byte arrays can again be converted into human-readable IPv6 forms like *fe80::f253:ed9b:15a1:f914*
with the assistance of the Python module ipaddress.

.. code-block:: python
   :linenos:

   _, src_address, dst_address = struct.unpack_from('>Q16s16s',
                                                    bytes(package[14:header.contents.caplen])
   ipaddress.ip_address(src_address)
   ipaddress.ip_address(dst_address)

.. list-table:: Format characters struct.unpack_from()
   :widths: 10 90
   :header-rows: 1

   * - Format character
     - Description
   * - d
     - signed char (8 bits)
   * - i
     - unsigned char (8 bits)
   * - h
     - signed short (16 bits)
   * - H
     - unsigned short (16 bits)
   * - I
     - signed int (32 bits)
   * - L
     - unsigned int (32 bits)
   * - q
     - signed long long (64 bits)
   * - Q
     - unsigned long long (64 bits)
   * - f
     - single precision (32-bit) floating-point number
   * - d
     - double precision (64-bit) floating-point number
   * - s
     - string of characters terminated by a null byte (ASCII)
   * - p
     - pointer to a structure
   * - b
     - singed byte (8 bits)
   * - B
     - unsigned byte (8bits)
   * - !
     - Big Endian
   * - >
     - Little Endian