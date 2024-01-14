Appendix
********

Appendix:




Test Setup
==========

Open5gs
-------


System setup
++++++++++++

.. literalinclude:: ../_static/open5gs_system_setup.sh
   :language: sh
   :caption: initial system setup for Open5Gs

.. only:: builder_html or readthedocs

   :download:`Download Script above <../_static/open5gs_system_setup.sh>`.

Configuration
+++++++++++++

To configure Open5GS, you'll need to edit the amf.yaml and upf.yaml files located in the ``/etc/open5gs/`` directory.
These files are quite lengthy; therefore, either download the pre-configured files or using the
provided wget command in the script above to fetch them :download:`amf.yaml <../_static/amf.yaml>`
:download:`upf.yaml <../_static/upf.yaml>`.


Install and start
+++++++++++++++++

.. literalinclude:: ../_static/open5gs_python_setup.sh
   :language: sh
   :caption: Downloading the client-application and starting it

.. only:: builder_html or readthedocs

   :download:`Download Script above <../_static/open5gs_python_setup.sh>`.

Ueransim
--------

.. literalinclude:: ../_static/ueransim_system_setup.sh
   :language: sh
   :caption: initial system setup for UERANSIM

.. only:: builder_html or readthedocs

   :download:`Download Script above <../_static/ueransim_system_setup.sh>`.

.. only:: builder_html or readthedocs

To configure UERANSIM, the :download:`GNodeB-config <../_static/gnb1.yaml>` and the
:download:`UserEquipment-config <../_static/ue1.yaml>` ought to be added to ``~/UERANSIM/config``.


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


Config
======

Due to the extensive number of settings required for this project, such as server addresses and ports, network
device names, and other parameters, a purely argument-driven approach is not feasible. Therefore, a configuration
system was implemented to manage these settings in a structured and organized manner.

The configuration file ``settings.conf`` adheres to the `MS-DOS`_ style, supports comments, and is structured as follows:

.. _MS-DOS: https://en.wikipedia.org/wiki/Configuration_file#:~:text=its%20system%20settings.-,MS%2DDOS,-%5Bedit%5D

.. literalinclude:: ../_static/settings.conf
   :language: python
   :caption: setting.conf / configuration file
   :linenos:
   :emphasize-lines: 11, 12

On initialization the ``Config-Object`` parses the ``settings.conf`` using the following pattern.

.. code-block:: python

   _line_pattern = re.compile(r'^(?P<key>\w+)'     # The line starts with a word (cannot be empty)
                                r'\s=\s'           # Followed by an equal sign surrounded by two whitespace chars
                                r'(?P<value>\S*)', # Followed by anything except whitespace (group could be empty)
                                re.M | re.VERBOSE)

The configuration example in line 12 deviates from the expected pattern due to the missing whitespace after the
equal sign. This error will be logged. However, the absence of the BPF_Filter in line 11 is interpreted as an
empty string, effectively disabling filtering.

Each setting will be attached to the Config-Instance and can be access like an attribute. However if a config-key
like in line 12 in the example above does not match the pattern it will raise an AttributeError.

Each configuration setting will be associated with the Config instance and can be accessed directly as an attribute.
However, if a configuration key, such as the one in line 12 of the example provided, does not conform to the expected
pattern, an AttributeError will be raised.



.. code-block:: python
   :caption: Accessing configuration attributes

   conf: Config = Config(Path('./settings.conf'))
   print(dir(conf))
   # Either access values like this
   print('BPF_Filter not found!' if not conf.has('bpf_filter') else conf.bpf_filter)
   # - or - like this
   try:
      print(conf.bpf_filter)
   except AttributeError:
      print('BPF_Filter not found!')





String Format
=============

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

Alternative String Format Creation
----------------------------------

For parsing packet data I used a simplified approach using a dictionary storing the most important Symbols.

.. code-block:: python
   :linenos:

   string_format: Dict[int, str] = {
      1: '{}s',
      8: 'B',
      16: 'H',
      32: 'I',
      64: 'Q'
   }

   def bld_str_fmt(bit_list: List[int]) -> str:
      return '>' + ''.join([string_format[1].format(bits // 8) if bits not in string_format.keys() else string_format[bits] for bits in bit_list])

   bld_str_fmt([8, 8, 16, 16, 16, 8, 8, 16, 32, 32])

The ``bld_str_fmt()`` function effectively clarifies the extraction of specific bit groups into contiguous segments
using ``struct.unpack_from()``. The build function consistently employs little-endian byte order, which is appropriate
since all conversions are performed in this format. It identifies integers from the provided list and replaces them
with corresponding values from the pre-defined dictionary. If the key is not found, the integer is divided by
8 (truncated integer division) and suffixed with "s". For instance, while parsing an IPv6 address, which occupies
128 bits, dividing 128 by 8 yields 16, resulting in the format "16s".