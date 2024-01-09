Appendix
********

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