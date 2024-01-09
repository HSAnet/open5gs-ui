import socket
import struct
import ipaddress

from socket import ETHERTYPE_IP

from .._utils import Packet

import numpy as np
from typing import Callable, Dict, List, Union

# string format for mac address
bytes_to_mac: Callable[[bytes], str] = lambda b: ':'.join(map('{:02x}'.format, b))
# parse bytes to ipv4/6 address
bytes_to_ip: Callable[[bytes], str] = lambda b: str(ipaddress.ip_address(b))
# parse two 16bit Integers to python Ints
parse_ports: Callable[[bytes], tuple] = lambda b: struct.unpack_from(bld_str_fmt([16, 16]), b)
# Store supported EtherTypes (from socket module) in dict
socket_eth_types: Dict[str, int] = {key: value for (key, value) in socket.__dict__.items() if 'ETHERTYPE' in key}

# Bits to struct.string_format dict
string_format: Dict[int, str] = {
    1: '{}s',
    8: 'B',
    16: 'H',
    32: 'I',
    64: 'Q'
}


def bld_str_fmt(bit_list: List[int]) -> str:
    """
    Function parses list of bit representation into struct.string_format (little endian)

    :param bit_list: List of bit values
    :return: struct.string_format (little endian)
    """
    return '>' + ''.join([string_format[1].format(bits // 8) if bits not in string_format.keys() else string_format[bits] for bits in bit_list])


def __parse_ethernet_frame(data: bytes, ref: np.array) -> None:
    """
    Function parses provided data into ethernet frame (src- a. dst MAC + Ethertype)

    EtherType:
        - IPv4: 0x0800 -> 2048
        - IPv6: 0x86DD -> 34525
        - ARP:  0x0806 -> 2054
        - VLAN: 0x8100 -> 33024

    :param data: bytes-data to be parsed
    :return: dst-MAC (str), src-MAC (str), EtherType (int)
    """
    dst_mac, src_mac, eth_type = struct.unpack_from('>6s6sH', data)
    ref[Packet.ETHERTYPE.value] = eth_type
    ref[Packet.SOURCE_MAC.value] = bytes_to_mac(src_mac)
    ref[Packet.DESTINATION_MAC.value] = bytes_to_mac(dst_mac)


def __parse_ip_packet(data: bytes, ref: np.array) -> None:
    """
    Function parses provided data into IPv4 packet

    IPv4-Packet-Architecture:
        Version-4, InternetHeaderLength-4, TOS-8, TotalLength-16,
        Identifier-16, Flags-3, FragmentOffset-13, TTL-8, Protocol-8,
        Checksum-16, Source-IPAddress-32, Dest-IPAddress-32, Options-?

    :param data: bytes data to be parsed
    :return: Tuple(Source_IP, Source_Port, Dest_IP, Dest_Port, Protocol(str))
    """
    v_ihl, tos, ttl_len, p_id, fg_fo, ttl, prot, check, src_ip, dst_ip = struct.unpack_from(
        bld_str_fmt([8, 8, 16, 16, 16, 8, 8, 16, 32, 32]), data)
    # The header-length is a 4-bit value at second position in the header.
    # The & operation retrieves that value. It represents the amount of words (32-bits) the header uses.
    # 15 is dec for 0xf but doesn't need to be converted
    ip_header_len = ((v_ihl & 15) * 32) // 8
    src_port, dst_port = parse_ports(data[ip_header_len:])
    ref[Packet.SOURCE_IP.value] = bytes_to_ip(src_ip)
    ref[Packet.SOURCE_PORT.value] = src_port
    ref[Packet.DESTINATION_IP.value] = bytes_to_ip(dst_ip)
    ref[Packet.DESTINATION_PORT.value] = dst_port


def __parse_ipv6_packet(data: bytes, ref: np.array) -> None:
    """
    Function parses provided data into Ipv6 packet format

    IPv6-Packet-Architecture:
        Version-4, Traffic-Class-8, Flow-Label-20, Payload-Length-16,
        Next-Header-8, Hop-Limit-8, Source-Address-128, Dest-Address-128

    :param data: bytes data to be parsed
    :return: Tuple(Source_IP, Source_Port, Dest_IP, Dest_Port)
    """
    vtfl, payload_len, nxt_head, hop_lmt, src_ip, dst_ip = struct.unpack_from(bld_str_fmt([32, 16, 8, 8, 128, 128]), data)
    src_port, dst_port = parse_ports(data[40:])
    ref[Packet.SOURCE_IP.value] = bytes_to_ip(src_ip)
    ref[Packet.SOURCE_PORT.value] = src_port
    ref[Packet.DESTINATION_IP.value] = bytes_to_ip(dst_ip)
    ref[Packet.DESTINATION_PORT.value] = dst_port


def __parse_arp_packet(data: bytes, ref: np.array) -> None:
    """
    Function parses ARP-Packet

    Protocol-type:
        - 2048  (IPv4)
        -       (IPv6)
        -       (IPX)
        -       (SPX)
    Operation:
        - 1     (Request)
        - 2     (Reply)

    :param data: packet data in bytes
    :return: Tuple(Protocol-type, Operation, sender-IP-Address, receiver_IP-Address)
    """
    hw_type, prot_type, hw_addr_len, prot_addr_len, op = struct.unpack_from(bld_str_fmt([16, 16, 8, 8, 16]), data[:9])
    packet_bits: List[int] = [hw_addr_len * 8, prot_addr_len * 8, hw_addr_len * 8, prot_addr_len * 8]
    send_mac, send_ip, rec_mac, rec_ip = struct.unpack_from(bld_str_fmt(packet_bits), data[8:])
    ref[Packet.PROT_TYPE.value] = prot_type
    ref[Packet.OPERATION.value] = op
    ref[Packet.SOURCE_IP.value] = bytes_to_ip(send_ip)
    ref[Packet.DESTINATION_IP.value] = bytes_to_ip(rec_ip)


def __parse_vlan_packet(data: bytes, ref: np.array) -> None:
    pass


def parse_packet(packet_data: bytes, ex_packet_data: List[Union[str, int, None]]) -> None:
    """
    Function parses bytes to python data and stores it in provided list.

    :param packet_data: The bytes to be parsed
    :param ex_packet_data: reference to list
    """
    try:
        __parse_ethernet_frame(packet_data, ex_packet_data)
        eth_type_str = [key.rsplit('_')[-1].lower() for key, value in socket_eth_types.items() if
                        ex_packet_data[Packet.ETHERTYPE.value] == value][0]
        globals()[f'__parse_{eth_type_str}_packet'](packet_data[14:], ex_packet_data)
    except (struct.error, IndexError):
        # IndexError occurs when EtherType not supported
        # If a captured packet is too short to parse, Struct.error will be risen
        # -> No concern - Proceed and continue with next packet!
        return None
