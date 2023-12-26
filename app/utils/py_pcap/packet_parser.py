import socket
import struct
import ipaddress
from exceptions import CaptureError

import numpy as np
from typing import Callable, Dict, List, Union


bytes_to_mac: Callable[[bytes], str] = lambda b: ':'.join(map('{:02x}'.format, b))
bytes_to_ip: Callable[[bytes], str] = lambda b: str(ipaddress.ip_address(b))
parse_ports: Callable[[bytes], tuple] = lambda b: struct.unpack_from(bld_str_fmt([16, 16]), b)


socket_eth_types: Dict[str, int] = {key: value for (key, value) in socket.__dict__.items() if 'ETHERTYPE' in key}


PKG_COLUMNS: List[str] = ['TimeStamp', 'EtherType', 'Direction', 'SrcMac', 'DstMac', 'SrcAddress', 'SrcPort', 'DstAddress', 'DstPort', 'ProtType', 'Operation', 'Size']


string_format: Dict[int, str] = {
    1: '{}s',
    8: 'B',
    16: 'H',
    32: 'I',
    64: 'Q'
}


protocol_numbers = {
    0: "Reserved",
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IP-in-IP",
    5: "IPSec AH",
    6: "IPSec ESP",
    7: "IPCP",
    8: "OSPF",
    9: "BGP",
    10: "PING",
    11: "Traceroute",
    12: "DCCP",
    13: "Mobile IP",
    17: "UDP",
    20: "FTP-C",
    21: "FTP-D",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    69: "TFTP",
    123: "NTP",
    443: "HTTPS"
}


def bld_str_fmt(bit_list: List[int]) -> str:
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
    ref[PKG_COLUMNS.index('EtherType')] = eth_type
    ref[PKG_COLUMNS.index('SrcMac')] = bytes_to_mac(src_mac)
    ref[PKG_COLUMNS.index('DstMac')] = bytes_to_mac(dst_mac)


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
    ref[PKG_COLUMNS.index('SrcAddress')] = bytes_to_ip(src_ip)
    ref[PKG_COLUMNS.index('SrcPort')] = src_port
    ref[PKG_COLUMNS.index('DstAddress')] = bytes_to_ip(dst_ip)
    ref[PKG_COLUMNS.index('DstPort')] = dst_port


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
    ref[PKG_COLUMNS.index('SrcAddress')] = bytes_to_ip(src_ip)
    ref[PKG_COLUMNS.index('SrcPort')] = src_port
    ref[PKG_COLUMNS.index('DstAddress')] = bytes_to_ip(dst_ip)
    ref[PKG_COLUMNS.index('DstPort')] = dst_port


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
    ref[PKG_COLUMNS.index('ProtType')] = prot_type
    ref[PKG_COLUMNS.index('Operation')] = op
    ref[PKG_COLUMNS.index('SrcAddress')] = bytes_to_ip(send_ip)
    ref[PKG_COLUMNS.index('DstAddress')] = bytes_to_ip(rec_ip)


def __parse_vlan_packet(data: bytes, ref: np.array) -> None:
    pass


def parse_packet(packet_data: bytes) -> np.array:
    try:
        ret_value: List[Union[int, str, None]] = [None for _ in range(12)]
        __parse_ethernet_frame(packet_data, ret_value)
        eth_type_str = [key.rsplit('_')[-1].lower() for key, value in socket_eth_types.items() if ret_value[1] == value][0]
        globals()[f'__parse_{eth_type_str}_packet'](packet_data[14:], ret_value)
        return ret_value
    except struct.error:
        # Error while parsing - ignore packet - continue
        return None
    except IndexError:
        raise CaptureError(f'Ethernet-Type - {ret_value[1]} - not supported')



