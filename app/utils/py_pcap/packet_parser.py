import ipaddress
import struct
from configparser import ParsingError
from typing import Callable, Tuple, Dict, List
import numpy as np
import socket

bytes_to_mac: Callable[[bytes], str] = lambda b: ':'.join(map('{:02x}'.format, b))
bytes_to_ip: Callable[[bytes], str] = lambda b: str(ipaddress.ip_address(b))


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


def __parse_ethernet_frame(data: bytes) -> Tuple[str, str, int]:
    """
    Function parses provided data into ethernet frame (src- a. dst MAC + Ethertype)
    EtherType:
        - IPv4: 0x0800 -> 2048
        - IPv6: 0x86DD -> 34525
        - ARP:  0x0806 -> 2054
        - VLAN: 0x8100 -> 33024

    :raises ParsingError: If provided data does not match min. required length
    :param data: bytes-data to be parsed
    :return: dst-MAC (str), src-MAC (str), EtherType (int)
    """
    if len(data) < 14:
        raise ParsingError("Provided data too short for ethernet frame!")

    dst_mac, src_mac, eth_type = struct.unpack_from('>6s6sH', data)
    return bytes_to_mac(dst_mac), bytes_to_mac(src_mac), eth_type


def __parse_ip_packet(data: bytes) -> tuple:
    """
    Function parses provided data into IPv4 packet

    IPv4-Packet-Architecture:
        Version-4, InternetHeaderLength-4, TOS-8, TotalLength-16,
        Identifier-16, Flags-3, FragmentOffset-13, TTL-8, Protocol-8,
        Checksum-16, Source-IPAddress-32, Dest-IPAddress-32, Options-?

    :param data: bytes data to be parsed
    :return: Tuple(Source_IP, Source_Port, Dest_IP, Dest_Port, Protocol(str))
    """
    try:
        v_ihl, tos, ttl_len, p_id, fg_fo, ttl, prot, check, src_ip, dst_ip = struct.unpack_from(
            bld_str_fmt([8, 8, 16, 16, 16, 8, 8, 16, 32, 32]), data)
        print(data)
        # The header-length is a 4-bit value at second position in the header.
        # The & operation retrieves that value. It represents the amount of words (32-bits) the header uses.
        # 15 is dec for 0xf but doesn't need to be converted
        ip_header_len = ((v_ihl & 15) * 32) // 8
        src_port, dst_port = struct.unpack_from(bld_str_fmt([16, 16]), data[ip_header_len:])
        return src_ip, src_port, dst_ip, dst_port, protocol_numbers.get(prot, '')
    except struct.error:
        raise ParsingError("Provided data too short for IPv4 packet!")


def __parse_ipv6_packet(data: bytes) -> tuple:
    #print('inside_IP6')
    pass


def __parse_arp_packet(data: bytes) -> Tuple[int, int, str, str]:
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
    if len(data) < 8:
        raise ParsingError('Provided data too short for ARP packet')
    hw_type, prot_type, hw_addr_len, prot_addr_len, op = struct.unpack_from(bld_str_fmt([16, 16, 8, 8, 16]), data[:9])
    packet_bits: List[int] = [hw_addr_len * 8, prot_addr_len * 8, hw_addr_len * 8, prot_addr_len * 8]
    send_mac, send_ip, rec_mac, rec_ip = struct.unpack_from(bld_str_fmt(packet_bits), data[8:])
    return prot_type, op, bytes_to_ip(send_ip), bytes_to_ip(rec_ip)


def __parse_vlan_packet(data: bytes) -> tuple:
    print('inside_VLAN')
    pass


def parse_packet(packet_data: bytes) -> np.array:
    try:
        dst_mac, src_mac, eth_type = __parse_ethernet_frame(packet_data)
        parsed_packet = globals()[f'__parse_{[var.rsplit('_')[-1].lower() for var in dir(socket) if 'ETHERTYPE' in var and eth_type == getattr(socket, var)][0]}_packet'](packet_data[14:])
    except ParsingError:
        print('Error parsing ethernet frame')
    except IndexError:
        print('EtherType not found!')


if __name__ == '__main__':
    struct.unpack_from('>HHHHHHH', b'E\x00\x00')
    # ether_type: int = 2048
    # fun = [var.rsplit('_')[-1].lower() for var in dir(socket) if 'ETHERTYPE' in var and ether_type == getattr(socket, var)][0]
    # locals()[f'__parse_{fun}_packet'](b'xy')