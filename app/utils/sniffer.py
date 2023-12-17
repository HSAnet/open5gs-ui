import binascii
import sys
from typing import List, Dict

import socket
import datetime
import ctypes as ct
import libpcap as pcap
from dataclasses import dataclass
from libpcap._platform import sockaddr_in, sockaddr_in6
from libpcap._dlt import DLT_EN10MB
import struct
import ipaddress

ETHERNET_IPV6: int = 34525
ETHERNET_IPV4: int = 2048

ebuf2str   = lambda ebuf: ebuf.value.decode("utf-8", "ignore")

@dataclass
class NetDevice:
    name: str
    flags: List[str]
    addr_families: List[Dict[str, str]]

    def status(self) -> bool:
        return 'UP' in self.flags and 'RUNNING' in self.flags

    def __str__(self) -> str:
        return (f"{self.name}\n"
                f"{'Flags':>4}: {' '.join(self.flags)}\n"
                f"{''.join([f"\tAddress Family: {'unknown' if 'type' not in fam else fam['type']}\n"
                            f"\t\tAddress: {'' if 'addr' not in fam else fam['addr']}\n"
                            f"\t\tNetmask: {'' if 'mask' not in fam else fam['mask']}\n" 
                            for fam in self.addr_families])}")


class NetSnifferPackage:

    def __exit__(self):
        pcap.freecode(ct.byref(self.__f_code))
        pcap.close(self.__pd)
    def __enter__(self):
        class NetSniffer:
            def __init__(self):
                self.__net_devices: List[NetDevice] = self._get_net_devs()
                self.__pd = None
                self.__f_code = None

            def _get_net_devs(self) -> List[NetDevice]:
                err_buf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
                device_array = ct.POINTER(pcap.pcap_if_t)()
                device_list: List[NetDevice] = []
                if pcap.findalldevs(ct.byref(device_array), err_buf) == 0:
                    it = device_array
                    while it:
                        it = it.contents
                        device_list.append(NetDevice(name=it.name.decode('utf-8'),
                                                     flags=self.__get_device_flags(it),
                                                     addr_families=self.__get_addr_family(it)))
                        it = it.next
                    pcap.freealldevs(device_array)
                else:
                    # Todo: Raise error with ebuf.value.decode('utf-8', 'ignore') as string
                    pass
                return device_list

            def __get_device_flags(self, device) -> List[str]:
                flags: List[str] = []
                if device.flags & pcap.PCAP_IF_UP:
                    flags.append("UP")
                if device.flags & pcap.PCAP_IF_RUNNING:
                    flags.append("RUNNING")
                if device.flags & pcap.PCAP_IF_LOOPBACK:
                    flags.append("LOOPBACK")
                if device.flags & pcap.PCAP_IF_WIRELESS:
                    flags.append("WIRELESS")
                conn_status = device.flags & pcap.PCAP_IF_CONNECTION_STATUS
                if device.flags & pcap.PCAP_IF_WIRELESS:
                    if conn_status == pcap.PCAP_IF_CONNECTION_STATUS_UNKNOWN:
                        flags.append(" (association status unknown)")
                    elif conn_status == pcap.PCAP_IF_CONNECTION_STATUS_CONNECTED:
                        flags.append(" (associated)")
                    elif conn_status == pcap.PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
                        flags.append(" (not associated)")
                    elif conn_status == pcap.PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
                        pass
                else:
                    if conn_status == pcap.PCAP_IF_CONNECTION_STATUS_UNKNOWN:
                        flags.append(" (connection status unknown)")
                    elif conn_status == pcap.PCAP_IF_CONNECTION_STATUS_CONNECTED:
                        flags.append(" (connected)")
                    elif conn_status == pcap.PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
                        flags.append(" (disconnected)")
                    elif conn_status == pcap.PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
                        pass
                return flags

            def __get_addr_family(self, device) -> List[Dict[str, str]]:
                addr_families = []
                addr_family = device.addresses
                while addr_family:
                    addr_family = addr_family.contents

                    addr = addr_family.addr
                    netmask = addr_family.netmask
                    broad_addr = addr_family.broadaddr
                    dst_addr = addr_family.dstaddr
                    if addr:
                        family: Dict[str] = dict()
                        if addr.contents.sa_family == socket.AF_INET:
                            family['type'] = 'IPv4'
                            if addr:
                                family['addr'] = socket.inet_ntop(socket.AF_INET, ct.cast(addr, ct.POINTER(sockaddr_in)).contents.sin_addr)
                            if netmask:
                                family['mask'] = socket.inet_ntop(socket.AF_INET, ct.cast(netmask, ct.POINTER(sockaddr_in)).contents.sin_addr)
                            if broad_addr:
                                family['broad_addr'] = socket.inet_ntop(socket.AF_INET, ct.cast(broad_addr, ct.POINTER(sockaddr_in)).contents.sin_addr)
                            if dst_addr:
                                family['dst_addr'] = socket.inet_ntop(socket.AF_INET, ct.cast(dst_addr, ct.POINTER(sockaddr_in)).contents.sin_addr)
                            addr_families.append(family)
                        elif addr.contents.sa_family == socket.AF_INET6:
                            family['type'] = 'IPv6'
                            if addr:
                                family['addr'] = socket.inet_ntop(socket.AF_INET6, ct.cast(addr, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)
                            if netmask:
                                family['mask'] = socket.inet_ntop(socket.AF_INET6, ct.cast(netmask, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)
                            if broad_addr:
                                family['broad_addr'] = socket.inet_ntop(socket.AF_INET6, ct.cast(broad_addr, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)
                            if dst_addr:
                                family['dst_addr'] = socket.inet_ntop(socket.AF_INET6, ct.cast(dst_addr, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)
                            addr_families.append(family)
                    addr_family = addr_family.next
                return addr_families

            def __open_dev(self, device_name: str):
                """
                :param device: Adapter name
                :param snap_len:  maximum size of packets to capture in bytes
                :param pr_misc: set card in promiscuous mode
                :param to_ms: time to wait for packets in milliseconds before read times out
                :param err_buf: Error string will be placed here
                :return:
                """
                if device_name not in [device.name for device in self.__net_devices]:
                    print('Device not found')
                    exit(-1)
                    # todo Raise error!

                err_buf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)

                device: bytes = str.encode(device_name)
                immediate: bool = True  # According to manpage should always be true if supported
                nonblock: int = 0
                snapshot_len: int = 262144
                timeout: int = 1000

                # Create Device
                self.__pd = pcap.create(device, err_buf)

                if not self.__pd:
                    print('Error creating device!')
                # Snapshot length
                if 0 != (status := pcap.set_snaplen(self.__pd, snapshot_len)):
                    print('Snapshot_length could not be set!')
                if immediate:
                    try:
                        status = pcap.set_immediate_mode(self.__pd, 1)
                    except AttributeError:
                        print('Immediate mode not available for platform')
                    if status != 0:
                        print('Setting up immediate mode failed')
                status = pcap.set_timeout(self.__pd, timeout)
                if status != 0:
                    print('Setting timeout failed!')
                status = pcap.activate(self.__pd)
                if status < 0:
                    print(f'Failed to activate device {pcap.geterr(self.__pd).decode('utf-8', 'ignor')}')
                elif status > 0:
                    print(f'Pcap encountered an issue during device activation {pcap.geterr(self.__pd).decode('utf-8', 'ignor')}')

                # Todo this should be in the NetDevice
                localnet = pcap.bpf_u_int32()
                netmask = pcap.bpf_u_int32()
                if pcap.lookupnet(device, ct.byref(localnet), ct.byref(netmask), err_buf) < 0:
                    localnet = pcap.bpf_u_int32(0)
                    netmask = pcap.bpf_u_int32(0)
                    print("{!s}", err_buf.value.decode("utf-8", "ignore"))
                # Todo ----------------------------

                # Setup Filter
                expression = ""

                self.__f_code = pcap.bpf_program()
                cmd_buf = ' '.join(expression).encode('utf-8')
                if pcap.compile(self.__pd, ct.byref(self.__f_code), cmd_buf, 1, netmask) < 0:
                    print('Error compiling filter!')
                if pcap.setfilter(self.__pd, ct.byref(self.__f_code)) < 0:
                    print('Error setting filter')
                if pcap.setnonblock(self.__pd, nonblock, err_buf) == -1:
                    print('Error setting nonblocking capture mode')

            def sniff(self, device_name: str):
                self.__open_dev(device_name)
                while True:
                    link_type = ct.c_int(pcap.datalink(self.__pd))
                    status = pcap.dispatch(self.__pd, -1, print_me, ct.cast(ct.pointer(link_type), ct.POINTER(ct.c_ubyte)))
                    if status < 0:
                        break
                    if status != 0:
                        pass
                        #print(f'{status} packages seen, {packet_count.value} pakcets counted after ')

                if status == -2:
                    print()
                sys.stdout.flush()
                if status == -1:
                    print(f'Encountered Error! -> {pcap.geterr(self.__pd).decode('utf-8', 'ignore')}')

        self.net_sniffer_package = NetSniffer()
        return self.net_sniffer_package


class IPv4Packet:
    def __init__(self, packet):
        self.packet = packet
        self.__ip_header_values = struct.unpack_from('>QLII', self.packet)


    def __str__(self):
        return (f"Source address: {ipaddress.ip_address(self.__ip_header_values[2])}\n"
                f"Destination address: {ipaddress.ip_address(self.__ip_header_values[3])}\n")


class IPv6Packet:
    def __init__(self, packet):
        self.packet = packet
        self.__ip_header_values = struct.unpack_from('>Q16s16s', self.packet)

    def __str__(self):
        return (f"Source address: {ipaddress.ip_address(self.__ip_header_values[1])}\n"
                f"Destination address: {ipaddress.ip_address(self.__ip_header_values[2])}\n")

@pcap.pcap_handler
def print_me(usr, header, packet):

    def get_mac(my_bytes):
        mac = map('{:02x}'.format, my_bytes)
        return (':'.join(mac)).upper()

    def unpack_ether(package):
        dest_mac, src_mac, eth_proth = struct.unpack_from('!6s6sH', bytes(package[:14]))
        return get_mac(dest_mac), get_mac(src_mac), eth_proth, bytes(package[14:header.contents.caplen])

    link_type = ct.cast(usr, ct.POINTER(ct.c_int))
    if link_type.contents.value == DLT_EN10MB:
        if header.contents.caplen >= 14:
            (dst_mac_ad, src_mac_ad, ethertype, data) = unpack_ether(packet)
            if ethertype == ETHERNET_IPV4:
                print(IPv4Packet(data))
            elif ethertype == ETHERNET_IPV6:
                print(IPv6Packet(data))


def sniff():
    with NetSnifferPackage() as net_sniffer:
        net_sniffer.sniff('enp0s3')
