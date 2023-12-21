import struct
import socket
import logging
import traceback
import ipaddress
from functools import partial

import regex as re
import libpcap as pcap
import ctypes as ct
from dataclasses import dataclass, field
from typing import List, Dict, Callable, Tuple, Union
from libpcap._platform import sockaddr_in, sockaddr_in6
import pandas as pd
from multiprocessing import Manager, Process

from app.utils.exceptions import NetworkError

__ERROR_BUFFER: ct.c_buffer = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
__NETWORK_DEVICE = None

err_to_str: Callable[[], str] = lambda: __ERROR_BUFFER.value.decode('utf-8', 'ignore')
dev_to_str: Callable[[], str] = lambda device: device.decode("utf-8")
dev_err: Callable[[], str] = lambda device: pcap.geterr(device).decode("utf-8", "ignore")
public_attr_pattern = re.compile(r'^(?!_)')
logger = logging.getLogger(__name__)


@dataclass
class NetDevice:
    name: str
    flags: List[str]
    addr_families: List[Dict[str, Union[str, int]]]
    network_id: Dict[str, Dict[str, int]] = field(init=False)

    def __post_init__(self):
        self.network_id = self.__network_id_init()

    def status(self) -> bool:
        return 'UP' in self.flags and 'RUNNING' in self.flags

    def __network_id_init(self) -> Dict[str, Dict[str, int]]:
        """
        This function precalculates network-id and cdir for easy comparison.
        First it counts the 1s in the binary representation of the network mask - resulting in the cdir.
        Then it takes the network-ip, then shifts it to the right by either 128 - cdir (IPv6) or 32 - cdir (IPv4).
        Both values are stored as integer in a dictionary.

                #   0b11000000101010000011100000000011
                # &	0b11111111111111111111111100000000
                #   ----------------------------------
                # 	0b11000000101010000011100000000000
                #
                #   Shift to right by 32 - cdir_mask
                # 	0b110000001010100000111000   -> IPv4-Network-ID

        :return: Dictionary containing integer-representations of network-id and cdir (192.168.1/24)
        """
        ret_value = {'IPv4': {'id': 0, 'cdir': 0}, 'IPv6': {'id': 0, 'cdir': 0}}
        for family in self.addr_families:
            if family['type'] == 'IPv6':
                ret_value['IPv6']['cdir'] = bin(family['mask_int']).count('1')
                ret_value['IPv6']['id'] = (family['addr_int']) >> (128 - ret_value['IPv6']['cdir'])
            else:
                ret_value['IPv4']['cdir'] = bin(family['mask_int']).count('1')
                ret_value['IPv4']['id'] = (family['addr_int']) >> (32 - ret_value['IPv4']['cdir'])
        return ret_value

    def in_ip_range(self, ip_addr: str) -> bool:
        """
        Method converts provided ip_addr respectively to integer representation and shifts it to the right to compare
        it to the network-id. If they match, true is returned, else false.

        :param ip_addr: The IP Address to be checked
        :return: True if IP Address in network, else false
        """
        if ':' in ip_addr:
            return self.network_id['IPv6']['id'] == (int.from_bytes(socket.inet_pton(socket.AF_INET6, ip_addr), byteorder='big') >> (128 - self.network_id['IPv6']['cdir']))
        else:
            return self.network_id['IPv4']['id'] == (int.from_bytes(socket.inet_aton(ip_addr), byteorder='big') >> (32 - self.network_id['IPv4']['cdir']))

    def __str__(self) -> str:
        return (f"{self.name}\n"
                f"{'Flags':>4}: {' '.join(self.flags)}\n"
                f"{''.join([f"\tAddress Family: {'unknown' if 'type' not in fam else fam['type']}\n"
                            f"\t\tAddress: {'' if 'addr' not in fam else fam['addr']}\n"
                            f"\t\tNetmask: {'' if 'mask' not in fam else fam['mask']}\n"
                            for fam in self.addr_families])}")


def __setup_sniffer(device_name: str, bpf_filter: Union[None, List[str]] = None) -> Tuple[NetDevice, pcap.pcap_if, pcap.bpf_program]:
    try:
        device: NetDevice = [dev for dev in __find_all_network_devices()
                             if dev.status() and dev.name == device_name][0]
    except ValueError:
        logger.error(err_msg := f'Device: {device_name} not found or active!')
        raise NetworkError(err_msg)

    snapshot_len: int = 262444  # tcpdump default
    nonblock: int = 0           # default false
    timeout: int = 1000         # 1 second seams to be a reasonable time
    create_device: Callable[[str], str] = lambda: pcap.create(str.encode(device_name), __ERROR_BUFFER)

    def setup_device_values():
        """
        Function sets up values for device like:
            - Snap-length
            - Immediate mode
            - timeout
        :raises NetworkError: If timeout or snap-length could not be set.
        """
        if 0 != (status := pcap.set_snaplen(network_device, snapshot_len)):
            raise NetworkError(f'Device: {dev_to_str(network_device)}\nStatus: {str(status)}')
        try:
            pcap.set_immediate_mode(network_device, 1)
        except AttributeError as err:
            logger.warning(f'Device: {dev_to_str(network_device)} does not support immediate mode!\n'
                           f'{str(err)}')
        if pcap.set_timeout(network_device, timeout) != 0:
            raise NetworkError(f'Device: {dev_to_str(network_device)} - cannot set timeout!')

    def activate_device():
        """
        Function tries to activate network device

        :raises NetworkError: If device could not be activated
        """
        if (status := pcap.activate(network_device)) < 0:
            raise NetworkError(f'Cannot activate device: {dev_to_str(network_device)}')
        elif status > 0:
            logger.warning(f'Error occurred while Network device activation!\n'
                           f'{pcap.geterr(network_device).decode('utf - 8', 'ignore')}')

    def get_dev_add_and_mask() -> Tuple[pcap.bpf_u_int32, pcap.bpf_u_int32]:
        """
        Function tries to retrieve network-devices address and mask.

        :raises NetworkError: If error occurred during lookup

        :return: Network-Addr and Network-Mask
        :rtype: Tuple[pcap.bpf_u_int32, pcap.bpf_u_int32]
        """
        localnet = pcap.bpf_u_int32()
        netmask = pcap.bpf_u_int32()
        if pcap.lookupnet(str.encode(device_name), ct.byref(localnet), ct.byref(netmask), __ERROR_BUFFER) < 0:
            localnet = pcap.bpf_u_int32(0)
            netmask = pcap.bpf_u_int32(0)
            raise NetworkError(f'Cannot retrieve Network address/mask for device '
                               f'{dev_to_str(network_device)} - {err_to_str()}')
        return localnet, netmask

    def create_capture_filter(code: pcap.bpf_program, filter_bpf: List[str], netmask: pcap.bpf_u_int32):
        """
        Function tries to create bpf filter for device

        :param filter_bpf: A list of filter parameters
        :param code: Pcap-Struct containing bpf-instructions/maps and relocation section
        :param netmask: The netmask in int-form
        :raises NetworkError: If error occurred during filter-setup
        """
        if pcap.compile(network_device, ct.byref(code), ' '.join(filter_bpf).encode('utf-8'), 1, netmask) < 0:
            raise NetworkError(f'{pcap.geterr(network_device).decode('utf-8', 'ignore')}')
        if pcap.setfilter(network_device, ct.byref(code)) < 0:
            raise NetworkError(f'{pcap.geterr(network_device).decode('utf-8', 'ignore')}')
        if pcap.setnonblock(network_device, nonblock, __ERROR_BUFFER) == -1:
            logger.warning(f'{pcap.geterr(network_device).decode('utf-8', 'ignore')}')

    if not (network_device := create_device()):
        raise NetworkError(err_to_str())
    else:
        try:
            setup_device_values()
            activate_device()
            net_addr, net_mask = get_dev_add_and_mask()
            create_capture_filter((f_code := pcap.bpf_program()), [''] if not bpf_filter else bpf_filter, net_mask)
        except NetworkError as n_err:
            if 'f_code' in locals():
                pcap.freecode(ct.byref(f_code))
            pcap.close(network_device)
        return device, network_device, f_code


class PacketData(ct.Structure):
    _fields_ = [
        ('pkg_type', ct.c_int),
        ('dst_addr', ct.c_char_p),
        ('src_addr', ct.c_char_p),
        ('pkg_size', ct.c_int)
    ]


def __sniff_on_network(queue, device: NetDevice, pcap_device, f_code: pcap.bpf_program):
    def new_entry(src, dst, size):
        return {
            'src_addr': src.decode('utf-8'),
            'dst_addr': dst.decode('utf-8'),
            'size': size,
            'type': 'UPLOAD' if device.in_ip_range(src.decode('utf-8')) else 'DOWNLOAD'
        }
    try:
        while True:
            packet_data = PacketData()
            status = pcap.dispatch(pcap_device, -1, __capture_packet, ct.cast(ct.pointer(packet_data), ct.POINTER(ct.c_ubyte)))
            if status < 0:
                break
            if status != 0:
                # In case of a timeout the struct members might be null
                call_member = lambda m_str: getattr(packet_data, m_str)
                if not any(el is None for el in [call_member(member) for member in dir(packet_data) if public_attr_pattern.search(member)]):                
                    # Assert - all members set!
                    queue.put(new_entry(src=packet_data.src_addr, dst=packet_data.dst_addr, size=packet_data.pkg_size))
                    del packet_data
        if status <= pcap.PCAP_ERROR:
            logger.critical(f'Network sniffer encountered critical error!\n{dev_err(device)}')
    except:
        logger.critical(traceback.print_exc())
    finally:
        pcap.freecode(ct.byref(f_code))
        pcap.close(pcap_device)
        exit()


@pcap.pcap_handler
def __capture_packet(usr, header, packet):
    packet_data = ct.cast(usr, ct.POINTER(PacketData))

    try:
        _, ether_type = struct.unpack('!12sH', bytes(packet[:14]))
        ip_packet: bytes = bytes(packet[14:header.contents.caplen])
    except struct.error:
        # Todo none ETH10MB Packet caught -- ignore!
        return
    if header.contents.caplen >= 14:
        if ether_type == socket.ETHERTYPE_IP:
            packet_data.contents.pkg_type = socket.ETHERTYPE_IP
            _, _, src_addr, dst_addr = struct.unpack_from('>QLII', ip_packet)
        elif ether_type == socket.ETHERTYPE_IPV6:
            packet_data.contents.pkg_type = socket.ETHERTYPE_IPV6
            _, src_addr, dst_addr = struct.unpack_from('>Q16s16s', ip_packet)
        if {'src_addr', 'dst_addr'} <= set(locals().keys()):
            packet_data.contents.src_addr = ct.string_at(str(ipaddress.ip_address(src_addr)).encode('utf-8'))
            packet_data.contents.dst_addr = ct.string_at(str(ipaddress.ip_address(dst_addr)).encode('utf-8'))
            packet_data.contents.pkg_size = header.contents.len


def __find_all_network_devices() -> List[NetDevice]:
    def get_device_flags(device: pcap.pcap_if) -> List[str]:
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

    def get_addr_family(device: pcap.pcap_if) -> List[Dict[str, str]]:
        addr_families = []
        addr_family = device.addresses
        while addr_family:
            addr_family: pcap.pcap_addr = addr_family.contents

            addr: pcap.sockaddr = addr_family.addr
            netmask: pcap.sockaddr = addr_family.netmask
            broad_addr: pcap.sockaddr = addr_family.broadaddr
            dst_addr: pcap.sockaddr = addr_family.dstaddr
            if addr:
                family: Dict[str] = dict()
                if addr.contents.sa_family == socket.AF_INET:
                    family['type'] = 'IPv4'
                    if addr:
                        family['addr'] = socket.inet_ntop(socket.AF_INET, ct.cast(addr, ct.POINTER(sockaddr_in)).contents.sin_addr)
                        family['addr_int'] = int.from_bytes(ct.cast(addr, ct.POINTER(sockaddr_in)).contents.sin_addr, byteorder='big')
                    if netmask:
                        family['mask'] = socket.inet_ntop(socket.AF_INET, ct.cast(netmask, ct.POINTER(sockaddr_in)).contents.sin_addr)
                        family['mask_int'] = int.from_bytes(ct.cast(netmask, ct.POINTER(sockaddr_in)).contents.sin_addr, byteorder='big')
                    if broad_addr:
                        family['broad_addr'] = socket.inet_ntop(socket.AF_INET, ct.cast(broad_addr, ct.POINTER(sockaddr_in)).contents.sin_addr)
                    if dst_addr:
                        family['dst_addr'] = socket.inet_ntop(socket.AF_INET, ct.cast(dst_addr, ct.POINTER(sockaddr_in)).contents.sin_addr)
                    addr_families.append(family)
                elif addr.contents.sa_family == socket.AF_INET6:
                    family['type'] = 'IPv6'
                    if addr:
                        family['addr'] = socket.inet_ntop(socket.AF_INET6, ct.cast(addr, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)
                        family['addr_int'] = int.from_bytes(ct.cast(addr, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr, byteorder='big')
                    if netmask:
                        family['mask'] = socket.inet_ntop(socket.AF_INET6, ct.cast(netmask, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)
                        family['mask_int'] = int.from_bytes(ct.cast(netmask, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr, byteorder='big')
                    if broad_addr:
                        family['broad_addr'] = socket.inet_ntop(socket.AF_INET6, ct.cast(broad_addr, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)
                    if dst_addr:
                        family['dst_addr'] = socket.inet_ntop(socket.AF_INET6, ct.cast(dst_addr, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)
                    addr_families.append(family)
            addr_family = addr_family.next
        return addr_families

    device_array = ct.POINTER(pcap.pcap_if_t)()
    device_list: List[NetDevice] = []
    if pcap.findalldevs(ct.byref(device_array), __ERROR_BUFFER) == 0:
        it = device_array
        while it:
            it = it.contents
            device_list.append(NetDevice(name=it.name.decode('utf-8'),
                                         flags=get_device_flags(it),
                                         addr_families=get_addr_family(it)))
            it = it.next
        pcap.freealldevs(device_array)
    else:
        raise NetworkError(err_to_str())
        pass
    return device_list


def sniff(device_name: str, delay: int = 1):
    """
    Collects network-data from provided device and returns data in delay-time

    :raises NetworkError if error occurred while sniffing
    :param device_name: The network-device name (e.g. ogstun)
    :param delay: Delay in seconds before return
    :return:
    """
    manager = Manager()
    p_queue = manager.Queue()
    net_dev, pcap_dev, bpf_filer = __setup_sniffer(device_name=device_name)
    network_sniffer: Process = Process(target=__sniff_on_network, args=(p_queue, net_dev, pcap_dev, bpf_filer))
    try:
        network_sniffer.start()
        while True:
            yield p_queue.get()
    except:
        # Todo: Error handling
        raise NetworkError('')
    finally:
        network_sniffer.terminate()
        p_queue.join()


if __name__ == '__main__':
    flush_rows = lambda frame: frame.drop(frame.index, inplace=True)
    append_row = lambda frame, row: pd.concat([frame, pd.DataFrame([row], columns=row.index)]).reset_index(drop=True)

    df = pd.DataFrame(columns=['src_addr', 'dst_addr', 'size', 'type'])
    for packet_data in sniff('enp0s3'):
        df = append_row(df, pd.Series(packet_data))
        #grouped = df['size'].groupby(df['src_addr'], df['dst_addr'], df['type']).size()
        grouped = df.groupby(['src_addr', 'dst_addr', 'type'], as_index=False)['size'].sum()
        print(grouped.tail(15))
        print()
        print()
        print()