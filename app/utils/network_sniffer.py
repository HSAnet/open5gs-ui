import socket
import logging
import ctypes as ct
from dataclasses import dataclass
from typing import List, Dict, Callable, Tuple, Union

import libpcap as pcap
from libpcap._platform import sockaddr_in, sockaddr_in6

from app.utils.exceptions import NetworkError

__ERROR_BUFFER: ct.c_buffer = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
__NETWORK_DEVICE = None

err_to_str: Callable[[], str] = lambda: __ERROR_BUFFER.value.decode('utf-8', 'ignore')
dev_to_str: Callable[[], str] = lambda device: device.decode("utf-8")
dev_err: Callable[[], str] = lambda device: pcap.geterr(device).decode("utf-8", "ignore")
logger = logging.getLogger(__name__)


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


def setup_sniffer(device_name: str, bpf_filter: Union[None, List[str]] = None) -> Tuple[pcap.pcap_if, pcap.bpf_program]:
    if device_name not in [device.name for device in __find_all_network_devices() if device.status()]:
        # Check if provided network-adapter is known to system and accessible
        logger.error(err_msg := f'Device: {device_name} not found!')
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



            while True:
                print('in loop')
                packet_count = ct.c_int(0)
                print('link created')
                status = pcap.dispatch(network_device, -1, capture_packet,
                                       ct.cast(ct.pointer(packet_count), ct.POINTER(ct.c_ubyte)))
                print('funciton returned')
                if status < 0:
                    print('status < ß')
                    break
                if status != 0:
                    print(f'Status: {status}')
                    pass  # returnValue
                    # print(f'{status} packages seen, {packet_count.value} packets counted after ')

            if status <= -1:
                print('hello')
                logger.critical(f'Network sniffer encountered critical error!\n{dev_err(device)}')



            return network_device, f_code
        finally:
            if 'f_code' in locals():
                pcap.freecode(ct.byref(f_code))
            pcap.close(network_device)


def sniff_on_network(device, f_code: pcap.bpf_program):
    pass


@pcap.pcap_handler
def capture_packet(usr, header, packet):
    counterp = ct.cast(usr, ct.POINTER(ct.c_int))
    counterp[0] += 1


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



if __name__ == '__main__':
    try:
        sniff_on_network(*setup_sniffer('enp0s3'))
    except NetworkError as err:
        print(err)
