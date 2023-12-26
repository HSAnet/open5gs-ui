import socket
import struct
import ctypes as ct
from typing import Callable, Union, List, Dict

import libpcap as pcap

from .pcap_exceptions import NetworkError, SetupError, err_to_str, dev_err
import logging


bytes_to_int: Callable[[bytes], int] = lambda b: int.from_bytes(b, byteorder='big', signed=False)
bytes_to_ip: Callable[[int], str] = lambda b: socket.inet_ntop(socket.AF_INET6, b) if len(b) > 4 else socket.inet_ntop(socket.AF_INET, b)
str_to_bytes: Callable[[str], bytes] = lambda s: s.encode('utf-8')
dev_to_str: Callable[[], str] = lambda device: device.decode("utf-8")


class NetworkDevice:

    def __init__(self, device: pcap.pcap_if):
        self.__snapshot_len: int = 262444
        self.__nonblock: int = 0
        self.__timeout: int = 1000
        self.__name: str = device.name.decode('utf-8')
        self.__set_flags(device=device)
        self.__set_network_families(device=device)
        self.__pcap_logger: logging.Logger = logging.getLogger(__name__)

        self.__pcap_dev = None
        self.__f_code = None

    @property
    def name(self) -> str:
        return self.__name

    @property
    def bpf_program(self):
        return self.__f_code

    @property
    def pcap_device(self):
        return self.__pcap_dev

    @property
    def snapshot_len(self) -> int:
        return self.__snapshot_len

    def ready(self) -> bool:
        return all(map(lambda flag: flag in self.__flags, ['UP', 'RUNNING']))

    def __set_flags(self, device: pcap.pcap_if) -> None:
        """
        Function set device flags (only wired flags)
        Iterates through global variables in pcap, filters flags and checks if they apply.

        :param device: pcap.pcap_if struct instance
        """
        get_flag: Callable[[str], str] = lambda pcap_flag_name: pcap_flag_name.rsplit('_', 1)[-1]
        self.__flags = [get_flag(x) for x in dir(pcap) if 'PCAP_IF' in x and 'CONNECTION' not in x and device.flags & getattr(pcap, x)]

    def __set_network_families(self, device: pcap.pcap_if) -> None:
        """
        Function sets network families - IP-Addresses and corresponding masks.

        :param device: pcap.pcap_if struct instance
        """
        self.__addr_families = []
        addr_family = device.addresses
        empty_array: Callable[[bytes], bool] = lambda arr: not any([b for b in arr if b != 0])
        while addr_family:
            addr_family = addr_family.contents
            if addr_family.addr and addr_family.netmask:
                # The addr_family.addr and add_family.netmask can be NULL-Pointers.
                # struct.unpack_from unpacks the pcap.socketaddr struct with the following members
                #                       socketaddr - members ['sa_family', '__pad1', 'ipv4_addr', ipv6_addr', '__pad2']
                # Only index 2 and 3 are important -> slice(2:4)
                # If the ip_addr has more than 4 bytes it must be a IPv6 address -> len(ip) <= 4
                # If the ip_addr consists of \x00 bytes it can be ignored -> if not empty_array(ip)
                # Whenever the ipv4_address is occupied in the struct, the ipv6_address cannot be!
                # However, there are random values in its member and it always starts with \x00\x00 -> not empty_array(ip[:2])
                # The cdir value is the amount of 1s in the bit representation of the network-mask. Usually seen in combination
                # with the IP-Address like '192.186.1.1/24' -> 24 is the cdir value.
                self.__addr_families += [{
                    'type': f'IPv4' if len(ip) <= 4 else f'IPv6',
                    'addr': ip,
                    'mask': mask,
                    'cdir': bin(bytes_to_int(mask)).count('1'),
                    'net_id': bytes_to_int(ip) >> ((32 if len(ip) <= 4 else 128) - bin(bytes_to_int(mask)).count('1'))
                }
                    for (ip, mask) in
                    zip(
                        struct.unpack_from('<hH4s16sQ', addr_family.addr.contents)[2:4],
                        struct.unpack_from('<hH4s16sQ', addr_family.netmask.contents)[2:4]
                    ) if not empty_array(ip) and not empty_array(ip[:2])]
            addr_family = addr_family.next

    def comp_net_id(self, ip_addr: str):
        """
        Function validates the provided IP Address and checks if it is valid considering the
        devices IP Address and NetMask.

        This is done by converting the provided IP Address to an integer and shifted to the right by either
            - ipv4 32
            - ipv6 128
        If it matches any of the devices Network-IDs, True is returned else False

        :raises NetworkError: If provided IP Address is not valid
        :param ip_addr: The IP Address to check in string format like '192.168.127.12'
        :return: True if IP Address matched devices network-id, False otherwise
        """
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

    def get_ipv4_addresses(self, as_str: bool = False) -> List[Union[str, bytes]]:
        return [family['addr'] if not as_str
                else socket.inet_ntop(socket.AF_INET, family['addr'])
                for family in list(self.__addr_families)
                if family['type'] == 'IPv4']

    def get_ipv6_addresses(self, as_str: bool = False) -> List[Union[str, bytes]]:
        return [family['addr'] if not as_str
                else socket.inet_ntop(socket.AF_INET6, family['addr'])
                for family in list(self.__addr_families)
                if family['type'] == 'IPv6']

    def get_ipv4_masks(self, as_str: bool = False) -> List[Union[str, int]]:
        return [family['mask'] if not as_str
                else socket.inet_ntop(socket.AF_INET, family['mask'])
                for family in list(self.__addr_families)
                if family['type'] == 'IPv4']

    def get_ipv6_masks(self, as_str: bool = False) -> List[Union[str, int]]:
        return [family['mask'] if not as_str
                else socket.inet_ntop(socket.AF_INET6, family['mask'])
                for family in list(self.__addr_families)
                if family['type'] == 'IPv6']

    def __setup_device_values(self, ):
        """
        Function sets up values for device like:
            - Snap-length
            - Immediate mode
            - timeout
        :raises NetworkError: If timeout or snap-length could not be set.
        """
        if 0 != (status := pcap.set_snaplen(self.__pcap_dev, self.__snapshot_len)):
            raise NetworkError(f'Device: {dev_to_str(self.__pcap_dev)}\nStatus: {str(status)}')
        try:
            pcap.set_immediate_mode(self.__pcap_dev, 1)
        except AttributeError as err:
            self.__pcap_logger.warning(f'Device: {dev_to_str(self.__pcap_dev)} does not support immediate mode!\n{str(err)}')
        if pcap.set_timeout(self.__pcap_dev, self.__timeout) != 0:
            raise NetworkError(f'Device: {dev_to_str(self.__pcap_dev)} - not able to set timeout!')

    def __activate_device(self, ):
        """
        Function tries to activate network device

        :raises NetworkError: If device could not be activated
        """
        if (status := pcap.activate(self.__pcap_dev)) < 0:
            raise NetworkError(f'Cannot activate device: {dev_to_str(self.__pcap_dev)}')
        elif status > 0:
            self.__pcap_logger.warning(f'Error occurred while Network device activation!\n'
                           f'{dev_err(self.__pcap_dev)}')

    def __create_capture_filter(self, filter_bpf: List[str], err_buff: ct.c_buffer):
        """
        Function tries to create bpf filter for device

        :param filter_bpf: A list of filter parameters
        :raises NetworkError: If error occurred during filter-setup
        """
        if pcap.compile(self.__pcap_dev, ct.byref(self.__f_code), str_to_bytes(' '.join(filter_bpf)), 1, pcap.PCAP_NETMASK_UNKNOWN) < 0:
            raise NetworkError(f'{dev_err(self.__pcap_dev)}')
        if pcap.setfilter(self.__pcap_dev, ct.byref(self.__f_code)) < 0:
            raise NetworkError(f'{dev_err(self.__pcap_dev)}')
        if pcap.setnonblock(self.__pcap_dev, self.__nonblock, err_buff) == -1:
            self.__pcap_logger.warning(f'{dev_err(self.__pcap_dev)}')

    def setup(self, bpf_filter: List[str]) -> None:
        err_buff: ct.c_buffer = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)

        if not (pcap_dev := pcap.create(str_to_bytes(self.name), err_buff)):
            raise NetworkError(err_to_str(err_buff))
        else:
            self.__pcap_dev = pcap_dev
            try:
                self.__setup_device_values()
                self.__activate_device()
                self.__f_code = pcap.bpf_program()
                self.__create_capture_filter(filter_bpf=bpf_filter, err_buff=err_buff)
            except NetworkError as n_err:
                if self.__f_code:
                    pcap.freecode(ct.byref(self.__f_code))
                if self.__pcap_dev:
                    pcap.close(self.__pcap_dev)
                raise SetupError(n_err.msg)

    def __str__(self) -> str:
        return f'{self.__name}\n'\
               f'{'Flags':>4}: {' '.join(self.__flags)}\n'\
               f'\tAddress Family: IPv4\n'\
               f'{''.join([f'\t\tAddress: {addr}\n\t\tMask: {mask}\n' for (addr, mask) in zip(self.get_ipv4_addresses(as_str=True), self.get_ipv4_masks(as_str=True))])}'\
               f'\tAddress Family: IPv6\n'\
               f'{''.join([f'\t\tAddress: {addr}\n\t\tMask: {mask}\n' for (addr, mask) in zip(self.get_ipv6_addresses(as_str=True), self.get_ipv6_masks(as_str=True))])}'
