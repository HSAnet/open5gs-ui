import ctypes as ct
import struct
import traceback
from typing import Generator, List, Union, Dict
from multiprocessing import Process, Queue
import logging
from datetime import datetime
from packet_parser import parse_packet

import libpcap as pcap

from exceptions import NetworkError, SetupError, CaptureError, err_to_str, dev_err
from network_device import NetworkDevice

_pcap_logger = logging.getLogger(__name__)


def __get_network_device() -> Generator[NetworkDevice, None, None]:
    sys_net_devices: ct.POINTER = ct.POINTER(pcap.pcap_if_t)()
    err_buff = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
    if not pcap.findalldevs(ct.byref(sys_net_devices), err_buff):
        it: ct.POINTER = sys_net_devices
        while it:
            it = it.contents
            yield NetworkDevice(it)
            it = it.next
        pcap.freealldevs(sys_net_devices)
    else:
        raise NetworkError(err_to_str(err_buff=err_buff))


def find_all_devs():
    """
    Function returns all network devices as list

    :return:
    """
    return [device for device in __get_network_device()]


def iter_all_devs():
    """
    Function returns all network devices as Generator

    :return:
    """
    return (device for device in __get_network_device())


class PacketData(ct.Structure):
    _fields_ = [
        ('ts', ct.c_longlong),
        ('cap_len', ct.c_uint),
        ('len', ct.c_uint),
        ('pkg', ct.POINTER(ct.c_ubyte))
    ]


def __capture(q_in: Queue, q_out: Queue, net_dev: NetworkDevice):
    parse_proc: Process = Process(target=__packet_parser, args=(q_in, q_out, net_dev))
    parse_proc.start()

    while True:
        packet_data = PacketData()
        status = pcap.dispatch(net_dev.pcap_device, -1, __packet_handler, ct.cast(ct.pointer(packet_data), ct.POINTER(ct.c_ubyte)))
        if status < 0:
            break
        if status != 0:
            # Todo remove try catch, only used for debugging purpose
            try:
                q_in.put({
                    'hdr': {
                        'ts': packet_data.ts,
                        'cap_len': packet_data.cap_len,
                        'len': packet_data.len
                    },
                    'pkg': bytes(packet_data.pkg[:packet_data.cap_len])
                })
            except:
                print(traceback.print_exc())
            del packet_data
    if status <= pcap.PCAP_ERROR:
        _pcap_logger.critical(f'Network sniffer encountered critical error!\n{dev_err(net_dev)}')


@pcap.pcap_handler
def __packet_handler(usr, header, packet):
    packet_data = ct.cast(usr, ct.POINTER(PacketData))
    packet_data.contents.ts = header.contents.ts.tv_sec
    packet_data.contents.cap_len = header.contents.caplen
    packet_data.contents.len = header.contents.len
    packet_data.contents.pkg = packet


def __packet_parser(q_in: Queue, q_out: Queue, net_dev: NetworkDevice):
    while True:
        try:
            pkg_data: Dict[str, Union[Dict[str, Union[bytes, int]], bytes]] = q_in.get()
            packet: bytes = pkg_data['pkg']
            header: Dict[str, Union[bytes, int]] = pkg_data['hdr']
            # print(f'{datetime.fromtimestamp(header['ts'])} -> len: {header["len"]}')
            parse_packet(packet)
            _, ether_type = struct.unpack('!12sH', bytes(packet[:14]))
            ip_packet: bytes = bytes(packet[14:header['cap_len']])
        except struct.error:
            # Todo none ETH10MB Packet caught -- ignore!
            pass
        except:
            print(traceback.print_exc())

        del pkg_data


def capture(device_name: str, bpf_filter: List[str]):
    """
    :raises NetworkError: If further processing not possible due to network-error
    :param device_name: The name of the device to capture as string
    :param bpf_filter: The bpf-filter as list of strings
    :return: todo
    """

    def cleanup(net_device: Union[NetworkDevice, None], process: Union[Process, None]):
        if net_device and net_dev.bpf_program:
            pcap.freecode(ct.byref(net_dev.bpf_program))
        if net_dev and net_dev.pcap_device:
            pcap.close(net_dev.pcap_device)
        if process:
            process.terminate()
            process.join()
            process.close()

    try:
        net_dev: NetworkDevice = [dev for dev in find_all_devs() if dev.name == device_name][0]
        if not net_dev.ready():
            raise NetworkError(f'Device "{device_name}" not ready for network capturing')
        else:
            net_dev.setup([''] if not bpf_filter else bpf_filter)
            q_extern: Queue = Queue(-1)
            cap_proc: Process = Process(target=__capture, args=(Queue(-1), q_extern, net_dev))
            cap_proc.start()
            return q_extern
    except IndexError:
        raise NetworkError(f'Device "{device_name}" was not found!')
    except SetupError as se:
        cleanup(None if 'net_dev' not in locals() else net_dev, None if 'cap_proc' not in locals() else cap_proc)
        raise NetworkError(f'Error occurred during device setup!\n{se.msg}')
    except CaptureError as ce:
        cleanup(None if 'net_dev' not in locals() else net_dev)
        raise NetworkError(f'Error occurred during packet capturing!\n{ce.msg}')
    except:
        print('Unexpected Error ')


if __name__ == '__main__':
    dev = find_all_devs()[0]
    try:
        capture('enp0s3', [])
    except NetworkError as ne:
        print(ne)