import logging
import time
import traceback
import ctypes as ct
from datetime import datetime
from multiprocessing import Process, Queue
from typing import Generator, List, Union, Dict

import pandas as pd

import _utils as utils
from ._core import parse_packet
from ._utils import LibpcapShare, NetworkError, SetupError, CaptureError, err_to_str, dev_to_str, dev_err


from packet_parser import parse_packet, PKG_COLUMNS

import libpcap as pcap

from libpcap_share import LibpcapShare, Flags
from exceptions import NetworkError, SetupError, CaptureError, err_to_str, dev_err
from network_device import NetworkDevice

_pcap_logger = logging.getLogger(__name__)
_shared_state = LibpcapShare()

CLM_D_TYPES = [pd.StringDtype(), 'Int64', pd.StringDtype(), pd.StringDtype(), pd.StringDtype(), pd.StringDtype(), 'Int64', pd.StringDtype(), 'Int64', pd.StringDtype(), pd.StringDtype(), 'Int64']

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


class _Capture:

    def __init__(self):
        self.__queue: Queue = Queue(-1)

    def get(self):
        _shared_state.write(Flags.FLAG_GET)
        while _shared_state.read() != Flags.FLAG_PUT.value:
            pass
        _shared_state.write(Flags.FLAG_NONE)
        return self.__queue.get()

    def put(self, data):
        self.__queue.put(data)


def __capture(q_in: Queue, c_obj: _Capture, net_dev: NetworkDevice):
    parse_proc: Process = Process(target=__packet_parser, args=(q_in, c_obj, net_dev))
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


def __packet_parser(q_in: Queue, c_obj: _Capture, net_dev: NetworkDevice):
    packet_lst: List[List[Union[str, int, None]]] = []

    while True:
        try:
            pkg_data: Dict[str, Union[Dict[str, Union[bytes, int]], bytes]] = q_in.get()
            packet: bytes = pkg_data['pkg']
            header: Dict[str, Union[bytes, int]] = pkg_data['hdr']
            packet_data = parse_packet(packet)
            if not packet_data:
                continue
            packet_data[PKG_COLUMNS.index('TimeStamp')] = datetime.fromtimestamp(header['ts'])
            # Define Up/Download
            x = [net_dev.comp_net_id(ip) for ip in [packet_data[5], packet_data[7]]].index(True)
            packet_data[PKG_COLUMNS.index('Direction')] = 'UP' if x == 0 else 'Down' if x == 1 else ''
            packet_data[PKG_COLUMNS.index('Size')] = header['len']
            packet_lst.append(packet_data)
            if _shared_state.read() == Flags.FLAG_GET.value:
                dc = dict()
                for col_idx, col_name in enumerate(PKG_COLUMNS):
                    lst = []
                    for pkg_idx in range(len(packet_lst)):
                        lst.append(packet_lst[pkg_idx][col_idx])
                    dc[col_name] = pd.Series(data=lst, dtype=CLM_D_TYPES[col_idx])
                c_obj.put(pd.DataFrame(dc))
                _shared_state.write(Flags.FLAG_PUT)
                packet_lst = []
        except CaptureError as ce:
            _pcap_logger.info(ce.msg)
        except ValueError:
            _pcap_logger.info(f'Could not define Up/Download for package {packet_data}')
        except KeyboardInterrupt:
            return
        except:
            _pcap_logger.warning(traceback.print_exc())
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
            capture_obj: _Capture = _Capture()
            cap_proc: Process = Process(target=__capture, args=(Queue(-1), capture_obj, net_dev))
            cap_proc.start()
            return capture_obj
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
    # dev = find_all_devs()[0]
    pd.set_option('display.max_columns', 500)
    pd.set_option('display.width', 2000)
    try:
        c_obj: _Capture = capture('enp0s3', [])
        while True:
            time.sleep(5)
            print(c_obj.get())
            #print(c_obj.get().head(20))
    except NetworkError as ne:
        print(ne)