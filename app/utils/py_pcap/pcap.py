import traceback
import ctypes as ct
from datetime import datetime
from multiprocessing import Process, Queue
from typing import Generator, List, Union, Dict

import pandas as pd
import libpcap as pcap

from ._core import parse_packet
from ._utils import (LibpcapShare, SharedFlags,
                     NetworkError, SetupError, err_to_str, dev_err,
                     NetworkDevice,
                     Capture, Packet)

_shared_mem: LibpcapShare = LibpcapShare()


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


def __capture(q_in: Queue, c_obj: Capture, net_dev: NetworkDevice):
    parse_proc: Process = Process(target=__packet_parser, args=(q_in, c_obj, net_dev))
    parse_proc.start()

    while True:
        packet_data = PacketData()
        status = pcap.dispatch(net_dev.pcap_device, -1, __packet_handler, ct.cast(ct.pointer(packet_data), ct.POINTER(ct.c_ubyte)))
        if status < 0:
            break
        if status != 0:
            q_in.put({
                'hdr': {
                    'ts': packet_data.ts,
                    'cap_len': packet_data.cap_len,
                    'len': packet_data.len
                },
                'pkg': bytes(packet_data.pkg[:packet_data.cap_len])
            })
            del packet_data
    if status <= pcap.PCAP_ERROR:
        parse_proc.terminate()
        parse_proc.join()
        parse_proc.close()
        raise NetworkError(f'Network sniffer encountered critical error!\n{dev_err(net_dev)}')


@pcap.pcap_handler
def __packet_handler(usr, header, packet):
    packet_data = ct.cast(usr, ct.POINTER(PacketData))
    packet_data.contents.ts = header.contents.ts.tv_sec
    packet_data.contents.cap_len = header.contents.caplen
    packet_data.contents.len = header.contents.len
    packet_data.contents.pkg = packet


def __packet_parser(q_in: Queue, c_obj: Capture, net_dev: NetworkDevice):
    packet_lst = [[] for _ in range(len(Packet.__members__))]
    while True:
        try:
            if not q_in.empty():
                pkg_data: Dict[str, Union[Dict[str, Union[bytes, int]], bytes]] = q_in.get()
                packet: bytes = pkg_data['pkg']
                header: Dict[str, Union[bytes, int]] = pkg_data['hdr']

                ex_data: List[Union[str, int, None, datetime]] = [None for _ in range(len(Packet.__members__))]
                parse_packet(packet, ex_data)
                if not all(entry is None for entry in ex_data):
                    # Adding Timestamp / Size / Direction (Up-/Download)
                    ex_data[Packet.TIMESTAMP.value] = datetime.fromtimestamp(header['ts'])
                    ex_data[Packet.SIZE.value] = header['len']
                    direction: int = [net_dev.comp_net_id(ip) for ip in [ex_data[Packet.SOURCE_IP.value], ex_data[Packet.DESTINATION_IP.value]]].index(True)
                    ex_data[Packet.DIRECTION.value] = 'UP' if direction == 0 else 'Down' if direction == 1 else ''
                    # convert horizontal to vertical list
                    for idx, etr in enumerate(ex_data):
                        packet_lst[idx].append(etr)
                del pkg_data
            # Gets executed when get is called on Capture-Object
            if _shared_mem.read() == SharedFlags.FLAG_GET.value:
                c_obj.put(pd.DataFrame({col.name.capitalize(): pd.Series(data=packet_lst[index], dtype=col.d_type) for
                                        index, col in enumerate(Packet)}))
                # write dataframe to queue
                _shared_mem.write(SharedFlags.FLAG_PUT)
                packet_lst = [[] for _ in range(len(Packet.__members__))]
        except ValueError:
            # Up/Download could not be defined - Further processing impossible
            print('ValueError')
            pass
        except KeyboardInterrupt:
            # End process
            _shared_mem.close()
            return
        except:
            # Severe unexpected Error!
            # Write Error to queue and end process.
            _shared_mem.write(SharedFlags.FLAG_ERROR)
            c_obj.put(traceback.format_exc())
            _shared_mem.close()
            return



def capture(device_name: str, bpf_filter: List[str]):
    """
    :raises NetworkError: If further processing not possible due to network-error
    :param device_name: The name of the device to capture as string
    :param bpf_filter: The bpf-filter as list of strings
    :return: Capture obj
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
            capture_obj: Capture = Capture(_shared_mem)
            cap_proc: Process = Process(target=__capture, args=(Queue(-1), capture_obj, net_dev))
            cap_proc.start()
            return capture_obj
    except IndexError:
        raise NetworkError(f'Device "{device_name}" was not found!')
    except SetupError as se:
        cleanup(None if 'net_dev' not in locals() else net_dev, None if 'cap_proc' not in locals() else cap_proc)
        raise NetworkError(f'Error occurred during device setup!\n{se.msg}')
    except NetworkError as ne:
        cleanup(None if 'net_dev' not in locals() else net_dev)
        _shared_mem.write(SharedFlags.FLAG_ERROR)
        if 'capture_obj' in locals():
            capture_obj.put(f'Error occurred during packet capturing!\n{ne.msg}')
