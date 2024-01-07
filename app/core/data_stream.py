import time
import logging
import traceback
from typing import List

from ..utils import py_pcap as pcap
from ..utils.open5g_rake import Open5GRake, Open5gsException


class MonitoringAgent:

    def __init__(self, bpf_filter: List, network_device: str, delay: str):
        dev_list: List[str] = [dev.name for dev in pcap.pcap.find_all_devs()]
        if network_device not in dev_list:
            raise AttributeError(f'Network device not found: {network_device}\nDevices found: [{'|'.join(dev_list)}]')
        if not delay.isdigit():
            raise AttributeError(f'Unexpected delay value: {delay}\nDelay must be integer')
        self._bpf_filter = bpf_filter
        self._delay = int(delay)
        self._network_device = network_device
        self._agent_logger = logging.getLogger(__name__)
        self._log_rake: Open5GRake = Open5GRake()
        self._net_cap: pcap.pcap.Capture = pcap.pcap.capture(self._network_device, bpf_filter)

    def run(self):
        while True:
            try:
                start_time = time.time()
                self._collect_logs(self._delay if 'elapsed_time' not in locals() else elapsed_time + self._delay)
                self._capture_network_traffic()
                self._send_data()
                end_time = time.time()
                if (elapsed_time := (end_time - start_time)) < self._delay:
                    time.sleep(elapsed_time - self._delay)
            except pcap.pcap.NetworkError as ne:
                print(ne.msg)
            except Open5gsException as oge:
                print(oge.msg)
            except KeyboardInterrupt:
                break
            except:
                print(traceback.format_exc())

    def _collect_logs(self, delta: int):
        print(self._log_rake.rake_json(time_delta=delta))

    def _capture_network_traffic(self):
        if self._net_cap.error():
            raise pcap.pcap.NetworkError(self._net_cap.get())
        else:
            print(self._net_cap.get())

    def _send_data(self):
        pass

