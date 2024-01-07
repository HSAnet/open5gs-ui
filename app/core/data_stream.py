import logging
import time
import traceback
from typing import List

from ..utils import py_pcap as pcap


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


    def run(self):
        self.__agent_logger = logging.getLogger(__name__)
        while True:
            try:
                self._collect_logs()
                self._capture_network_traffic()
                self._send_data()
                time.sleep(self._delay)
            except:
                # Todo proper error handling
                print(traceback.format_exc())

    def _collect_logs(self):
        pass

    def _capture_network_traffic(self):
        pass

    def _send_data(self):
        pass

