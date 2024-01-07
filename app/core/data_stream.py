import time
import logging
import traceback
from typing import List
from multiprocessing import Manager

from app.utils import py_pcap as pcap
from app.utils.open5g_rake import Open5GRake, Open5gsException


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

    @property
    def bpf_filter(self):
        return self._bpf_filter

    @property
    def delay(self):
        return self.delay

    @property
    def network_device(self):
        return self.network_device

    @property
    def agent_logger(self):
        return self.agent_logger

    @property
    def log_rake(self):
        return self.log_rake

    @property
    def net_cap(self):
        return self.net_cap

    @staticmethod
    def run(queue, logg):
        self: MonitoringAgent = queue.get()
        while True:
            try:
                start_time = time.time()
                self.collect_logs(self.delay if 'elapsed_time' not in locals() else elapsed_time + self.delay)
                self.capture_network_traffic()
                self.send_data()
                end_time = time.time()
                if (elapsed_time := (end_time - start_time)) < self.delay:
                    time.sleep(elapsed_time - self.delay)
            except pcap.pcap.NetworkError as ne:
                print(ne.msg)
            except Open5gsException as oge:
                print(oge.msg)
            except KeyboardInterrupt:
                break
            except:
                print(traceback.format_exc())

    def collect_logs(self, delta: int):
        print(self.log_rake.rake_json(time_delta=delta))

    def capture_network_traffic(self):
        if self.net_cap.error():
            raise pcap.pcap.NetworkError(self.net_cap.get())
        else:
            print(self.net_cap.get())

    def send_data(self):
        pass

