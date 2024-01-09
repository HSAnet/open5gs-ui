import time
import logging
import traceback
from typing import List

from app.utils import py_pcap as pcap
from app.utils.open5g_rake import Open5GRake, Open5gsException
from app.utils import Server
from app.utils import Config


class MonitoringAgent:

    def __init__(self, config: Config):
        dev_list: List[str] = [dev.name for dev in pcap.pcap.find_all_devs()]
        if config.device not in dev_list:
            raise AttributeError(f'Network device not found: {config.device}\nDevices found: [{'|'.join(dev_list)}]')
        if not config.delay.isdigit():
            raise AttributeError(f'Unexpected delay value: {config.delay}\nDelay must be integer')
        self._bpf_filter = config.bpf_filter
        self._delay = int(config.delay)
        self._network_device = config.device
        self._agent_logger = logging.getLogger(__name__)
        self._log_rake: Open5GRake = Open5GRake()
        self._net_cap: pcap.pcap.Capture = pcap.pcap.capture(self._network_device, config.bpf_filter)
        # Todo: Need to clarify how communication should be implemented / check django-restframework for async possibility
        # try:
        #     self._server_con: Server = Server(config=config)
        # except:
        #     print(traceback.format_exc())

    def run(self):
        while True:
            try:
                start_time = time.time()
                self._collect_logs(self._delay if 'elapsed_time' not in locals() else elapsed_time + self._delay)
                self._capture_network_traffic()
                self._send_data()
                end_time = time.time()
                if (elapsed_time := (end_time - start_time)) < self._delay:
                    time.sleep(self._delay - elapsed_time)
            except pcap.pcap.NetworkError as ne:
                print(ne.msg)
            except Open5gsException as oge:
                print(oge.msg)
            except KeyboardInterrupt:
                break
            except:
                print(traceback.format_exc())

    def _collect_logs(self, delta: int):
        # self._log_rake.rake_json(time_delta=delta)
        print(self._log_rake.rake_json(time_delta=delta))

    def _capture_network_traffic(self):
        if self._net_cap.error():
            raise pcap.pcap.NetworkError(self._net_cap.get())
        else:
            # self._net_cap.get()
            print(self._net_cap.get())

    def _send_data(self):
        pass

