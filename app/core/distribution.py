import logging
from typing import Union
from pathlib import Path
from multiprocessing import Process

from app.utils import Config, ExecError, worker_config, LOG_QUEUE
from .data_stream import MonitoringAgent


class ObsProcess(Process):

    def __init__(self, bpf_filter, device_name, time_delay, *args, **kwargs):
        super(ObsProcess, self).__init__()
        self._bpf_filter = bpf_filter
        self._device_name = device_name
        self._time_delay = time_delay

    def run(self):
        worker_config(LOG_QUEUE)
        local_agent: MonitoringAgent = MonitoringAgent(self._bpf_filter, self._device_name, self._time_delay)
        local_agent.run()


class Valve:

    def __init__(self, config_path: Union[str, None] = None) -> None:
        valve_logger = logging.getLogger(__name__)
        try:
            self._config: Config = Config(config_path if config_path else Path.cwd() / 'settings.conf')
            # todo create server_connection
        except AttributeError as ae:
            valve_logger.critical(str(ae))
            raise ExecError()

    def run(self):
        self.__manage_data()
        self.__manage_ue()

    def __manage_ue(self) -> None:
        # ue_worker: Process = Process(target=self.__receive_data,
        #                              args=(self.__server_con, partial(worker_config, LOG_QUEUE)))
        # ue_worker.start()
        pass

    def __manage_data(self) -> None:
        obs_worker = ObsProcess(self._config.bpf_filter, self._config.device, self._config.delay)
        #print(self._config.bpf_filter)
        obs_worker.start()
