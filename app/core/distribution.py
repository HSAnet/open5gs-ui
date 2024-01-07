import logging
from functools import partial
from typing import Union
from pathlib import Path
from multiprocessing import Process, Manager

from app.utils import Config, ExecError, worker_config, LOG_QUEUE
from .data_stream import MonitoringAgent


class Valve:

    def __init__(self, config_path: Union[str, None] = None) -> None:
        valve_logger = logging.getLogger(__name__)
        try:
            config: Config = Config(config_path if config_path else Path.cwd() / 'settings.conf')
            self._local_agent: MonitoringAgent = MonitoringAgent(config.bpf_filter, config.device, config.delay)
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
        manager = Manager()
        p_queue = manager.Queue(-1)
        obs_worker: Process = Process(target=self._local_agent.run,
                                      args=(p_queue, partial(worker_config, LOG_QUEUE)))
        obs_worker.start()
