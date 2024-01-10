import logging
from typing import Union
from pathlib import Path
from multiprocessing import Process, Queue

from ..utils import Config, ExecError, worker_config, LOG_QUEUE
from .data_stream import MonitoringAgent


class ObsProcess(Process):

    def __init__(self, config_queue: Queue):
        super(ObsProcess, self).__init__()
        self._config_queue: Queue = config_queue

    def run(self):
        worker_config(LOG_QUEUE)
        config: Config = self._config_queue.get()
        local_agent: MonitoringAgent = MonitoringAgent(config)
        local_agent.run()


class Valve:

    def __init__(self, config_path: Union[str, None] = None) -> None:
        valve_logger = logging.getLogger(__name__)
        try:
            self._config: Config = Config(config_path if config_path else Path.cwd() / 'settings.conf')
            self._config_queue: Queue = Queue(-1)
        except AttributeError as ae:
            # Config could not be initialised
            valve_logger.critical(str(ae))
            raise ExecError()

    def run(self):
        self._config_queue.put(self._config)
        self.__manage_data()
        self._config_queue.put(self._config)
        self.__manage_ue()

    def __manage_ue(self) -> None:
        # ue_worker: Process = Process(target=self.__receive_data,
        #                              args=(self.__server_con, partial(worker_config, LOG_QUEUE)))
        # ue_worker.start()
        pass

    def __manage_data(self) -> None:
        obs_worker = ObsProcess(self._config_queue)
        obs_worker.start()
