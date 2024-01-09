import logging
import traceback

from multiprocessing import Manager, Process
from time import time, sleep
from functools import partial
from typing import Union

from utils import ExecError, worker_config, LOG_QUEUE, SharedMemory, Flags

from observer import Observer


class Scheduler:

    def __init__(self, delay_in_seconds: int):
        self.__sh_mem: SharedMemory = SharedMemory()
        self.__delay_in_sec: int = delay_in_seconds

    def __receive(self, p_queue, log_config) -> None:
        """
        Schedule log-data reading - Parsing log-data to Json-obj

        :raises ObservationError: Error is put into Queue!

        :param p_queue: Queue Object used to pass process data
        :type p_queue: manager.Queue
        :return: Nothing, retValues are put into Queue
        :rtype: None
        """
        logger = logging.getLogger(__name__)
        observer: Observer = Observer()
        delay: int = p_queue.get()
        while True:
            start_time: float = time()
            try:
                delta_time: Union[None, float] = None if 'delta_time' not in locals() else delta_time
                observer.observe_logs(delta_time)
                db_data: str = observer.observe_db(delta_time)
                net_data: str = observer.observe_network(delta_time)
                if self.__sh_mem.read() == Flags.FLAG_NEW_LOGS.value:
                    # Todo: Create Json object and put into queue
                    #p_queue.put(log_data)
                    self.__sh_mem.write(Flags.FLAG_EMPTY)
                sleep(delay)
            except KeyboardInterrupt as ke:
                break
            except ExecError as ex:
                SharedMemory().write(Flags.FLAG_WORKER_ERROR)
                break
            except Exception as e:
                logger.critical(e)
                traceback.print_exc()
            delta_time: float = time() - start_time


    def __send(self):
        pass

    def run(self):
        manager = Manager()
        p_queue = manager.Queue(-1)
        p_queue.put(self.__delay_in_sec)
        data_reader: Process = Process(target=self.__receive, args=(p_queue, partial(worker_config, LOG_QUEUE)))
        data_reader.start()

        while True:
            try:
                if flag := SharedMemory().read() == Flags.FLAG_WORKER_ERROR.value:
                    data_reader.join()
                    break
                elif flag == Flags.FLAG_NEW_LOGS.value:
                    pass
            except KeyboardInterrupt:
                raise
            finally:
                data_reader.join()
