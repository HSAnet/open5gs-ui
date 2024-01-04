from enum import Enum
from multiprocessing import Queue

import pandas as pd

from .shared_state import SharedFlags, LibpcapShare


class Capture:

    def __init__(self, shared_mem: LibpcapShare):
        self.__queue: Queue = Queue(-1)
        self.__shared_mem: LibpcapShare = shared_mem

    def get(self):
        if not self.__error():
            self.__shared_mem.write(SharedFlags.FLAG_GET)
            while self.__shared_mem.read() != SharedFlags.FLAG_PUT.value:
                pass
            self.__shared_mem.write(SharedFlags.FLAG_NONE)
            return self.__queue.get()
        else:
            return self.__queue.get()

    def put(self, data):
        self.__queue.put(data)

    def __error(self):
        if self.__shared_mem.read() == SharedFlags.FLAG_ERROR:
            return True


class Packet(Enum):
    TIMESTAMP = 0
    ETHERTYPE = 1
    DIRECTION = 2
    SOURCE_MAC = 3
    DESTINATION_MAC = 4
    SOURCE_IP = 5
    SOURCE_PORT = 6
    DESTINATION_IP = 7
    DESTINATION_PORT = 8
    PROT_TYPE = 9
    OPERATION = 10
    SIZE = 11

    @property
    def d_type(self):
        return pd.StringDtype() if self.value in [0, 2, 3, 4, 5, 7, 9] else 'Int64'
