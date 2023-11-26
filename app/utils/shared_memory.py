import mmap
from enum import Enum


class Flags(Enum):
    FLAG_WORKER_ERROR = 2
    FLAG_NEW_LOGS = 1
    FLAG_EMPTY = 0


class SharedMemory:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SharedMemory, cls).__new__(cls)
            cls._instance.__sh_mem = mmap.mmap(-1, 1)
        return cls._instance

    def write(self, flag: Flags) -> None:
        self.__sh_mem.seek(0)
        self.__sh_mem.write_byte(flag.value)

    def read(self) -> int:
        self.__sh_mem.seek(0)
        return self.__sh_mem.read_byte()

    def close(self) -> None:
        None if self.__sh_mem.closed else self.__sh_mem.close()
