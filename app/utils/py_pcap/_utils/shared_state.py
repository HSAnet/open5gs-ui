import mmap
from enum import Enum


class SharedFlags(Enum):
    FLAG_GET = 1
    FLAG_PUT = 2
    FLAG_NONE = 0
    FLAG_ERROR = 3


class LibpcapShare:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(LibpcapShare, cls).__new__(cls)
            cls._instance.__sh_mem = mmap.mmap(-1, 1)
        return cls._instance

    def write(self, flag: SharedFlags) -> None:
        self.__sh_mem.seek(0)
        self.__sh_mem.write_byte(flag.value)

    def read(self) -> int:
        self.__sh_mem.seek(0)
        return self.__sh_mem.read_byte()

    def close(self) -> None:
        None if self.__sh_mem.closed else self.__sh_mem.close()