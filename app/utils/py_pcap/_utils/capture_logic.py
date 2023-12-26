from multiprocessing import Queue

from .shared_state import Flags, LibpcapShare

class Capture:

    def __init__(self):
        self.__queue: Queue = Queue(-1)

    def get(self):
        LibpcapShare().write(Flags.FLAG_GET)
        while LibpcapShare().read() != Flags.FLAG_PUT.value:
            pass
        LibpcapShare().write(Flags.FLAG_NONE)
        return self.__queue.get()

    def put(self, data):
        self.__queue.put(data)