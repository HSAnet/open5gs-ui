from typing import List

from app.utils.system_d_logs.bash import Bash
from app.utils.system_d_logs.service import Service

class Rake:

    def __init__(self):
        self.__bash = Bash()
        self.__service_list: List[Service] = [Service('open5gs-upfd.service')]

    def check_status(self):
        for service in self.__service_list:
            print(service.status)


if __name__ == '__main__':
    rake = Rake()
    rake.check_status()