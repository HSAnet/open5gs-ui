from typing import List
from pathlib import Path
import regex as re

from app.utils.open5g_rake.utils.service_parser import ParsePattern
from app.utils.open5g_rake.exceptions import BashException
from app.utils.open5g_rake.utils.bash import Bash, BashCommands
from app.utils.open5g_rake.utils.service import Service





class Open5GRake:

    def __init__(self, log_files_dir: Path = None):
        self.__path: Path = log_files_dir
        self.__service_list: List[Service]

        self.__get_service_list()

    def __get_service_list(self) -> None:
        pattern = re.compile(r"(?P<service_name>open5gs-\w+\.service).*?(?<=Open5GS\s)(?P<log_name>[\w\-]+)", re.M)
        try:
            result = Bash().run(BashCommands.OPENFIVEGSERVICES.value)
            for line in (l for l in result.split('\n') if l.strip().startswith('open5gs-')):
                if match := pattern.search(line):
                    service_name = match.group('service_name')
                    log_name = match.group('log_name').lower().replace('-', '')
                    print(f'Service_name: {service_name}\nLog_name: {log_name}')
        except BashException:
            # Todo: Kill process
            print('Error occurred.. end program!')

    def check_status(self):
        for service in self.__service_list:
            print(service.status)


if __name__ == '__main__':
    rake = Open5GRake()