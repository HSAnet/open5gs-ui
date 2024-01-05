import regex as re
from datetime import datetime
from typing import Union, Dict
from pathlib import Path

from .bash import Bash, BashException, BashCommands

status_pattern = re.compile(r'Active:\s(?P<status>\w+).*?(?<=since)[\D\s]*(?P<date>[\d\s\-:]+).*?Memory:\s(?P<memory>[\d.]+).*?CPU:\s(?P<cpu>\d+)', re.DOTALL)


class Service:

    def __init__(self, service_name: str, log_file: Path, network_function_name: str):
        self.__service_name: str = service_name
        self.__log_name: Path = log_file / network_function_name
        self.__status: Union[None, Dict[str, Union[str, datetime, None, bool]]] = {
                    'status': False,
                    'up_date': None,
                    'memory': None,
                    'cpu': None
                }

    @property
    def service_name(self) -> str:
        return self.__service_name

    @property
    def status(self) -> Union[None, Dict[str, Union[str, datetime, None, bool]]]:
        self.__get_status()
        return self.__status

    def __get_status(self) -> None:
        """
        Executes status check on service. Retrieves status, up-time, memory-usage and cpu-time.
        If an error occurred or the mandatory string wasn't found the status attribute is set to False

        :return: None
        """
        try:
            result = Bash().run(BashCommands.CTL_STATUS.value.format(service_name=self.service_name))
            if match := status_pattern.search(result):
                self.__status['status'] = True if 'active' == match.group('status') else False
                self.__status['up_date'] = datetime.fromisoformat(match.group('date').strip())
                self.__status['memory'] = match.group('memory')
                self.__status['cpu'] = match.group('cpu')
            else:
                self.__status['status'] = False
        except BashException:
            self.__status['status'] = False
