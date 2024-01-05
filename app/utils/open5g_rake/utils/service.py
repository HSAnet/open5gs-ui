import regex as re
from datetime import datetime
from typing import Union, Dict
from pathlib import Path

from app.utils.open5g_rake.utils.bash import Bash, BashException, BashCommands

status_pattern = re.compile(r'Active:\s(?P<status>\w+).*?(?<=since)[\D\s]*(?P<date>[\d\s\-:]+)(.*?Memory:\s(?P<memory>[\d.]+))?.*?CPU:\s(?P<cpu>\d+)', re.DOTALL)


class Service:

    def __init__(self, service_name: str, log_file: Union[None, Path]):
        self.__service_name: str = service_name
        self.__log_file: Path = None if not log_file else log_file.parent / (log_file.name + '.log')
        print(f'Path of log-file: {self.__log_file}')
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

    @property
    def log_file(self) -> Union[None, Path]:
        return self.__log_file

    def __get_status(self) -> None:
        """
        Executes status check on service. Retrieves status, up-time, memory-usage and cpu-time.
        If an error occurred or the mandatory string wasn't found the status attribute is set to False

        :return: None
        """
        try:
            result = Bash().run(BashCommands.CTL_STATUS.value.format(service_name=self.service_name))
            x = status_pattern.search(result)
            print(x.groups())
            if match := status_pattern.search(result):
                self.__status['status'] = True if 'active' == match.group('status') else False
                self.__status['up_date'] = datetime.fromisoformat(match.group('date').strip())
                self.__status['memory'] = match.group('memory')
                self.__status['cpu'] = match.group('cpu')
            else:
                self.__status['status'] = False
        except BashException as be:
            print(be.msg)
            self.__status['status'] = False

    def __str__(self):
        self.__get_status()
        return (f"Service: {self.service_name}\n"
                f"Log-File: {'Unknown' if not self.log_file else self.log_file}\n"
                f"Status: {'Active' if self.__status['status'] else 'Inactive'}\n"
                f"{'Up' if self.__status['status'] else 'Down'} since {self.__status['up_date'].strftime('%d.%m.%Y %H:%M:%S')} {int((datetime.now() - self.__status['up_date']).total_seconds() // 60)} Minutes\n"
                f"\tCPU usage: {self.__status['cpu']} ms\n"
                f"\tMem usage: {'0' if not self.__status['memory'] else self.__status['memory']} MB")