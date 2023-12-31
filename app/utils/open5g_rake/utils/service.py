import json
import regex as re
from pathlib import Path
from datetime import datetime, timedelta
from typing import Union, Dict, List, Callable

from .exceptions import Open5gsException, BashException
from .bash import Bash, BashCommands

status_pattern = re.compile(r'Active:\s(?P<status>\w+).*?(?<=since)[\D\s]*(?P<date>[\d\s\-:]+)(.*?Memory:\s(?P<memory>[\d.]+))?.*?CPU:\s(?P<cpu>\d+)', re.DOTALL)
log_pattern = re.compile(r'(?P<date>\d{2}/\d{2})\s(?P<time>[\d:]+).*?(?P<level>DEBUG|INFO|WARNING|CRITICAL):\s(?P<msg>.*)', re.MULTILINE)


class Service:

    def __init__(self, service_name: str, log_file: Union[None, Path]):
        self.__service_name: str = service_name
        self.__log_file: Path = None if not log_file else log_file.parent / (log_file.name + '.log')
        self.__file_access: bool = True
        self.__status: Union[None, Dict[str, Union[str, datetime, None, bool]]] = {
            'status': False,
            'since': None,
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
            if match := status_pattern.search(result):
                self.__status['status'] = True if 'active' == match.group('status') else False
                self.__status['since'] = match.group('date').strip()
                self.__status['memory'] = match.group('memory')
                self.__status['cpu'] = match.group('cpu')
            else:
                self.__status['status'] = False
        except BashException:
            self.__status['status'] = False

    def get_logs(self, time_delta: Union[int, None]) -> List[Dict[str, Union[datetime, str]]]:
        """
        Access service-log data via file-reader or journalctl.
        If provided path is not accessible or permission denied journalctl is executed.

        :raises BashException: If journalctl command encountered error
        :return: logs as dictionary
        """
        if self.__file_access:
            try:
                with self.log_file.open() as file:
                    return self.__parse_log_data(file.read(), time_delta)
            except (PermissionError, OSError, AttributeError) as e:
                # User might not have permission to access the file
                # OS might encounter error when opening the file
                # The provided path is not valid or is None
                # Disable file-reading and call function to access log data via journalctl
                self.__file_access = False
                return self.get_logs(time_delta=time_delta)
        else:
            # Raises BashException if error while executing command
            try:
                return self.__parse_log_data(Bash().run(BashCommands.CTLSERVICELOG.value.format(service_name=self.service_name)), time_delta)
            except BashException as be:
                raise Open5gsException(msg='Logs cannot be retrieved!', prev_error=be)

    def __parse_log_data(self, log_data: str, time_delta: Union[int, None]) -> List[Dict[str, Union[datetime, str]]]:
        """
        Function turns raw log-string (multiple lines) into python dictionary

        :param log_data: string containing log data
        :param time_delta: max age (in seconds) of log
        :return: list of dictionaries containing 3 keys (date, level, msg)
        """
        is_new_log: Callable[[datetime], bool] = lambda lg_ts: True if not time_delta else (
                lg_ts > (datetime.now() - timedelta(seconds=time_delta)))
        return [{'date': log_date.strftime('%Y-%m-%d %H:%M:%S'),
                 'level': match.group('level'),
                 'msg': match.group('msg')
                 } for line in log_data.splitlines() if (match := log_pattern.search(line)) and
                is_new_log((log_date := datetime.fromisoformat(f'{datetime.now().year}' 
                                                               f'{match.group('date').replace('/', '')} '
                                                               f'{match.group('time')}')))]

    def to_json(self, time_delta: Union[int, None]) -> str:
        return (f"{{\"Name\": \"{self.service_name}\",\"Status\": \"{self.status['status']}\",\""
                f"{'Up' if self.__status['status'] else 'Down'} "
                f"since\": \"{self.__status['since']}\","
                f"\"CPU usage\": \"{self.__status['cpu']}\","
                f"\"Mem usage\": \"{'0' if not self.__status['memory'] else self.__status['memory']}\","
                f"\"logs\": {json.dumps([log for log in self.get_logs(time_delta)])}"
                f"}}")

    def __str__(self):
        return (f"Service: {self.service_name}\n"
                f"Log-File: {'Unknown' if not self.log_file else self.log_file}\n"
                f"Status: {'Active' if self.status['status'] else 'Inactive'}\n"
                f"{'Up' if self.__status['status'] else 'Down'} since {self.__status['since'].strftime('%Y-%m-%d %H:%M:%S')} {int((datetime.now() - self.__status['since']).total_seconds() // 60)} Minutes\n"
                f"\tCPU usage: {self.__status['cpu']} ms\n"
                f"\tMem usage: {'0' if not self.__status['memory'] else self.__status['memory']} MB")
