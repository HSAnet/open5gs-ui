from typing import List, Union
from pathlib import Path
import regex as re

from .exceptions import BashException, Open5gsException
from .utils import Service, Bash, BashCommands


class Open5GRake:

    def __init__(self, log_files_dir: Path = None):
        self.__path: Union[None, Path] = log_files_dir
        self.__service_list: List[Service] = []

        self.__get_service_list()

    def __get_service_list(self) -> None:
        """
        Function makes executes bash-command 'systemctl list-units open5gs-* --all' and parses
        result into Services which then are attached to self.__service_list.

        :raises Open5GSException: If error occurs while executing bash-command
        """
        pattern = re.compile(r"(?P<service_name>open5gs-\w+\.service).*?(?<=Open5GS\s)(?P<log_name>[A-Z]{3,4}(?:-[A-Z])?)", re.M)
        try:
            result = Bash().run(BashCommands.OPENFIVEGSERVICES.value)
            for line in (l for l in result.split('\n') if l.strip().startswith('open5gs-')):
                if match := pattern.search(line):
                    service_name = match.group('service_name')
                    log_name = match.group('log_name').lower().replace('-', '')
                    self.__service_list.append(Service(service_name, None if not self.__path else self.__path / log_name))
        except BashException as be:
            raise Open5gsException("Error occurred while trying to access service list.", prev_error=be)

    @property
    def service_list(self) -> List[Service]:
        return self.__service_list

    def rake_raw(self, time_delta: int = None):
        """
        Get raw log-data without service information.
        The result is a list containing logs which are within the timeframe

        :raises: Open5gsException when logs where not accessible!
        :param time_delta: Integer Value in seconds, determining how old the log files can be.
                           (If 10s for example, any logs data found which was logged more than 10s ago will be discarded)
        :return: List with dictionaries, the dicts contain 3 keys (date, level, msg)
        :rtype: List[Dict[str, str]]
        """
        for service in self.__service_list:
            for log in service.get_logs(time_delta):
                yield log

    def rake_json(self, time_delta: int = None) -> str:
        """
        Get log-data + service information bundled in json format.

        :raises: Open5gsException when logs where not accessible!
        :param time_delta: Integer Value in seconds, determining how old the log files can be.
                           (If 10s for example, any logs data found which was logged more than 10s ago will be discarded)
        :return: json string
        """
        return f'{{\"services\": {{\"service": [{','.join([service.to_json(time_delta) for service in self.__service_list])}]}}}}'


if __name__ == '__main__':
    rake = Open5GRake(Path('/var/log/open5gs/'))

    print(rake.rake_json(10))

