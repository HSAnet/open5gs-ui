import logging
from pathlib import Path
from typing import Callable, Tuple

from app.utils.bash import Bash, BashCommands


class Rake:

    def __init__(self, log_dir: str = '/var/log/open5gs') -> None:
        """
        :param log_dir: absolute path of log-directory
        :raises: ValueError if provided log_dir does not exist!
        """
        self.__log_dir: Path = Path(log_dir)
        self.__rake_logger = logging.getLogger(__name__)
        if not self.__log_dir.is_dir():
            raise ValueError(f'{str(self.__log_dir)} does not exist!')

    def rake(self, service_name: str, net_fun_name: str) -> str:
        """
        Call to retrieve logs from network-functions.
        If no log-files are found, journalctl tries to find logs.

        :param service_name: The name of the systemd-service
        :param net_fun_name: The actual name of the network-function
        :raises: BashException if execution of cmd didn't succeed
        :return:
        """
        logs, log_error = self.__file_reader(net_fun_name=net_fun_name)
        return logs if not log_error else Bash().run(
            BashCommands.CTLSERVICELOG.value.format(service_name=service_name))

    def __file_reader(self, net_fun_name: str) -> Tuple[str, bool]:
        """
        This function searches log files by the name provided in the dir setup by initialization.
        Once all the log files with that name are collected the first two are opened and data is collected.
        Systemd rotating file-logger stores new logs in .log and moves older logs in files like [.log.1 , .log.2 , .log.3]

        Open5Gs zips old logs, therefore they need to be filtered out.

        :param net_fun_name: The name of the log files (suffix is log).
        :return: Most recent logs of service.
                 And a boolean value defining whether any log file was found or not
        """
        ret_value: str = ''
        log_error: bool = True
        zipped: Callable[[Path], bool] = lambda file_name: '.gz' == file_name.suffix
        for path in [log_file for log_file in self.__log_dir.glob('*')
                     if not zipped(log_file)
                     and net_fun_name.lower() in str(log_file)][1::-1]:
            log_error = False
            try:
                with path.open() as f:
                    ret_value += f.read()
            except PermissionError:
                self.__rake_logger.warning('Permission denied, cannot access log files!\n'
                                           'Journalctl will be used to retrieve log-data.\n')
                log_error = True
                break
        return ret_value, log_error


if __name__ == '__main__':
    r = Rake()
    print(r.rake('open5gs-upfd.service', 'upf'))
