from pathlib import Path
from typing import Callable, Tuple


class FileLogs:

    def __init__(self, log_dir: str):
        self.__log_dir: Path = Path(log_dir)
        if not self.__log_dir.is_dir():
            raise ValueError(f'{str(self.__log_dir)} does not exist!')

    def get_logs(self, service_name: str) -> Tuple[str, bool]:
        """
        This function searches log files by the name provided in the dir setup by initialization.
        Once all the log files with that name are collected the first two are opened and data is collected.
        Systemd rotating file-logger stores new logs in .log and moves older logs in files like [.log.1 , .log.2 , .log.3]

        Open5Gs zips old logs, therefore they need to be filtered out.

        :param service_name: The name of the log files (suffix is log).
        :return: Most recent logs of service.
                 And a boolean value defining whether any log file was found or not
        """
        ret_value: str = ''
        file_found: bool = False
        zipped: Callable[[Path], bool] = lambda file_name: '.gz' == file_name.suffix
        for path in [log_file for log_file in self.__log_dir.glob('*') if not zipped(log_file) and service_name.lower() in str(log_file)][1::-1]:
            file_found = True
            with path.open() as f:
                ret_value += f.read()
        return ret_value, file_found


if __name__ == '__main__':
    x = FileLogs('/var/log/open5gs')
    print(x.get_logs('upf')[0])

    s = ['Hello', 'Hello1', 'Hello2', 'Hello3']
    print(s[1::-1])
