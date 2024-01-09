from subprocess import run, CalledProcessError, CompletedProcess
from typing import List
from enum import Enum

from app.utils.open5g_rake.utils.exceptions import BashException


class BashCommands(Enum):
    OPENFIVEGSERVICES: str = 'systemctl list-units open5gs-* --all'
    CTLSERVICELOG: str = 'journalctl -u {service_name} -b'
    CTL_STATUS: str = 'systemctl status {service_name}'


class Bash:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Bash, cls).__new__(cls)
        return cls._instance

    def run(self, cmd: str) -> str:
        try:
            exec_cmd: List[str] = cmd.split(' ')
            proc_data: CompletedProcess = run(exec_cmd, capture_output=True, text=True, check=True)
        except CalledProcessError as cpe:
            # Did not find any information about this error.
            # It does however perfectly execute the command but doesn't allow accessing stdout on proc_data
            return cpe.output
        except FileNotFoundError as fnfe:
            raise BashException(errno=fnfe.errno, msg=fnfe.strerror, cmd=cmd)
        return proc_data.stdout

