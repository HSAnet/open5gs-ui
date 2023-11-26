from subprocess import run, CalledProcessError, CompletedProcess
from typing import List
from enum import Enum

from app.utils.exceptions import BashException


class BashCommands(Enum):
    OPENFIVEGSERVICES: str = 'systemctl list-units open5gs-* --all'
    CTLSERVICELOG: str = 'journalctl -u {service_name} -b'


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
            raise BashException(errno=cpe.returncode, msg=cpe.stderr, cmd=cmd)
        except FileNotFoundError as fnfe:
            raise BashException(errno=fnfe.errno, msg=fnfe.strerror, cmd=cmd)
        return proc_data.stdout

