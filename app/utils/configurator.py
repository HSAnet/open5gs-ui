import regex as re
from enum import Enum
from typing import Dict, List, Union
from pathlib import Path


class _Pattern(Enum):
    DELAY = re.compile(r'^Delay[\s=]+(?P<delay>\d+)', re.MULTILINE)
    SERVER = re.compile(r'^Server[\s=]+(?P<server>(?:25[0-5]|(?:2[0-4]|1\d|[1-9]|)\d\.?\b){4})', re.MULTILINE)
    PORT = re.compile(r'^Port[\s=]+(?P<port>\d+)', re.MULTILINE)
    CERT = re.compile(r'^Cert[\s=]+(?P<cert>.+)', re.MULTILINE)
    BPF = re.compile(r'^BPF-Filter[\s=]+(?P<bpf>.+)?', re.MULTILINE)
    LOG_DIR = re.compile(r'^Dir[\s=]+(?P<log_dir>.+)', re.MULTILINE)

    @classmethod
    def parse(cls, string: str):
        return {m[0]: m[1] for m in (pattern.in_string(string) for pattern in _Pattern) if m}

    def in_string(self, string: str) -> Union[None, List[str]]:
        if match := self.value.search(string):
            return [(key := self.name.lower()), match.group(key)]


class _Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(_Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class Config(metaclass=_Singleton):

    _instance = None

    def __init__(self, config_file: Path = Path.cwd() / 'settings.conf'):
        if not (config_file.exists() and config_file.is_file()):
            raise AttributeError('Config file not found!')
        self._config_file = config_file
        self._settings: Dict[str, str] = dict()

        self._parse_config_file()

    def _parse_config_file(self):
        try:
            with self._config_file.open() as file:
                for line in file:
                    self._settings |= _Pattern.parse(line)
        except (PermissionError, OSError, AttributeError):
            raise AttributeError('Config file could not be accessed!')

    @property
    def bpf_filter(self):
        return self._settings["bpf_filter"]

    @property
    def delay(self):
        return self._settings["delay"]

    @property
    def cert(self):
        return self._settings["cert"]

    @property
    def log_dir(self):
        return self._settings["log_dir"]

    @property
    def port(self):
        return self._settings["port"]

    @property
    def server(self):
        return self._settings["server"]

    # Neet Idea, but not really practical
    #
    # @staticmethod
    # def _create_new_method(key: str):
    #     def method(self):
    #         return self._settings[key]
    #     return method
    #
    # def _setup_methods(self):
    #     for key in self._settings.keys():
    #         setattr(self, f'get_{key}', MethodType(self._create_new_method(key), self))