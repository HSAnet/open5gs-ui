from pathlib import Path
import regex as re


class Config:

    def __init__(self, config_file: Path):
        """

        :raises AttributeError: if provided config-file does not exist / permission to access not granted or
                                is not readable and other File related OSErrors
        :param config_file: Path to the config file
        """
        if not (config_file.exists() and config_file.is_file()):
            raise AttributeError('Config file not found!')
        self._config_file = config_file
        self._line_pattern = re.compile(r'^(?P<key>\w+)\s=\s(?P<value>\S*)', re.M)
        self._parse_config_file()

    def _parse_config_file(self) -> None:
        """
        Method parses instance-level config-file and creates attributes
        to access the config-file values like the following:

            .conf [File]
                Attr = Value
            Config() [class]
                Config().attr (returns Value)

        :raises AttributeError: if config file could not be access due to permission or other OSErrors
        """
        try:
            with self._config_file.open() as file:
                for line_nr, line in enumerate(file):
                    if match := self._line_pattern.search(line):
                        setattr(self, match.group('key').lower(), match.group('value'))
                    elif not line.startswith('#'):
                        # Todo: log this - Config line was not parsed
                        print(f'[ConfigParser] - Error - Line {line_nr + 1}: "{line.strip()}" ignored!')
        except (PermissionError, OSError, AttributeError):
            raise AttributeError('Config file could not be accessed!')

    def has(self, attribute: str) -> bool:
        """
        Check if config contains value you are looking for.
        Either use this method or access it with try - except.

        :param attribute: The attribute to look for
        :return: True if value is found, else False
        """
        if attribute in self.__dict__:
            return True

# if __name__ == '__main__':
#     conf: Config = Config(Path('./settings.conf'))
#     print(dir(conf))
#     # Either access values like this
#     print('BPF_Filter not found!' if not conf.has('bpf_filter') else conf.bpf_filter)
#     # - or - like this
#     try:
#         print(conf.bpf_filter)
#     except AttributeError:
#         print('BPF_Filter not found!')