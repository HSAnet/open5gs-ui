from contextlib import contextmanager
from subprocess import run
import fcntl
import time
from typing import List
import re


@contextmanager
def timeit_context(name):
    startTime = time.time()
    yield
    elapsedTime = time.time() - startTime
    print('[{}] finished in {} ns'.format(name, int(elapsedTime * 1000000000)))


def file_opening():
    """
    17 files
    """
    for _ in range(17):
        with open('process_logs.rst', 'r') as f:
            # Lock the file
            fcntl.lockf(f.fileno(), fcntl.LOCK_SH)
            # Read the file
            data = f.read()
            # Unlock the file
            fcntl.lockf(f.fileno(), fcntl.LOCK_UN)
            continue


def cmd_execution(service_list: List[str]):
    """
    """
    for service in service_list:
        run(f'journalctl -u {service} -b'.split(' '), capture_output=True, text=True, check=True)


status_pattern = re.compile(r'Active:\s'                     # Looking for Active: with a trailing whitespace
                            r'(?P<status>\w+)'                      # Followed by (active/inactive) and grouped
                            r'.*?'                                  # Follwed by a random amount of character
                            r'(?<=since)[\D\s]*'                    # The date is prefixed by since and an abreviation of the day
                            r'(?P<date>[\d\s\-:]+)'                 # The date consinsts of digits, whitespaces and the 
                                                                    # character [-:]. Includes trailing whitespace.
                            r'(.*?Memory:\s(?P<memory>[\d.]+))?'    # The Memory info only exists if the service is active -> ()?
                            r'.*?'                                  # Randon number of characters
                            r'CPU:\s'                               # Followed by CPU with a trailing whitespace
                            r'(?P<cpu>\d+)'                         # Only grab the digits and group it.
                            , re.DOTALL | re.VERBOSE)


log_pattern = re.compile(r'(?P<date>\d{2}/\d{2})'            # The log date consists of day and mont like 30/02
                         r'\s'                                      # Followed by a whitespace char
                         r'(?P<time>[\d:]+)'                        # The time consists of digits and ':'
                         r'.*?'                                     # Random info between time and log-level
                         r'(?P<level>DEBUG|INFO|WARNING|CRITICAL)'  # The log-level is one of the listet words
                         r':\s'                                     # Followed by a whitespace char
                         r'(?P<msg>.*)',                            # The rest of the line is the log message
                         re.MULTILINE | re.VERBOSE)


if __name__ == '__main__':
    with timeit_context('File Opening'):
        file_opening()
    with timeit_context('Command execution'):
        service_lst: List[str] = ['open5gs-amfd.service', 'open5gs-amfd.service', 'open5gs-bsfd.service',
                                  'open5gs-hssd.service', 'open5gs-mmed.service', 'open5gs-nrfd.service',
                                  'open5gs-nrfd.service', 'open5gs-pcfd.service', 'open5gs-pcrfd.service',
                                  'open5gs-scpd.service', 'open5gs-sgwcd.service', 'open5gs-sgwud.service',
                                  'open5gs-smfd.service', 'open5gs-udmd.service', 'open5gs-udrd.service',
                                  'open5gs-upfd.service', 'open5gs-webui.service']
        cmd_execution(service_list=service_lst)
