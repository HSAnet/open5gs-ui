import argparse
import urllib.request
from os import linesep
from typing import Callable

from scheduler import Scheduler

c_print: Callable[[str], None] = lambda content: print("\u001B[31m" + str(content) + "\u001B[0m")
NEWLINE: str = linesep
CURRENT_VERSION: str = '0.1.0'


def _init_args():
    help_txt: str = (f'Open5Gs-Log-Observer version {CURRENT_VERSION} {NEWLINE}'
                     f'Copyright (C) 2023 by TH-Augsburg {NEWLINE}'
                     f'Developer: Jonas Winkler {NEWLINE}'
                     f'Documentation: https:// {NEWLINE}'
                     f'GitHub: https://github.com/HSAnet/open5gs-ui {NEWLINE}'
                     f'{NEWLINE}'
                     f'Supported OS: {NEWLINE}'
                     f'\t Linux {NEWLINE}'
                     f'{NEWLINE}'
                     f'This is an open-source tool to read all log-files created by Open5Gs. {NEWLINE}'
                     f'Open5Gs uses systemd services and mongoDB to log information. Both are covered and conveyed {NEWLINE}'
                     f'{NEWLINE}'
                     f'This tool comes with ABSOLUTELY NO WARRANTY. This is free software, and you{NEWLINE}'
                     f'are welcome to redistribute it under certain conditions. See the{NEWLINE} '
                     f'GNU General Public Licence for details.{NEWLINE}')
    parser = argparse.ArgumentParser(prog="Open5Gs-Log-Observer", description=help_txt, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("dest", type=str, help="server IP or name")
    parser.add_argument("-v", "--verbose", help="increase verbosity", action="store_true")
    parser.add_argument("-q", "--quite", metavar='', help="suppress non-error messages")
    parser.add_argument("-d", "--delay", metavar='', help="use delay to reduce load on system")
    parser.add_argument("-p", "--port", metavar='', help="port of REST-Service")
    parser.add_argument("-V", "--version", metavar='', help="print version and other info and exit")
    return parser.parse_args()


def _check_rest_server(args: argparse.Namespace):
    match int(str(urllib.request.urlopen(f'{args.dest}:{'' if not args.port else args.port}').getcode())[:1]):
        # Todo log accordingly
        case 1:
            c_print('Information')
        case 2:
            c_print("Success")
        case 3:
            c_print("Redirect")
        case 4:
            c_print("Client Error")
        case 5:
            c_print("Server Error")
        case _:
            c_print("Unexpected Error")


def main(delay: int = 1):
    args: argparse.Namespace = _init_args()
    _check_rest_server(args=args)

    scheduler: Scheduler = Scheduler(delay)
    scheduler.run()


if __name__ == '__main__':
    main()
