import logging
import argparse
import urllib.request
from os import linesep
from urllib import error as url_err

from scheduler import Scheduler
from utils.logger import start_logger, stop_logger

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
    logger = logging.getLogger()
    try:
        response_code: int = urllib.request.urlopen(f'{args.dest}:{'' if not args.port else args.port}').getcode()
    except url_err.HTTPError as http_err:
        response_code = http_err.code
        logger.critical(http_err)
    except url_err.URLError as u_err:
        response_code = 500
        logger.critical(u_err)
    except Exception:
        import sys, traceback
        traceback.print_exc(file=sys.stderr)
        cleanup()

    match int(str(response_code)[:1]):
        case 1:
            logger.info("Server is connecting - %d)" % response_code)
        case 2:
            logger.info("Server connection successful - %d" % response_code)
        case 3:
            logger.info("Server is redirecting - %d" % response_code)
        case 4:
            logger.warning("Client was not able to connect! - %d" % response_code)
            logger.info("Program will proceed, however logs cannot not be sent!")
        case 5:
            logger.warning("Server was unable to connect! - %d" % response_code)
            logger.info("Program will proceed, however logs cannot not be sent!")


def cleanup():
    stop_logger()
    exit(-1)


def main(delay: int = 1):
    args: argparse.Namespace = _init_args()
    start_logger('INFO' if args.verbose else 'WARNING')
    _check_rest_server(args=args)

    scheduler: Scheduler = Scheduler(delay)
    scheduler.run()


if __name__ == '__main__':
    main()
