import sys
import logging
import multiprocessing
from typing import Dict
import logging.handlers
from asyncio import Queue
from functools import partial
from multiprocessing import Process
from logging.config import dictConfig

# ---------------------------------

LOG_QUEUE: Queue = multiprocessing.Queue(-1)
LISTENER_PROC: Process

# ---------------------------------


def filter_stdout(level):
    """
    Filter all logs higher than provided level (provided level excluded)
    Python logging levels are build like dictionary e.g. {"DEBUG": 10, "INFO": 20, "WARNING": 30...}

    :param level: The level (exclusive) from where to start filtering
    :return: Function to evaluate whether log meets condition
    """
    return lambda record: (lambda lvl: record.levelno <= lvl)(getattr(logging, level))


def filter_stderr(level):
    """
    Filter all logs lower than provided level (provided level excluded)
    Python logging levels are build like dictionary e.g. {"DEBUG": 10, "INFO": 20, "WARNING": 30...}

    :param level: The level (exclusive) from where to start filtering
    :return: Function to evaluate whether log meets condition
    """
    return lambda record: (lambda lvl: record.levelno >= lvl)(getattr(logging, level))


def _setup_listener(level="INFO") -> None:
    """
    Configuration for logger.
    Logs are written to stdout if <= WARNING
    Logs are written to stderr if >= WARNING
    This allows user to pipe stderr to file.

    :param level: Filter all messages bellow this level
    """
    filters: Dict[str, str] = {x.rsplit('_')[-1]: f'{__name__}.{x}' for x in dir(sys.modules.get(__name__)) if 'filter' in x}
    dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "filters": {
            "warning_and_below": {
                "()": filters['stdout'],
                "level": "WARNING"
            },
            "warning_and_above": {
                "()": filters['stderr'],
                "level": "WARNING"
            }
        },
        "formatters": {
            "standard": {
                "format": "%(asctime)s : [%(levelname)s] : %(name)s : %(funcName)s() : %(message)s",
                "datefmt": "%d.%m.%Y-%H:%M:%S"
            }
        },
        "handlers": {
            "stdout": {
                "class": "logging.StreamHandler",
                "formatter": "standard",
                "level": level,
                "stream": "ext://sys.stdout",
                "filters": ["warning_and_below"]
            },
            "stderr": {
                "class": "logging.StreamHandler",
                "formatter": "standard",
                "level": level,
                "stream": "ext://sys.stderr",
                "filters": ["warning_and_above"]
            },
        },
        "loggers": {
            "": {
                "level": level,
                "handlers": [
                    "stdout",
                    "stderr"
                ],
            }
        }
    })


def _listener_process(queue, log_config):
    log_config()
    while True:
        try:
            record = queue.get()
            if record is None:
                break
            logger = logging.getLogger(record.name)
            logger.handle(record)
        except KeyboardInterrupt:
            stop_logger()
            break
        except Exception:
            import sys, traceback
            traceback.print_exc(file=sys.stderr)


def worker_config(queue):
    h = logging.handlers.QueueHandler(queue)
    root = logging.getLogger()
    root.addHandler(h)
    root.setLevel(logging.DEBUG)


def stop_logger() -> None:
    """
    Cleanup Logger when program ends or fails

    :param listener_proc: The Process listening for logs
    :param log_queue: The queue used for logging
    :return: None
    """
    LOG_QUEUE.put_nowait(None)
    try:
        LISTENER_PROC.join()
    except NameError:
        pass    # Ignore -> Process was not initiated yet


def start_logger(level: str) -> None:
    """
    Setup multiprocessing logger and configuration.
    Returns queue and configuration for logging.

    Started logger must be stopped as well!
    """
    LISTENER_PROC = multiprocessing.Process(target=_listener_process,
                                            args=(LOG_QUEUE, partial(_setup_listener, level)))
    LISTENER_PROC.start()
    worker_config(LOG_QUEUE)
