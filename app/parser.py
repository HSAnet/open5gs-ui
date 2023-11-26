import time
from datetime import datetime
from typing import Union, Dict, Callable, Iterable
import regex as re

from utils import ParsePattern


class Parser:
    def __init__(self):
        self.__str_to_float: Callable[[re.Match], float] = \
            lambda date_str: time.strptime(f'{date_str.group('day')}/{date_str.group('month')}/{datetime.now().year} {date_str.group('time')}',
                                           '%d/%b/%Y %H:%M:%S')

    def parse_service_table(self, table_data: str) -> Iterable[Dict[str, Union[bool, str]]]:
        try:
            return ({'service': service.group('service'),
                     'status': True if 'active' == service.group('status') else False,
                     'name': service.group('s_name').title()}
                    for service in ParsePattern.SERVICEPATTERN.value.finditer(table_data))
        except AttributeError as ae:
            # Todo: should return proper error
            print('a1')
            print(ae)
        except IndexError as ie:
            print('1')
            print(ie)

    def parse_service_logs(self, service_log_data: str) -> Iterable[Dict[str, Union[float, str]]]:
        try:
            return ({'time_stamp': time.mktime(self.__str_to_float(ParsePattern.TIMESTAMP.value.search(log_message))),
                     'message': log_message}
                    for log_message in service_log_data.split('\n') if log_message)
        except AttributeError as ae:
            # Todo: should return proper error
            print('b2')
            print(ae)
        except IndexError as ie:
            print('2')
            print(ie)
