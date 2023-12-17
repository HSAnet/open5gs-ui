from typing import Callable, List, Union, Dict
from time import time
import logging

from parser import Parser
from utils import Bash, BashCommands, BashException, ExecError, Rake


class Observer:

    def __init__(self):
        self.__bash: Bash = Bash()
        self.__rake: Rake = Rake()
        self.__parser: Parser = Parser()
        self.__old_log: Callable[[float, float, float], bool] = lambda log_time, current_time, delta_time: False if log_time >= (current_time - delta_time) else True
        self.__systemd_logs: List[Dict[str, Union[bool, str, List[str]]]] = []
        self._obs_logger = logging.getLogger(__name__)

    @property
    def systemd_log(self) -> List[Dict[str, Union[bool, str, List[str]]]]:
        return [log for log in self.__systemd_logs if log['state_changed']]

    def __create_systemd_log(self, service_name: str, service_status: str, logs: List[str]) -> None:
        """
        Populate service dictionary

        :param service_name: Name of the service
        :param service_status: Status of the servie inactive/active (False/True)
        :param logs: Logs to be inserted if any
        """
        def get_service() -> Dict[str, Union[bool, str, List[str]]]:
            """
            By default, the log dictionary is empty, therefore new dict is inserted.

            :return: Service dict-reference
            :rtype: Dict[str, Union[bool, str, List[str]]]
            """
            if not next((service for service in self.__systemd_logs if service['name'] == service_name), None):
                self.__systemd_logs.append({'name': service_name, 'state_changed': True, 'status': service_status, 'logs': []})
            return next(service for service in self.__systemd_logs if service['name'] == service_name)

        system_log: Dict[str, Union[bool, str, List[str]]] = get_service()
        if system_log['status'] != service_status:
            system_log['state_changed'] = True
            system_log['status'] = service_status
        if logs:
            system_log['logs'] = logs
            system_log['state_changed'] = True

    def __flush_systemd_log(self):
        """
        All but the name of system-logs will be reset
        """
        for service in self.systemd_log:
            service['state_changed'] = False
            service['logs'] = []

    def observe_logs(self, delta_time: [float, None]) -> None:
        self.__flush_systemd_log()
        try:
            start_time: float = time()
            for service in self.__parser.parse_service_table(self.__bash.run(BashCommands.OPENFIVEGSERVICES.value)):
                service_logs: List[str] = []
                for logs in self.__parser.parse_service_logs(self.__rake.rake(service_name=service['service'], net_fun_name=service['name'])):
                    if not delta_time:
                        service_logs.append(logs['message'])
                    elif not self.__old_log(log_time=logs['time_stamp'], current_time=time(), delta_time=delta_time):
                        service_logs.append(logs['message'])
                        delta_time += time() - start_time
                    self.__create_systemd_log(service['name'], service['status'], service_logs)
            # Pretty print logs
            for service in self.systemd_log:
                print(f'------------------------\nServiceName: {service['name']}:\nStatus: {service['status']}\nChanged: {service['state_changed']}\n--------------------------')
                for ln, log in enumerate(service['logs']):
                    print(f'{ln}:\t{log}')
        except BashException as be:
            self._obs_logger.critical(be.msg)
            raise ExecError()
        except KeyError as ke:
            import traceback
            self._obs_logger.critical("Internal Error: %s" % ''.join(traceback.format_tb(ke.__traceback__)))
            raise ExecError()

    def observe_db(self, delta_time: float):
        pass

    def observe_network(self, delta_time: float):
        pass
