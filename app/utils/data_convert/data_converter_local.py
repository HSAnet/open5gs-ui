import json

import pandas as pd

from .data_converter import DataConverterInterface


class DataConverterLocal(DataConverterInterface):

    def convert_network_data(self, network_data: pd.DataFrame):
        pass

    def convert_service_data(self, service_data: str):
        """
        Function reduces information of service_data to
        simple string if a service is not running.

        :param service_data: json string to be converted
        :return: String listing any service that is not running
        """
        data = json.loads(service_data)
        return '\n'.join([f"Service: {service['Name']} not running!" for service in data['services']['service'] if service['Status'] == 'False'])