import json
import socket

import pandas as pd
from socket import gethostbyaddr

from .data_converter import DataConverterInterface

UNIT_MAP = [
    (1 << 50, ' PB'),
    (1 << 40, ' TB'),
    (1 << 30, ' GB'),
    (1 << 20, ' MB'),
    (1 << 10, ' KB'),
    (1, (' byte', ' bytes')),
]


class DataConverterLocal(DataConverterInterface):

    def _convert_bytes_to_display(self, amount_bytes: str):
        bytes_int: int = int(amount_bytes)
        for factor, suffix in UNIT_MAP:
            if bytes_int >= factor:
                break
        amount = int(bytes_int / factor)

        if isinstance(suffix, tuple):
            singular, multiple = suffix
            if amount == 1:
                suffix = singular
            else:
                suffix = multiple
        return str(amount) + suffix

    def convert_network_data(self, network_data: pd.DataFrame):
        pd.set_option('display.max_columns', 500)
        pd.set_option('display.width', 2000)
        df = network_data.groupby(['Source_ip', 'Destination_ip', 'Direction'], as_index=False)['Size'].sum()

        def convert_to_string(x):
            try:
                return f"{host if len(host := gethostbyaddr(x)[0]) <= 10 else f'{host[:10]}...'}"
            except socket.herror:
                return 'Unknown Host'

        df['Size'] = df.Size.map(self._convert_bytes_to_display)
        df['Source_Host'] = df.Source_ip.map(convert_to_string)
        df['Dest_Host'] = df.Destination_ip.map(convert_to_string)

        return pd.DataFrame(df,
                            columns=['Direction', 'Source_ip', 'Source_Host', 'Destination_ip', 'Dest_Host', 'Size'])

    def convert_service_data(self, service_data: str):
        """
        Function reduces information of service_data to
        simple string if a service is not running.

        :param service_data: json string to be converted
        :return: String listing any service that is not running
        """
        return '\n'.join([f"Service: {service['Name']} not running!"
                          for service in json.loads(service_data)['services']['service']
                          if service['Status'] == 'False'])
