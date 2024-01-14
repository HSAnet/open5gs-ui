import pandas as pd

from .data_converter import DataConverterInterface


class DataConvertWeb(DataConverterInterface):

    def convert_network_data(self, network_data: pd.DataFrame):
        pass

    def convert_service_data(self, service_data: str):
        pass

