import abc

import pandas as pd


class DataConverterInterface(metaclass=abc.ABCMeta):

    @classmethod
    def __subclasshook__(cls, __subclass):
        return (hasattr(__subclass, 'convert_network_data') and
                callable(__subclass.export_network_data) and
                hasattr(__subclass, 'convert_service_data') and
                callable(__subclass.export_service_data) or
                NotImplemented)

    @abc.abstractmethod
    def convert_network_data(self, network_data: pd.DataFrame):
        raise NotImplemented

    @abc.abstractmethod
    def convert_service_data(self, service_data: str):
        raise NotImplemented
