from typing import Callable

import libpcap as pcap


class NetworkError(Exception):
    def __init__(self, pcap_msg: str):
        self.__pcap_msg: str = pcap_msg
        super(NetworkError, self).__init__('pcap_msg: {}'.format(pcap_msg))

    @property
    def msg(self) -> str:
        return f'An error occurred while operating with the network.\nMsg: {self.__pcap_msg}'

# ----------------------------------------------------------------------------------------------------


class SetupError(Exception):
    def __init__(self, pcap_msg: str):
        self.__pcap_msg: str = pcap_msg
        super(SetupError, self).__init__('pcap_msg: {}'.format(pcap_msg))

    @property
    def msg(self) -> str:
        return f'An error occurred while operating with the network.\nMsg: {self.__pcap_msg}'

# ----------------------------------------------------------------------------------------------------


class CaptureError(Exception):
    def __init__(self, pcap_msg: str):
        self.__pcap_msg: str = pcap_msg
        super(CaptureError, self).__init__('pcap_msg: {}'.format(pcap_msg))

    @property
    def msg(self) -> str:
        return f'An error occurred while operating with the network.\nMsg: {self.__pcap_msg}'


err_to_str: Callable[[], str] = lambda err_buff: err_buff.value.decode('utf-8', 'ignore')
dev_to_str: Callable[[], str] = lambda device: device.decode("utf-8")
dev_err: Callable[[], str] = lambda device: pcap.geterr(device).decode("utf-8", "ignore")