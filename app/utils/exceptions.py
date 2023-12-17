import sys


class BashException(Exception):
    def __init__(self, errno: int, msg: str, cmd: str):
        self._msg: str = msg
        self._errno: int = errno
        self.__cmd: str = cmd
        super(BashException, self).__init__('msg: {}, errno: {}, cmd: {}'.format(msg, errno, cmd))

    def __reduce__(self):
        return BashException, (self._msg, self._errno, self.__cmd)

    @property
    def msg(self) -> str:
        return f'Command: "{self.__cmd}" could not be executed! ErrNo: {self._errno} -> SysMessage: {self._msg}'

    @property
    def errno(self) -> int:
        return self._errno


# ---------------------------------------------------------------------------------------------------

class CleanupException(Exception):

    def __init__(self, msg: str, err_code: int, caught: Exception = None):
        super().__init__(msg)
        self.__msg: str = msg
        self.__prev_error: Exception = caught
        self.__err_code: int = err_code

    @property
    def previous_error(self) -> Exception:
        return '' if not self.__prev_error else self.__prev_error

    @property
    def err_code(self) -> int:
        return self.__err_code

    @property
    def msg(self) -> str:
        return f'{self.__msg} {self.previous_error}'

# ---------------------------------------------------------------------------------------------------


class ArgsException(Exception):
    def __init__(self, msg: str):
        super().__init__(msg)
        self.__msg: str = msg

    @property
    def msg(self) -> str:
        return self.__msg


# ---------------------------------------------------------------------------------------------------

class ExecError(Exception):
    """
    Error is being thrown if Execution encountered unresolvable condition
    """
    def __init__(self):
        super().__init__('')


# ----------------------------------------------------------------------------------------------------

class NetworkError(Exception):
    def __init__(self, pcap_msg: str):
        self.__pcap_msg: str = pcap_msg
        super(NetworkError, self).__init__('pcap_msg: {}'.format(pcap_msg))

    @property
    def msg(self) -> str:
        return f'An error occurred while operating with the network.\nMsg: {self.__pcap_msg}'

# ----------------------------------------------------------------------------------------------------


e_print = lambda *args, **kwargs: print(*args, file=sys.stderr, **kwargs)

