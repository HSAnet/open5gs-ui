import sys


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


e_print = lambda *args, **kwargs: print(*args, file=sys.stderr, **kwargs)

