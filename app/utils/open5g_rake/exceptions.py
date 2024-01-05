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