import os
import ssl
import traceback
from pathlib import Path
from socket import socket
from typing import Dict, Callable

from .configurator import Config

class Server:
    # Todo: Unclear how to proceed
    # Either create a socket (only connection)
    # - or -
    # Use REST-API on Django (requires polling  -_-)
    # - or -
    # Use REST-API and socket (Post data to REST and get-data (new ues via socket)
    # - or -
    # maybe there is a way to implement an asynchron REST-GET (like client: get() [blocking], server... waiting till data, fill request -
    #
    # Anyhow, REST-API calls are better done with "request-packet" not "sockets"
    def __init__(self, config: Config):
        if not config.server or not config.port:
            print(config.server, config.port)
            raise AttributeError("Server configuration not valid!\n"
                                 "Minimal setup requires Server IP/URL and Port.")
        if not config.port.isdigit():
            raise AttributeError(f'Port number "{config.port}" not valid!')
        self.__server: str = config.server
        self.__port: int = int(config.port)
        self.__config: Config = config

        self._validate_ssl_config()
        self._ssl_context = None
        self._connection = None

    def _validate_ssl_config(self) -> None:
        try:
            key_mapping: Dict[str, Path] = dict()
            for config_fun in [cls_attr for cls_attr in dir(self.__config) if 'key' in cls_attr]:
                try:
                    path_valid: Callable[[Path], bool] = lambda path: path.exists and path.is_file() and os.access(path, os.R_OK)
                    if not path_valid(key_file_path := Path(getattr(self.__config, config_fun)).resolve()):
                        raise NameError(f'Config-Error: {config_fun.title()} -> {key_file_path} not accessible!')
                    key_mapping |= {config_fun: key_file_path}
                except AttributeError as ae:
                    # Config file corrupt
                    # Todo: Log error!
                    # Exit SSL-config, try http connection
                    return
                except NameError as ne:
                    # log error
                    # exit ssl-config, try http connection
                    return
            self._ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=key_mapping['server_key'])
            self._ssl_context.load_cert_chain(certfile=key_mapping['public_key'], keyfile=key_mapping['private_key'])

            try:
                new_socket = socket()
                new_socket.settimeout(10)
                self._connection = self._ssl_context.wrap_socket(new_socket, server_side=False, server_hostname=self.__config.server_sni)
                self._connection.connect((self.__server, self.__port))
                # todo: log connection established
                # Validate ssl-certificate
                cert = self._connection.getpeercert()
                print(cert)
                if not cert or ssl.match_hostname(cert, self.__server):
                    raise ConnectionError(f'Invalid SSL-certificate for host {self.__server}!\nDisconnecting...')
            except TimeoutError as te:
                raise ConnectionAbortedError('Server handshake timout!\nMake sure the server is up and running.\nExiting...')
        except:
            print(traceback.format_exc())