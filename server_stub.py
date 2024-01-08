import socket
import ssl
from pathlib import Path

SSL_SERVER_PORT = 10023

private_key = Path('ssl_keys/server.key')
public_key = Path('ssl_keys/server.cert')

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=public_key.resolve(), keyfile=private_key.resolve())


def deal_with_client(connstream):
    data = connstream.recv(1024)
    # empty data means the client is finished with us
    while data:
        print(data.decode('utf-8'))
        data = connstream.recv(1024)


if __name__ == '__main__':
    server_socket = socket.socket()
    server_socket.bind(('', SSL_SERVER_PORT))
    server_socket.listen(5)

    print(f'Waiting for ssl client on port {SSL_SERVER_PORT}')

    while True:
        new_socket, from_addr = server_socket.accept()

        try:
            deal_with_client((connection := context.wrap_socket(new_socket, server_side=True)))
        finally:
            if 'connection' in locals():
                connection.shutdown(socket.SHUT_RDWR)
                connection.close()
