import socket
import ssl
from pathlib import Path

SSL_SERVER_PORT = 10023

server_public = Path('ssl_keys/server.crt')
server_private = Path('ssl_keys/server.key')
client_certs = Path('ssl_keys/client.crt')

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.verify_mode = ssl.CERT_REQUIRED
context.load_cert_chain(certfile=server_public.resolve(), keyfile=server_private.resolve())
context.load_verify_locations(cafile=client_certs.resolve())

server_socket = socket.socket()
server_socket.bind(('localhost', SSL_SERVER_PORT))
server_socket.listen(5)


def deal_with_client(connstream):
    data = connstream.recv(1024)
    # empty data means the client is finished with us
    while data:
        print(data.decode('ascii'))
        data = connstream.recv(1024)


if __name__ == '__main__':
    while True:
        new_socket, from_addr = server_socket.accept()
        print("Client connected: {}:{}".format(from_addr[0], from_addr[1]))
        try:
            deal_with_client((connection := context.wrap_socket(new_socket, server_side=True)))
        finally:
            if 'connection' in locals():
                #connection.shutdown(socket.SHUT_RDWR)
                connection.close()
