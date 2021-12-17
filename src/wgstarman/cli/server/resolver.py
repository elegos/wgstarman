from ipaddress import IPv4Address, IPv6Address
import socket
from threading import Event, Thread
from typing import List, Optional, Tuple, Union
from wgstarman.cli.protocol import ErrorCode, read_message, send_message
from wgstarman.cli.protocol.messages import ErrorResponse, Message, ResolveRequest, ResolveResponse
from wgstarman.cli.protocol.utils import MessageEncDec

from wgstarman.wg_conf import WireGuardConf


class ResolverServer:
    bind_address: Union[IPv4Address, IPv6Address]
    bind_port: int
    config: WireGuardConf
    end_signal: Event

    def __init__(self, bind_address: Union[IPv4Address, IPv6Address], bind_port: int, config: WireGuardConf, end_signal: Event):
        self.bind_address = bind_address
        self.config = config
        self.bind_port = bind_port
        self.end_signal = end_signal

    def resolve(self, host_name: str) -> Optional[List[str]]:
        return next((peer.allowed_ips for peer in self.config.peers if peer.name == host_name), None)

    def listen(self):
        family = socket.AF_INET6 if isinstance(self.bind_address, IPv6Address) else socket.AF_INET
        sock = socket.create_server(
            address=(self.bind_address.exploded, self.bind_port), family=family)

        thread = Thread(target=self.listen_routine, args=[sock])
        thread.start()

        # Wait for the thread to end
        thread.join()

    def listen_routine(self, sock: socket.socket) -> None:
        threads: List[Thread] = []
        sock.settimeout(1)

        while not self.end_signal.is_set():
            try:
                sock.listen()
                connection, address = sock.accept()
                thread = Thread(target=self.request_handler, args=[connection, address])
                thread.start()
                threads.append(thread)
            except socket.timeout:
                pass

        sock.close()

        # Wait for all the threads
        for thread in threads:
            if thread.is_alive():
                thread.join()

    def request_handler(self, connection: socket.socket, address: Tuple[str, int]):
        raw_msg = read_message(connection)

        message: ResolveRequest = MessageEncDec.loads(raw_msg)

        if not message.instance_of(ResolveRequest):
            send_message(connection, ErrorResponse(
                ErrorCode.UNHANDLED_REQUEST.value, 'Unhandled request'))

        send_message(connection, ResolveResponse(
            message.host_name, self.resolve(message.host_name)))

        connection.close()
