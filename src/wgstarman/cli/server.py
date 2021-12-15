import ipaddress
import logging
import signal
import socket
from argparse import (SUPPRESS, ArgumentDefaultsHelpFormatter, ArgumentParser,
                      Namespace, _SubParsersAction)
from ipaddress import IPv4Address, IPv6Address, IPv6Interface
from threading import Event, Lock, Thread
from typing import Dict, List, Tuple, Union

from cryptography.fernet import Fernet, InvalidToken

from wgstarman.cli.common import CLICommand
from wgstarman.cli.protocol import (AcknowledgeResponse, ErrorCode,
                                    ErrorResponse, IPAddressHoldRequest,
                                    IPAddressRequest, IPAddressResponse,
                                    Message, MessageEncDec, read_message, send_invalid_token_message,
                                    send_message)
from wgstarman.cli.wgstarman_conf import WGStarManConf
from wgstarman.decorators import syncronized
from wgstarman.wg_conf import Interface, Peer, WireGuardConf
from wgstarman.wgcli.exec import WireGuardCLI

LOG_FORMAT = '%(asctime)23s %(levelname)8s %(message)s'

conf_edit_lock = Lock()


class ServerCommand(CLICommand):
    task_name = 'server'

    config: WireGuardConf
    enc_key: bytes
    end_signal: Event
    temp_address_assoc: Dict[str, Union[IPv4Address, IPv6Address]]  # TODO introduce a timeout

    ipv6_interface: IPv6Interface
    device_name: str

    @property
    def inverse_temp_address_assoc(self) -> Dict[str, str]:
        return {str(v): k for k, v in self.temp_address_assoc.items()}

    def __init__(self) -> None:
        self.temp_address_assoc = {}

    def configure_logging(self, args: Namespace) -> None:
        logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG if args.debug else logging.INFO)

    def decorate_subparsers(self, subparsers: _SubParsersAction) -> None:
        parser: ArgumentParser = subparsers.add_parser(
            self.task_name, formatter_class=ArgumentDefaultsHelpFormatter)
        required = parser.add_argument_group('required')
        optional = parser.add_argument_group('optional')

        required.add_argument('--ipv6-network', required=True, default=SUPPRESS,
                              help='the IPv6 network to use for the VPN, i.e. fdxx:xxxx:xxxx:yyyy:zzzz:zzzz::/64')
        optional.add_argument('--device-name', required=False, default='wg0',
                              help='the name of both the network device and the configuration file')
        optional.add_argument('--listen-address-4', required=False, default='0.0.0.0',
                              help='the address IPv4 on which the address manager will listen on')
        optional.add_argument('--listen-address-6', required=False, default='::',
                              help='the address IPv6 on which the address manager will listen on; will overwrite --listen-address-4 if enabled; requires --enable-listen-ipv6')
        optional.add_argument('--listen-port', required=False, default=1194, type=int,
                              help='the port on which WireGuard (UDP) and the address manager (TCP) will listen on')
        optional.add_argument('--enable-listen-ipv6', required=False, default=False, action='store_true',
                              help='enable the address manager to listen on ipv6')
        optional.add_argument('--refresh-psk', required=False, default=False, action='store_true',
                              help='force the refresh of the pre-shared key')
        optional.add_argument('--debug', required=False, default=False, action='store_true',
                              help='enable debug log')

    def can_handle(self, task_name: str) -> bool:
        return self.task_name == task_name

    def handle(self, args: Namespace) -> None:
        self.ipv6_interface = IPv6Interface(args.ipv6_network)
        self.device_name = args.device_name

        self.end_signal = Event()

        def sigint_handler(*args):
            if not self.end_signal.is_set():
                self.end_signal.set()
        signal.signal(signal.SIGINT, sigint_handler)

        # Generate an (updated) configuration
        self.config = WireGuardConf.parse(self.device_name)
        if self.config:
            interface = Interface(
                private_key=self.config.interface.private_key,
                address=self.config.interface.address,
                listen_port=args.listen_port,
                fw_mark=self.config.interface.fw_mark,
            )
            peers = self.config.peers
        else:
            interface = Interface(
                private_key=WireGuardCLI.gen_private_key(),
                address=[str(self.ipv6_interface.network[1])],
                listen_port=args.listen_port,
                fw_mark=None,
            )
            peers = []

        self.config = WireGuardConf(interface, peers)

        self.config.save(self.device_name)

        srv_conf = WGStarManConf.load()
        public_key = WireGuardCLI.get_public_key(self.config.interface.private_key)
        self.enc_key = srv_conf.get_preshared_key(public_key).encode('utf8')
        psk_str = self.enc_key.decode('utf8')
        if not self.enc_key or args.refresh_psk:
            self.enc_key = Fernet.generate_key()
            psk_str = self.enc_key.decode('utf8')
            srv_conf.set_preshared_key(public_key, psk_str)

        if not WireGuardCLI.up(self.device_name):
            return

        print(f'\n\nPRE-SHARED KEY: {psk_str}\n')

        self.listen(args)

    @syncronized(conf_edit_lock)
    def _routine_ip_address(self, req: IPAddressRequest) -> Message:
        public_key = WireGuardCLI.get_public_key(self.config.interface.private_key)
        current_peer = next(
            (peer for peer in self.config.peers if peer.public_key == req.public_key), None)

        if current_peer:
            return IPAddressResponse(
                server_public_key=public_key,
                peer_address=current_peer.allowed_ips[0],
                peer_allowed_ips=str(self.ipv6_interface.network),
            )

        if req.public_key in self.temp_address_assoc:
            return IPAddressResponse(
                server_public_key=public_key,
                peer_address=str(self.temp_address_assoc[public_key]),
                peer_allowed_ips=str(self.ipv6_interface.network),
            )

        used_ip_addresses = [ipaddress.ip_address(self.config.interface.address[0].split('/')[0])]
        used_ip_addresses.extend([ipaddress.ip_address(peer.allowed_ips[0].split('/')[0])
                                  for peer in self.config.peers])
        used_ip_addresses.extend(self.temp_address_assoc.values())

        ip_address = next(
            (
                addr for addr in self.ipv6_interface.network

                if addr not in used_ip_addresses
                and addr != self.ipv6_interface.network[0]
            ),
            None
        )

        if not ip_address:
            message = 'No address available, the network is full.'
            logging.error(message)

            return ErrorResponse(error_code=ErrorCode.NETWORK_IS_FULL.value, message=message)

        self.temp_address_assoc[req.public_key] = ip_address

        logging.info(f'Offering IP address {ip_address} to {req.public_key}')

        return IPAddressResponse(
            server_public_key=public_key,
            peer_address=str(ip_address),
            peer_allowed_ips=str(self.ipv6_interface.network),
        )

    @syncronized(conf_edit_lock)
    def _routine_ip_address_hold(self, req: IPAddressHoldRequest) -> Message:
        ip_address = req.ip_address

        public_key = self.inverse_temp_address_assoc[ip_address] if ip_address in self.inverse_temp_address_assoc else None
        peer: Peer = next(
            (peer for peer in self.config.peers if peer.allowed_ips[0] == ip_address), None)

        if not public_key and not peer:
            logging.warning(
                f'A user attempted to hold the following unreleased IP address: {ip_address}')
            return ErrorResponse(ErrorCode.INVALID_IP_ADDRESS.value, 'The requested IP has not been assigned by this server')

        if peer:
            return AcknowledgeResponse()

        peer = Peer(public_key=public_key, allowed_ips=[ip_address])

        logging.info(f'Registering IP address {ip_address} to {public_key}')

        self.config.peers.append(peer)
        self.config.save(self.device_name)

        del self.temp_address_assoc[public_key]
        if WireGuardCLI.hot_reload(self.device_name):
            return AcknowledgeResponse()

        logging.error('Unable to hot-reload the server configuration')

        return ErrorResponse(ErrorCode.UNABLE_TO_RELOAD_CONFIGURATION.value,
                             'Unable to update central configuration, please retry again later')

    def address_manager_routine(self, connection: socket.socket, address: Tuple[str, int]):
        try:
            raw_msg = read_message(connection, self.enc_key)

            message = MessageEncDec.loads(raw_msg)
            response: Message = None

            if message.instance_of(IPAddressRequest):
                response = self._routine_ip_address(message)
            elif message.instance_of(IPAddressHoldRequest):
                response = self._routine_ip_address_hold(message)

            if message:
                send_message(connection, response, self.enc_key)

            connection.close()
        except InvalidToken:
            send_invalid_token_message(connection)
            logging.warning(
                f'User {address[0]} attempted to connect using an invalid pre-shared key')

    def socket_listen(self, sock: socket.socket):
        threads: List[Thread] = []
        sock.settimeout(1)

        while not self.end_signal.is_set():
            try:
                sock.listen()
                connection, address = sock.accept()
                thread = Thread(target=self.address_manager_routine, args=[connection, address])
                thread.start()
                threads.append(thread)
            except TimeoutError:
                pass

        sock.close()

        # Wait for all the threads
        for thread in threads:
            if thread.is_alive():
                thread.join()

    def listen(self, args: Namespace):
        if args.enable_listen_ipv6 and socket.has_dualstack_ipv6():
            sock = socket.create_server((args.listen_address_6, args.listen_port),
                                        family=socket.AF_INET6, dualstack_ipv6=True)
        else:
            sock = socket.create_server(
                (args.listen_address_4, args.listen_port), family=socket.AF_INET)

        thread = Thread(target=self.socket_listen, args=[sock])
        thread.start()

        # Wait for the thread to end
        thread.join()
