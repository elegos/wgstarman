import ipaddress
import logging
import socket
from argparse import (SUPPRESS, ArgumentDefaultsHelpFormatter, ArgumentParser,
                      Namespace, _SubParsersAction)
from typing import Union

from wgstarman.cli.common import CLICommand
from wgstarman.cli.protocol import (AcknowledgeResponse, ErrorResponse,
                                    IPAddressHoldRequest, IPAddressRequest,
                                    IPAddressResponse, MessageEncDec, ProtocolException,
                                    read_message, send_message)
from wgstarman.wg_conf import Interface, Peer, WireGuardConf
from wgstarman.wgcli.exec import WireGuardCLI

LOG_FORMAT = '%(levelname)9s %(message)s'


class PeerCommand(CLICommand):
    task_name = 'peer'

    def configure_logging(self, args: Namespace) -> None:
        logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG if args.debug else logging.INFO)

    def decorate_subparsers(self, subparsers: _SubParsersAction) -> None:
        parser: ArgumentParser = subparsers.add_parser(
            self.task_name, formatter_class=ArgumentDefaultsHelpFormatter)
        required = parser.add_argument_group('required')
        optional = parser.add_argument_group('optional')

        required.add_argument(
            '--server-address', help="the server's IPv4 or IPv6 address", required=True, default=SUPPRESS)
        required.add_argument(
            '--device-name', help='the name of both the network device and the configuration file', required=True, default=SUPPRESS)
        required.add_argument(
            '--psk', help='the pre-shared key, given by the server at startup', required=True, default=SUPPRESS)

        optional.add_argument('--server-port', default=1194, type=int,
                              help="the server's port", required=False)
        optional.add_argument('--keep-alive', default=False, action='store_true',
                              help='keep the connection to the server alive (to avoid connection drop in case of NAT)', required=False)
        optional.add_argument('--overwrite', default=False, action='store_true',
                              help="overwrite if a configuration already exists", required=False)
        optional.add_argument('--debug', default=False, action='store_true',
                              help='enable debug log', required=False)

    def can_handle(self, task_name: str) -> bool:
        return self.task_name == task_name

    def handle(self, args: Namespace) -> None:
        encdec_key = args.psk.encode('utf8')

        try:
            ipaddress.ip_address(args.server_address)
            server_address: str = args.server_address
        except:
            server_address = socket.gethostbyname(args.server_address)

        try:
            conf = WireGuardConf.parse(args.device_name)
        except PermissionError:
            logging.error('wgstarman re')
            return

        if conf is not None:
            if not args.overwrite:
                logging.error(
                    f'Configuration file for device {args.device_name} already exists. Use --overwrite to continue.')

                return
            else:
                logging.info('Configuration detected. Overwriting.')

        private_key = conf.interface.private_key if conf is not None else WireGuardCLI.gen_private_key()
        public_key = WireGuardCLI.get_public_key(private_key)

        logging.debug(f'Connecting to central peer ({server_address} : {args.server_port})')
        sock = socket.create_connection((server_address, args.server_port), 5000)

        try:
            # Request an IP address assigned to the public key
            send_message(sock, IPAddressRequest(public_key), encdec_key)
            response: Union[IPAddressResponse, ErrorResponse] = MessageEncDec.loads(
                read_message(sock, encdec_key))
            if response.instance_of(ErrorResponse):
                logging.error(f'{response.error_code}: {response.message}')
                return

            conf = WireGuardConf(
                Interface(private_key=private_key, address=[
                    response.peer_address]),
                [Peer(public_key=response.server_public_key, allowed_ips=[response.peer_allowed_ips],
                      endpoint=f'{server_address}:{args.server_port}', persistend_keep_alive=25 if args.keep_alive else None)]
            )

            # Send the IP address hold message
            sock = socket.create_connection((server_address, args.server_port), 5000)
            send_message(sock, IPAddressHoldRequest(conf.interface.address[0]), encdec_key)
            response: Union[AcknowledgeResponse, ErrorResponse] = MessageEncDec.loads(
                read_message(sock, encdec_key))
            if response.instance_of(ErrorResponse):
                logging.error(f'{response.error_code}: {response.message}')
                return

            conf.save(args.device_name)

            WireGuardCLI.up(args.device_name)
        except ProtocolException as e:
            logging.error(e)
