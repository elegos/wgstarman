from argparse import SUPPRESS, ArgumentDefaultsHelpFormatter, ArgumentParser, Namespace
import logging
import os
import socket
from typing import Union
from wgstarman.cli.common import CLICommand
from wgstarman.cli.peer import PeerCommand
from argparse import _SubParsersAction
from wgstarman.cli.protocol import read_message, send_message
from wgstarman.cli.protocol.messages import ErrorResponse, ResolveRequest, ResolveResponse
from wgstarman.cli.protocol.utils import MessageEncDec

from wgstarman.cli.wgstarman_resolvers import WGStarManResolver


class ResolvCommand(CLICommand):
    task_name = 'resolv'

    @staticmethod
    def configure_logging(args: Namespace) -> None:
        return PeerCommand.configure_logging(args)

    @staticmethod
    def ensure_wireguard() -> bool:
        return False

    def decorate_subparsers(self, subparsers: _SubParsersAction) -> None:
        parser: ArgumentParser = subparsers.add_parser(
            self.task_name, formatter_class=ArgumentDefaultsHelpFormatter)
        required = parser.add_argument_group('required')
        optional = parser.add_argument_group('optional')

        required.add_argument(
            '--device-name', '-d', help='the device associated with the network', required=True, default=SUPPRESS)
        required.add_argument('host_name')

        optional.add_argument(
            '--resolv-port', '-p', help='the resolv port (server listen port + 1)', type=int, default=1195)
        optional.add_argument('--debug', default=False, action='store_true',
                              help='enable debug log', required=False)

    def can_handle(self, task_name: str) -> bool:
        return self.task_name == task_name

    def handle(self, args: Namespace) -> None:
        resolv_conf = WGStarManResolver.load(args.device_name)
        if not resolv_conf.resolver_addresses:
            logging.error(f'Unknown resolver for device {args.device_name}')

            return

        # special case: resolv will return the resolver's IP addresses
        if args.host_name == 'resolv':
            print('\n'.join(resolv_conf.resolver_addresses))

            return

        host_name = args.host_name
        resolver_port = args.resolv_port
        for resolv_address in resolv_conf.resolver_addresses:
            try:
                sock = socket.create_connection((resolv_address, resolver_port), 1)
                send_message(sock, ResolveRequest(host_name))
                response = read_message(sock)
                message: Union[ResolveResponse, ErrorResponse] = MessageEncDec.loads(response)

                if message.instance_of(ErrorResponse):
                    logging.error(f'{message.error_code}: {message.message}')

                    os._exit(1)

                print('\n'.join(message.ip_addresses))

                return
            except socket.timeout:
                pass

        logging.error('Unable to contact resolv server')
        os._exit(2)
