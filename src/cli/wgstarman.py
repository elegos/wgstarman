from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from typing import List

from wgcli.exec import WireGuardCLI

from cli.common import CLICommand
from cli.peer import PeerCommand
from cli.server import ServerCommand


def main():
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    subparsers = parser.add_subparsers(dest='task')

    commands: List[CLICommand] = [PeerCommand(), ServerCommand()]
    for command in commands:
        command.decorate_subparsers(subparsers)

    args = parser.parse_args()

    if not WireGuardCLI.ensure_installation():
        return

    for command in commands:
        if command.can_handle(args.task):
            command.configure_logging(args)
            command.handle(args)


if __name__ == '__main__':
    main()
