import logging
from collections import namedtuple
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_WIREGUARD_ETC_DIR = '/etc/wireguard'

KwargResolve = namedtuple('KwargResolver', ['wg_name', 'conf_name', 'type'])


def resolve(resolver: List[KwargResolve], setting: str, value: str) -> Tuple[str, Any]:
    resolve = next((r for r in resolver if r.wg_name == setting), None)

    if resolve:
        if resolve.type == List[str]:
            value = value.strip().split(',')
        elif resolve.type == List[int]:
            value = [int(v) for v in value.strip().split(',')]
        else:
            value = resolve.type(value.strip())

        return (resolve.conf_name, value)

    return None


@dataclass
class Interface:
    private_key: str
    address: List[str]
    listen_port: Optional[int] = field(default=None)
    fw_mark: Optional[int] = field(default=None)

    @staticmethod
    def parse(section: str):
        kwarg_resolver = [
            KwargResolve('PrivateKey', 'private_key', str),
            KwargResolve('Address', 'address', List[str]),
            KwargResolve('ListenPort', 'listen_port', int),
            KwargResolve('FwMark', 'fw_mark', int),
        ]

        kwargs = {}
        for line in section.split('\n')[1:]:
            setting, value = map(str.strip, line.split('=', 1))
            resolved = resolve(kwarg_resolver, setting, value)
            if resolved:
                kwargs[resolved[0]] = resolved[1]

        return Interface(**kwargs)

    def __str__(self) -> str:
        result = []
        result.append('[Interface]')
        result.append(f'PrivateKey = {self.private_key}')
        result.append(f'Address = {",".join(self.address)}')
        if self.listen_port:
            result.append(f'ListenPort = {self.listen_port}')
        if self.fw_mark:
            result.append(f'FwMark = {self.fw_mark}')

        return '\n'.join(result)


@dataclass
class Peer:
    public_key: str
    allowed_ips: List[str]
    preshared_key: Optional[str] = field(default=None)
    endpoint: Optional[str] = field(default=None)
    persistend_keep_alive: Optional[int] = field(default=None)

    @staticmethod
    def parse(section: str):
        kwarg_resolver = [
            KwargResolve('PublicKey', 'public_key', str),
            KwargResolve('AllowedIPs', 'allowed_ips', List[str]),
            KwargResolve('PresharedKey', 'preshared_key', str),
            KwargResolve('Endpoint', 'endpoint', str),
            KwargResolve('PersistentKeepalive', 'persistend_keep_alive', int),
        ]

        kwargs = {}
        for line in section.split('\n')[1:]:
            setting, value = map(str.strip, line.split('=', 1))
            resolved = resolve(kwarg_resolver, setting, value)
            if resolved:
                kwargs[resolved[0]] = resolved[1]

        return Peer(**kwargs)

    def __str__(self) -> str:
        result = []
        result.append('[Peer]')
        result.append(f'PublicKey = {self.public_key}')
        result.append(f'AllowedIPs = {",".join(self.allowed_ips)}')
        if self.preshared_key:
            result.append(f'PresharedKey = {self.preshared_key}')
        if self.endpoint:
            result.append(f'Endpoint = {self.endpoint}')
        if self.persistend_keep_alive:
            result.append(f'PersistentKeepalive = {self.persistend_keep_alive}')

        return '\n'.join(result)


@dataclass
class WireGuardConf:
    interface: Interface
    peers: List[Peer] = field(default_factory=lambda: [])

    @staticmethod
    def parse(device_name: str, conf_path: str = DEFAULT_WIREGUARD_ETC_DIR) -> Optional['WireGuardConf']:
        logger = logging.getLogger('WireGuard ConfParser')
        path = Path(conf_path).joinpath(f'{device_name}.conf')

        if not path.exists():
            logger.debug(f'Configuration not found ({path})')

            return None

        sections: List[str] = []
        lines = path.read_text('utf8').split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue

            if line.startswith('['):
                sections.append(line)
            else:
                sections[-1] += f'\n{line}'

        interface: Interface = None
        peers: List[Peer] = []
        for section in sections:
            if section.startswith('[Interface]'):
                interface = Interface.parse(section)
            if section.startswith('[Peer]'):
                peers.append(Peer.parse(section))

        if not interface:
            logger.error('Invalid configuration found (no Interface section)')

            return None

        return WireGuardConf(interface, peers)

    def save(self, device_name: str, conf_path: str = DEFAULT_WIREGUARD_ETC_DIR):
        path = Path(conf_path).joinpath(f'{device_name}.conf')

        with path.open('w') as fp:
            parts = [str(self.interface)]
            parts.extend([str(peer) for peer in self.peers])
            fp.write('\n\n'.join(parts) + '\n')
