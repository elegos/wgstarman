import logging
from dataclasses import dataclass, field
from functools import reduce
from pathlib import Path
from typing import Any, List, Optional, Tuple

from wgstarman.cli.common import ETC_DIR_MODE, WG_CONF_FILE_MODE, WG_DIR_MODE

DEFAULT_WIREGUARD_ETC_DIR = '/etc/wireguard'


@dataclass
class KwargResolve:
    wg_name: str
    conf_name: str
    type: type


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
    name: Optional[str] = field(default=None)

    @staticmethod
    def parse(section: str):
        kwarg_resolver = [
            KwargResolve('PublicKey', 'public_key', str),
            KwargResolve('AllowedIPs', 'allowed_ips', List[str]),
            KwargResolve('PresharedKey', 'preshared_key', str),
            KwargResolve('Endpoint', 'endpoint', str),
            KwargResolve('PersistentKeepalive', 'persistend_keep_alive', int),
            KwargResolve('# Name', 'name', str),
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
        if self.name:
            result.append(f'# Name = {self.name}')
        result.append(f'PublicKey = {self.public_key}')
        result.append(f'AllowedIPs = {",".join(self.allowed_ips)}')
        if self.preshared_key:
            result.append(f'PresharedKey = {self.preshared_key}')
        if self.endpoint:
            result.append(f'Endpoint = {self.endpoint}')
        if self.persistend_keep_alive:
            result.append(f'PersistentKeepalive = {self.persistend_keep_alive}')

        return '\n'.join(result)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Peer):
            return False

        def cmp(attr: str) -> bool:
            a = getattr(self, attr)
            b = getattr(other, attr)

            if type(a) == list:
                a = ','.join(a)
                b = ','.join(b)

            return a == b or a is None and b is None

        return reduce(lambda cumu, attr: cumu and cmp(attr), vars(self).keys(), True)


@ dataclass
class WireGuardConf:
    interface: Interface
    peers: List[Peer] = field(default_factory=lambda: [])

    @ staticmethod
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
        if not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.parent.chmod(WG_DIR_MODE)

        with path.open('w') as fp:
            parts = [str(self.interface)]
            parts.extend([str(peer) for peer in self.peers])
            fp.write('\n\n'.join(parts) + '\n')

        path.chmod(WG_CONF_FILE_MODE)

    def append_peer(self, peer: Peer) -> None:
        old_peer = next((pr for pr in self.peers if peer.public_key == pr.public_key), None)
        if old_peer:
            self.peers.remove(old_peer)

        self.peers.append(peer)

    def find_peer_by_name(self, peer_name: str) -> Optional[Peer]:
        return next((peer for peer in self.peers if peer.name == peer_name), None)
