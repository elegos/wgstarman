from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from wgstarman.cli.common import DEFAULT_WGSTARMAN_ETC_PATH, RESOLVERS_ETC_DIR_MODE, RESOLVERS_FILE_MODE


@dataclass
class WGStarManResolver:
    device_name: str
    resolver_addresses: List[str]

    @staticmethod
    def get_conf_path(device_name: str, conf_path: str = DEFAULT_WGSTARMAN_ETC_PATH) -> Path:
        return Path(conf_path).joinpath(f'{device_name}.resolver.conf')

    @staticmethod
    def load(device_name: str, conf_path: str = DEFAULT_WGSTARMAN_ETC_PATH) -> 'WGStarManResolver':
        path = WGStarManResolver.get_conf_path(device_name, conf_path)

        if not path.exists():
            return WGStarManResolver(device_name, [])

        return WGStarManResolver(device_name, list(map(str.strip, path.read_text().split(','))))

    def save(self, conf_path: str = DEFAULT_WGSTARMAN_ETC_PATH) -> 'WGStarManResolver':
        path = WGStarManResolver.get_conf_path(self.device_name, conf_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.parent.chmod(RESOLVERS_ETC_DIR_MODE)

        path.write_text(','.join(self.resolver_addresses))
        path.chmod(RESOLVERS_FILE_MODE)

        return self
