from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
import stat

DEFAULT_WGSTARMAN_PATH = '/etc/wgstarman/wgstarman.conf'


@dataclass
class PresharedKey:
    public_key: str
    preshared_key: str

    def parse(line: str) -> 'PresharedKey':
        public_key, preshared_key = line.split(' = ')

        return PresharedKey(public_key.strip(), preshared_key.strip())

    def __str__(self) -> str:
        return f'{self.public_key} = {self.preshared_key}'


@dataclass
class WGStarManConf:
    preshared_keys: List[PresharedKey]

    @staticmethod
    def load(conf_path: str = DEFAULT_WGSTARMAN_PATH) -> 'WGStarManConf':
        path = Path(conf_path)

        if not path.exists():
            return WGStarManConf([])

        preshared_keys = []
        for line in path.read_text(encoding='utf8').split('\n'):
            if line:
                preshared_keys.append(PresharedKey.parse(line))

        return WGStarManConf(preshared_keys)

    def save(self, conf_path: str = DEFAULT_WGSTARMAN_PATH) -> None:
        chmod_mode = stat.S_IWUSR | stat.S_IRUSR

        path = Path(conf_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.parent.chmod(chmod_mode)

        path.write_text('\n'.join(map(lambda psk: str(psk), self.preshared_keys)) + '\n')
        path.chmod(chmod_mode)

    def get_preshared_key(self, public_key: str) -> Optional[str]:
        return next((psk.preshared_key for psk in self.preshared_keys if psk.public_key == public_key), None)

    def set_preshared_key(self, public_key: str, preshared_key: str) -> None:
        old_psk = next((psk for psk in self.preshared_keys if psk.public_key == public_key), None)
        if old_psk:
            self.preshared_keys.remove(old_psk)

        self.preshared_keys.append(PresharedKey(public_key, preshared_key))

        self.save()
