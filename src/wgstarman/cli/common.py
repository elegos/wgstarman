from abc import ABC, abstractmethod
from argparse import Namespace, _SubParsersAction
from pathlib import Path
import stat

WG_CONF_FILE_MODE = stat.S_IWUSR | stat.S_IRUSR
WG_DIR_MODE = stat.S_IXUSR | stat.S_IWUSR | stat.S_IRUSR

ETC_DIR_MODE = stat.S_IWUSR | stat.S_IRUSR | stat.S_IXUSR
RESOLVERS_ETC_DIR_MODE = stat.S_IWUSR | stat.S_IRUSR | stat.S_IXUSR \
    | stat.S_IRGRP | stat.S_IXGRP \
    | stat.S_IROTH | stat.S_IXOTH
RESOLVERS_FILE_MODE = stat.S_IWUSR | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH

DEFAULT_WGSTARMAN_ETC_PATH = Path('/etc/wgstarman')
DEFAULT_WGSTARMAN_CONF_PATH = str(DEFAULT_WGSTARMAN_ETC_PATH.joinpath('wgstarman.conf'))


class CLICommand(ABC):
    def configure_logging(self, args: Namespace) -> None:
        pass

    @staticmethod
    def ensure_wireguard() -> bool:
        return True

    @abstractmethod
    def decorate_subparsers(self, subparsers: _SubParsersAction) -> None:
        pass

    @abstractmethod
    def can_handle(self, task_name: str) -> bool:
        pass

    @abstractmethod
    def handle(self, args: Namespace) -> None:
        pass
