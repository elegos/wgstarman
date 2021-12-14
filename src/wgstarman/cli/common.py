from abc import ABC, abstractmethod
from argparse import Namespace, _SubParsersAction


class CLICommand(ABC):
    def configure_logging(self, args: Namespace) -> None:
        pass

    @abstractmethod
    def decorate_subparsers(self, subparsers: _SubParsersAction) -> None:
        pass

    @abstractmethod
    def can_handle(self, task_name: str) -> bool:
        pass

    @abstractmethod
    def handle(self, args: Namespace) -> None:
        pass
