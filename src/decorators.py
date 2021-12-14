from threading import Lock
from typing import Callable


def syncronized(lock: Lock) -> Callable:
    def synchronized_decorator(fn: Callable) -> Callable:
        def _synchronized_decorator(*args, **kwargs):
            with lock:
                return fn(*args, **kwargs)

        return _synchronized_decorator

    return synchronized_decorator
