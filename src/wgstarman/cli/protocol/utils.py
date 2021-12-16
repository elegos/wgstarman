import inspect
import json
import logging
from typing import Any, Dict, Optional, Type

from wgstarman.cli.protocol.messages import REGISTERED_MESSAGES, Message, T


class MessageEncDec:
    @staticmethod
    def dumps(obj: Message) -> Optional[str]:
        try:
            dictionary = {'message_type': obj.message_type}
            dictionary.update(vars(obj))

            return json.dumps(dictionary)
        except Exception as e:
            logging.getLogger(__class__.__name__).error(e)

            return None

    @staticmethod
    def loads(raw: str) -> Optional[Message]:
        try:
            jsonObj = json.loads(raw)
            message_type = jsonObj['message_type']
            for message_class in REGISTERED_MESSAGES:
                if message_class.message_type == message_type:
                    return MessageEncDec.from_raw(message_class, jsonObj)
        except Exception as e:
            logging.getLogger(__class__.__name__).error(e)

            return None

    @staticmethod
    def from_raw(cls: Type[T], msg: Dict[str, Any]) -> Optional[T]:
        sig = inspect.signature(cls.__init__)

        try:
            kwargs = {key: value for key, value in msg.items() if key in sig.parameters}

            return cls(**kwargs)

        except Exception as e:
            logging.getLogger(__class__.__name__).error(e)

            return None
