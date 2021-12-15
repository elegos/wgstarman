import inspect
import json
import logging
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Any, ClassVar, Dict, List, Optional, Type, TypeVar

from cryptography.fernet import Fernet


class ProtocolException(Exception):
    pass


class ErrorCode(Enum):
    NETWORK_IS_FULL = 10001,
    INVALID_IP_ADDRESS = 10002,
    UNABLE_TO_RELOAD_CONFIGURATION = 10003,


class Message:
    message_type: str = 'UnknownMessage'

    def instance_of(self, cls: Type['Message']) -> bool:
        return type(self) == cls


@dataclass
class IPAddressRequest(Message):
    public_key: str

    message_type: ClassVar[str] = 'request_ip_address'


@dataclass
class IPAddressHoldRequest(Message):
    ip_address: str

    message_type: ClassVar[str] = 'request_ip_address_hold'


@dataclass
class IPAddressResponse(Message):
    server_public_key: str
    peer_address: str
    peer_allowed_ips: str

    message_type: ClassVar[str] = 'ip_address_response'


@dataclass
class ErrorResponse(Message):
    error_code: int
    message: str

    message_type: ClassVar[str] = 'error_response'


class AcknowledgeResponse(Message):
    message_type: ClassVar[str] = 'ack'


T = TypeVar('T', bound=Message)
REGISTERED_MESSAGES: List[Type[T]] = [IPAddressRequest, IPAddressHoldRequest,
                                      IPAddressResponse, ErrorResponse, AcknowledgeResponse]

INVALID_MSG_LEN = 0xFFFF


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


def send_message(conn: socket.socket, msg: Any, encrypt_key: bytes) -> None:
    fernet = Fernet(encrypt_key)

    msg = MessageEncDec.dumps(msg)
    logging.debug(f'Sending {msg}')

    msg = fernet.encrypt(msg.encode('utf8'))
    msg = len(msg).to_bytes(4, 'big', signed=False) + msg

    conn.send(msg)


def send_invalid_token_message(conn: socket.socket) -> None:
    msg = INVALID_MSG_LEN.to_bytes(4, 'big', signed=False)

    conn.send(msg)


def read_message(conn: socket.socket, decrypt_key: bytes) -> str:
    fernet = Fernet(decrypt_key)

    msg_len = int.from_bytes(conn.recv(4), 'big', signed=False)
    if msg_len == INVALID_MSG_LEN:
        raise ProtocolException('The pre-shared key is invalid.')

    msg = conn.recv(msg_len)
    msg = fernet.decrypt(msg).decode('utf8')

    logging.debug(f'Receiving {msg}')

    return msg
