import logging
import socket
from enum import Enum
from typing import Any, Optional

from cryptography.fernet import Fernet
from wgstarman.cli.protocol.messages import (
    AcknowledgeResponse, ErrorResponse, IPAddressHoldRequest, IPAddressRequest, IPAddressResponse, Message
)
from wgstarman.cli.protocol.utils import MessageEncDec

__all__ = [
    # messages
    IPAddressRequest, IPAddressResponse, IPAddressHoldRequest, AcknowledgeResponse, ErrorResponse, Message
]


class ProtocolException(Exception):
    pass


class ErrorCode(Enum):
    NETWORK_IS_FULL = 10001,
    INVALID_IP_ADDRESS = 10002,
    HOST_NAME_THEFT = 10003,
    UNABLE_TO_RELOAD_CONFIGURATION = 10004,
    UNHANDLED_REQUEST = 10005,


INVALID_TOKEN_LEN = 0xFFFF


def send_message(conn: socket.socket, msg: Any, encrypt_key: Optional[bytes] = None) -> None:
    msg = MessageEncDec.dumps(msg)
    logging.debug(f'Sending {msg}')

    if encrypt_key:
        fernet = Fernet(encrypt_key)
        msg = fernet.encrypt(msg.encode('utf8'))
    else:
        msg = msg.encode('utf8')
    msg = len(msg).to_bytes(4, 'big', signed=False) + msg

    conn.send(msg)


def send_invalid_token_message(conn: socket.socket) -> None:
    msg = INVALID_TOKEN_LEN.to_bytes(4, 'big', signed=False)

    conn.send(msg)


def read_message(conn: socket.socket, decrypt_key: Optional[bytes] = None) -> str:
    msg_len = int.from_bytes(conn.recv(4), 'big', signed=False)
    if msg_len == INVALID_TOKEN_LEN:
        raise ProtocolException('The pre-shared key is invalid.')

    msg = conn.recv(msg_len)

    if decrypt_key:
        fernet = Fernet(decrypt_key)
        msg = fernet.decrypt(msg).decode('utf8')
    else:
        msg = msg.decode('utf8')

    logging.debug(f'Receiving {msg}')

    return msg
