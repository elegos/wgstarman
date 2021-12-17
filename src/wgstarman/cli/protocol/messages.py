from dataclasses import dataclass, field
from typing import ClassVar, List, Optional, Type, TypeVar


class Message:
    message_type: str = 'UnknownMessage'

    def instance_of(self, cls: Type['Message']) -> bool:
        return type(self) == cls


@dataclass
class IPAddressRequest(Message):
    public_key: str
    peer_name: Optional[str] = field(default=None)

    message_type: ClassVar[str] = 'request_ip_address'


@dataclass
class IPAddressHoldRequest(Message):
    ip_address: str
    host_name: Optional[str]

    message_type: ClassVar[str] = 'request_ip_address_hold'


@dataclass
class IPAddressResponse(Message):
    server_public_key: str
    peer_address: str
    peer_allowed_ips: str
    resolver_addresses: List[str]

    message_type: ClassVar[str] = 'ip_address_response'


@dataclass
class ResolveRequest(Message):
    host_name: str

    message_type: ClassVar[str] = 'resolv_request'


@dataclass
class ResolveResponse(Message):
    host_name: str
    ip_addresses: List[str]

    message_type: ClassVar[str] = 'resolv_response'


@dataclass
class ErrorResponse(Message):
    error_code: int
    message: str

    message_type: ClassVar[str] = 'error_response'


class AcknowledgeResponse(Message):
    message_type: ClassVar[str] = 'ack'


T = TypeVar('T', bound=Message)
REGISTERED_MESSAGES: List[Type[T]] = [
    IPAddressRequest, IPAddressHoldRequest, IPAddressResponse,
    ResolveRequest, ResolveResponse,
    ErrorResponse, AcknowledgeResponse
]
