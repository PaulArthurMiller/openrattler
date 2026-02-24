"""Standard error codes for the OpenRattler system."""

from enum import Enum


class ErrorCode(str, Enum):
    """Standard error codes used in UniversalMessage error payloads.

    Using str as a mixin so that .value comparisons work naturally and
    the code serialises to a plain string in JSON.
    """

    PERMISSION_DENIED = "PERMISSION_DENIED"
    INVALID_PARAMS = "INVALID_PARAMS"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    TIMEOUT = "TIMEOUT"
    NOT_FOUND = "NOT_FOUND"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    NETWORK_ERROR = "NETWORK_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"
