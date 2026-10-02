"""Loaded by every child process the tests start (this folder is first on PYTHONPATH): no sockets."""
import socket


class NetworkBlocked(RuntimeError):
    pass


def _refuse(*args, **kwargs):
    raise NetworkBlocked("network access is blocked in the test suite (child process)")


class _BlockedSocket(socket.socket):
    def __init__(self, *args, **kwargs):
        _refuse()


socket.socket = _BlockedSocket
socket.create_connection = _refuse
socket.getaddrinfo = _refuse
