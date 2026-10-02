"""Test suite of the proof pack. Importing this package blocks every socket in the process.

    python -m unittest discover -s tests -t .

Child processes started by the tests get the same block through ``tests/offline/sitecustomize.py``
(put on ``PYTHONPATH`` by ``tests/_util.py``). A test that needed the network would fail, not skip.
"""
import socket


class NetworkBlocked(RuntimeError):
    pass


def _refuse(*args, **kwargs):
    raise NetworkBlocked("network access is blocked in the test suite")


class _BlockedSocket(socket.socket):
    def __init__(self, *args, **kwargs):
        _refuse()


socket.socket = _BlockedSocket
socket.create_connection = _refuse
socket.getaddrinfo = _refuse
