import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem_hunter.config import Config  # noqa: E402
from siem_hunter.pipeline import Platform  # noqa: E402
from siem_hunter.store import Store  # noqa: E402

T0 = 1_760_000_000.0  # fixed reference time (Oct 2025) so tests are deterministic


def iso(ts: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def ssh_fail(ts, host, user, ip, port=40000):
    return f"{iso(ts)} {host} sshd[1]: Failed password for {user} from {ip} port {port} ssh2"


def ssh_ok(ts, host, user, ip, port=40001):
    return f"{iso(ts)} {host} sshd[1]: Accepted password for {user} from {ip} port {port} ssh2"


@pytest.fixture
def cfg():
    c = Config()
    c.db_path = ":memory:"
    return c


@pytest.fixture
def platform(cfg):
    return Platform(cfg, Store(":memory:"))
