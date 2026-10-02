from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
PROFILE = "xccdf_org.ssgproject.content_profile_cis_level1_server"


@pytest.fixture
def before() -> bytes:
    return (FIXTURES / "before.xml").read_bytes()


@pytest.fixture
def after() -> bytes:
    return (FIXTURES / "after.xml").read_bytes()
