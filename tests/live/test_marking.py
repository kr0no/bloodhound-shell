from __future__ import annotations

from bhshell.shell.app import BHShell
from tests.conftest import run
from tests.live.conftest import ok


def test_rule_based_tier_zero_is_left_alone(lab: BHShell) -> None:
    assert "nothing to add" in ok(lab, "hvt add 'DOMAIN ADMINS@PHANTOM.CORP'")
    assert "rule-based selector" in run(lab, "hvt remove 'DOMAIN ADMINS@PHANTOM.CORP'")
