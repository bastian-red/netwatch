import pytest

from offensive.arp_spoof import build_arp_reply, spoof
from offensive.guard import LabGuardError, is_lab_target, require_lab_target


# --- guard.py ------------------------------------------------------------

def test_loopback_is_lab_target():
    assert is_lab_target("127.0.0.1") is True


def test_rfc1918_is_lab_target():
    assert is_lab_target("192.168.1.1") is True
    assert is_lab_target("10.0.0.1") is True
    assert is_lab_target("172.16.0.1") is True


def test_public_ip_is_not_lab_target():
    assert is_lab_target("8.8.8.8") is False


def test_require_lab_target_passes_for_lab_ip():
    require_lab_target("192.168.1.1")  # should not raise


def test_require_lab_target_raises_for_public_ip():
    with pytest.raises(LabGuardError):
        require_lab_target("8.8.8.8")


def test_require_lab_target_override_bypasses_guard():
    require_lab_target("8.8.8.8", override=True)  # should not raise


# --- arp_spoof.py: pure packet building -----------------------------------

def test_build_arp_reply_fields():
    pkt = build_arp_reply(
        dst_ip="192.168.1.10", dst_mac="aa:aa:aa:aa:aa:01",
        spoof_ip="192.168.1.1", spoof_mac="de:ad:be:ef:00:01",
    )
    arp = pkt.payload
    assert pkt.dst == "aa:aa:aa:aa:aa:01"
    assert arp.op == 2  # is-at (reply)
    assert arp.pdst == "192.168.1.10"
    assert arp.hwdst == "aa:aa:aa:aa:aa:01"
    assert arp.psrc == "192.168.1.1"
    assert arp.hwsrc == "de:ad:be:ef:00:01"


# --- arp_spoof.py: guard refuses before any network call -------------------

def test_spoof_refuses_non_lab_target_without_override():
    with pytest.raises(LabGuardError):
        spoof(target_ip="8.8.8.8", gateway_ip="8.8.4.4", send_fn=lambda *a, **k: None)


def test_spoof_refuses_non_lab_gateway_without_override():
    with pytest.raises(LabGuardError):
        spoof(target_ip="192.168.1.10", gateway_ip="8.8.4.4", send_fn=lambda *a, **k: None)
