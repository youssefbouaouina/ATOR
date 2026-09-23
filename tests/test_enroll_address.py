"""The server address written into generated enrollment commands.

Found by enrolling a real endpoint: the server machine has Wi-Fi (192.168.0.125) plus six
VMware adapters, and the old logic advertised the default-route interface - Wi-Fi - so
machines on the 192.168.50.0/24 lab network were told to connect to an address they
cannot reach. The command must carry the server's address on the endpoints' network.
"""
import pytest

from server import ui

INTERFACES = ["169.254.90.210", "192.168.50.1", "192.168.11.100", "192.168.107.1",
              "192.168.116.1", "192.168.12.100", "192.168.0.125"]


@pytest.fixture()
def machine(monkeypatch):
    """This server as measured: seven IPv4 interfaces, Wi-Fi holding the default route."""
    monkeypatch.setattr(ui, "_local_ipv4_addresses", lambda: list(INTERFACES))
    monkeypatch.setattr(ui, "_default_route_ip", lambda: "192.168.0.125")
    monkeypatch.delenv("ATOR_ENROLL_SUBNET", raising=False)
    monkeypatch.delenv("ATOR_PUBLIC_URL", raising=False)
    return monkeypatch


class TestDetectLanIp:
    def test_prefers_the_lab_subnet_over_the_default_route(self, machine):
        assert ui.detect_lan_ip() == "192.168.50.1"

    def test_subnet_is_configurable(self, machine):
        machine.setenv("ATOR_ENROLL_SUBNET", "192.168.107.0/24")
        assert ui.detect_lan_ip() == "192.168.107.1"

    def test_several_subnets_are_tried_in_order(self, machine):
        machine.setenv("ATOR_ENROLL_SUBNET", "10.9.0.0/16, 192.168.12.0/24,192.168.50.0/24")
        assert ui.detect_lan_ip() == "192.168.12.100"

    def test_invalid_entries_are_ignored(self, machine):
        machine.setenv("ATOR_ENROLL_SUBNET", "not-a-subnet,192.168.50.0/24")
        assert ui.detect_lan_ip() == "192.168.50.1"

    def test_falls_back_to_the_default_route_when_no_interface_matches(self, machine):
        machine.setenv("ATOR_ENROLL_SUBNET", "10.200.0.0/16")
        assert ui.detect_lan_ip() == "192.168.0.125"

    def test_a_machine_without_the_lab_adapter_keeps_the_old_behaviour(self, machine):
        machine.setattr(ui, "_local_ipv4_addresses", lambda: ["192.168.0.125"])
        assert ui.detect_lan_ip() == "192.168.0.125"

    def test_link_local_addresses_are_never_chosen(self, machine):
        machine.setenv("ATOR_ENROLL_SUBNET", "10.200.0.0/16")
        assert not ui.detect_lan_ip().startswith("169.254.")


class _Req:
    """Just enough of a Starlette request for enrollment_server_url()."""

    def __init__(self, url):
        from starlette.datastructures import URL
        self.url = URL(url)
        self.base_url = URL(f"{self.url.scheme}://{self.url.netloc}/")


class TestEnrollmentServerUrl:
    def test_page_opened_via_localhost_advertises_the_lab_address(self, machine):
        req = _Req("http://127.0.0.1:8000/enroll/status/abc")
        assert ui.enrollment_server_url(req) == "http://192.168.50.1:8000"

    @pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "127.0.1.1"])
    def test_every_loopback_form_is_replaced(self, machine, host):
        assert ui.enrollment_server_url(_Req(f"http://{host}:8000/x")) == "http://192.168.50.1:8000"

    def test_page_opened_via_a_real_address_keeps_it(self, machine):
        """Whoever viewed the page already reached the server at that address."""
        req = _Req("http://192.168.50.1:8000/enroll/status/abc")
        assert ui.enrollment_server_url(req) == "http://192.168.50.1:8000"

    def test_hostname_is_kept(self, machine):
        req = _Req("http://ator-server.lab:8000/enroll/status/abc")
        assert ui.enrollment_server_url(req) == "http://ator-server.lab:8000"

    def test_explicit_public_url_wins(self, machine):
        machine.setenv("ATOR_PUBLIC_URL", "https://dfir.example.org/")
        req = _Req("http://127.0.0.1:8000/enroll/status/abc")
        assert ui.enrollment_server_url(req) == "https://dfir.example.org"

    def test_port_is_preserved(self, machine):
        assert ui.enrollment_server_url(_Req("http://localhost:8123/x")) == "http://192.168.50.1:8123"


class TestEnrollStatusPage:
    """The command an operator copies must carry the reachable address."""

    def test_rendered_command_uses_the_lab_address(self, machine, tmp_db):
        machine.setenv("ATOR_DFIR_DB", tmp_db)
        from fastapi.testclient import TestClient
        from server.app import app
        with TestClient(app, base_url="http://127.0.0.1:8000") as client:
            body = client.get("/enroll/status/some-token").text
        assert '"http://192.168.50.1:8000"' in body
        assert "request.base_url" not in body          # no client-side re-derivation left
