import ui.app as ui_app


def _client():
    ui_app.app.config["TESTING"] = True
    return ui_app.app.test_client()


def test_index_renders():
    client = _client()
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"netwatch" in resp.data


def test_api_hosts_empty_before_monitor_starts():
    ui_app.session = ui_app.Session()
    client = _client()
    resp = client.get("/api/hosts")
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_api_stats_empty_before_monitor_starts():
    ui_app.session = ui_app.Session()
    client = _client()
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    assert resp.get_json() == {}


def test_api_history_endpoints_empty_before_monitor_starts():
    ui_app.session = ui_app.Session()
    client = _client()
    assert client.get("/api/history/latency/10.0.0.1").get_json() == []
    assert client.get("/api/history/bandwidth/eth0").get_json() == []
