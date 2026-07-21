import json

from cli import build_parser, main


def test_build_parser_subcommand_defaults():
    parser = build_parser()
    args = parser.parse_args(["discover"])
    assert args.command == "discover"
    assert args.cidr is None

    args = parser.parse_args(["monitor", "--method", "icmp"])
    assert args.method == "icmp"
    assert args.interval == 5.0

    args = parser.parse_args(["attack", "arp-spoof", "--target-ip", "10.0.0.1", "--gateway-ip", "10.0.0.254"])
    assert args.target_ip == "10.0.0.1"
    assert args.i_understand_lab is False


def test_discover_against_static_hosts_file(tmp_path, capsys):
    hosts_file = tmp_path / "hosts.json"
    hosts_file.write_text(json.dumps(["127.0.0.1", "127.0.0.2"]))
    out_file = tmp_path / "out.json"
    db_file = tmp_path / "netwatch.db"

    exit_code = main([
        "discover", "--static-hosts-file", str(hosts_file),
        "--json", str(out_file), "--db", str(db_file),
    ])

    assert exit_code == 0
    written = json.loads(out_file.read_text())
    assert {h["ip"] for h in written} == {"127.0.0.1", "127.0.0.2"}
    captured = capsys.readouterr()
    assert "127.0.0.1" in captured.out


def test_stats_prints_no_data_message_for_missing_db(tmp_path, capsys):
    missing_db = tmp_path / "does-not-exist.db"
    exit_code = main(["stats", "--db", str(missing_db)])
    assert exit_code == 0
    assert "No data yet" in capsys.readouterr().out


def test_stats_prints_json_for_existing_db(tmp_path, capsys):
    from storage.store import NetwatchStore

    db_path = tmp_path / "netwatch.db"
    store = NetwatchStore(str(db_path))
    store.close()

    exit_code = main(["stats", "--db", str(db_path)])
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["total_hosts"] == 0


def test_attack_arp_spoof_blocked_for_non_lab_target(capsys):
    exit_code = main(["attack", "arp-spoof", "--target-ip", "8.8.8.8", "--gateway-ip", "8.8.4.4"])
    assert exit_code == 2
    assert "blocked" in capsys.readouterr().err
