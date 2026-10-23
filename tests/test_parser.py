import pytest

from modules.asset_manager import SAMPLE_XML_PATH, dataset_from_scan
from modules.nmap_parser import NmapParseError, parse_nmap_xml


def test_parses_multiple_hosts(two_hosts_xml):
    r = parse_nmap_xml(two_hosts_xml)
    assert [h["ip"] for h in r["hosts"]] == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]
    h = r["hosts"][0]
    assert h["hostname"] == "a.lab" and h["status"] == "up"
    assert h["ports"][0] == {"port": 80, "protocol": "tcp", "state": "open", "name": "http",
                             "product": "Apache httpd", "version": "2.4.29", "extrainfo": ""}
    assert r["meta"]["scan_start"].startswith("2025-10-09") and r["meta"]["args"] == "nmap -sV"


def test_dataset_keeps_only_open_ports_and_up_hosts(two_hosts_xml):
    ds = dataset_from_scan(parse_nmap_xml(two_hosts_xml))
    assert len(ds["assets"]) == 2
    assert sorted(s["port"] for s in ds["services"]) == [80, 5432]
    assert ds["findings"] == []  # a version string never creates a finding


@pytest.mark.parametrize("bad", [b"", b"   ", b"<nmaprun><host>", b"not xml at all", b"<html></html>"])
def test_invalid_input_raises_clear_error(bad):
    with pytest.raises(NmapParseError):
        parse_nmap_xml(bad)


def test_entity_declarations_rejected():
    evil = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>'
    with pytest.raises(NmapParseError, match="entity"):
        parse_nmap_xml(evil)


def test_host_without_address_is_skipped_with_warning():
    r = parse_nmap_xml(b"<nmaprun><host><status state='up'/></host></nmaprun>")
    assert r["hosts"] == [] and r["warnings"]


def test_bundled_sample_scan_parses():
    r = parse_nmap_xml(SAMPLE_XML_PATH.read_bytes())
    assert len(r["hosts"]) == 5 and sum(len(h["ports"]) for h in r["hosts"]) == 11
