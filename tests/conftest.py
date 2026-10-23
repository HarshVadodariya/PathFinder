import pytest

from modules.asset_manager import empty_dataset, load_sample_network
from modules.config import RuleConfig


@pytest.fixture
def sample():
    return load_sample_network()


@pytest.fixture
def rules():
    return RuleConfig()


@pytest.fixture
def two_hosts_xml():
    return b"""<?xml version="1.0"?><!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV" start="1760000000" version="7.95">
<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><hostnames><hostname name="a.lab"/></hostnames>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.29"/></port>
<port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port></ports></host>
<host><status state="up"/><address addr="10.0.0.6" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="5432"><state state="open"/><service name="postgresql"/></port></ports></host>
<host><status state="down"/><address addr="10.0.0.7" addrtype="ipv4"/></host>
<runstats><finished time="1760000100" summary="done"/></runstats></nmaprun>"""


@pytest.fixture
def empty():
    return empty_dataset()
