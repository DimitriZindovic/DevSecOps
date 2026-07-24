from core.detect import detect_from_nmap, validate_finding
from core.recon import NmapResult, parse_nmap_xml

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="3000">
        <state state="open"/>
        <service name="http" product="Node.js Express framework" version="" />
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml():
    ports = parse_nmap_xml(SAMPLE_NMAP_XML)
    assert len(ports) == 3
    p3000 = next(p for p in ports if p.port == 3000)
    assert p3000.state == "open" and p3000.service == "http"


def test_detect_from_nmap_open_ports_only():
    result = NmapResult(
        target="juiceshop",
        host="juiceshop",
        command="nmap -sV juiceshop",
        ports=parse_nmap_xml(SAMPLE_NMAP_XML),
    )
    findings = detect_from_nmap(result)
    types = [f["type"] for f in findings]
    assert types.count("open_port") == 2
    assert types.count("version_disclosure") == 1
    assert all("22/tcp" not in f["evidence"]["output"] for f in findings)


def test_all_findings_are_schema_valid():
    result = NmapResult(
        target="juiceshop",
        host="juiceshop",
        command="nmap -sV juiceshop",
        ports=parse_nmap_xml(SAMPLE_NMAP_XML),
    )
    for f in detect_from_nmap(result):
        validate_finding(f)
