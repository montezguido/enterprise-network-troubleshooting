# Independent Network-Triage Exercise

This is original, runnable Python code that supports the [WGU troubleshooting case study](../README.md). It is **not** an original coursework submission, packet capture, device configuration, or reconstruction of a restricted lab.

## Quick start

Python 3.11+; no third-party libraries, cloud account, administrator permissions, or network connection required:

    python portfolio_demo/triage.py
    python portfolio_demo/triage.py --json
    python -m unittest discover -s tests -v

The [fictional sample observations](sample_cases.json) cover six common investigation patterns:

| Case | Synthetic evidence | Candidate investigation |
|---|---|---|
| Suspicious file-transfer traffic | Unexpected traffic reported | Review authorized packet captures and flow metadata |
| DNS redirection | Answer differs from known-good baseline | Compare DNS server, cache, and authoritative data |
| Routing / forwarding | Gateway reachable; remote IP test fails | Inspect routes, path, ICMP policy, and destination |
| Endpoint IP configuration | Incorrect host addressing observed | Inspect address, prefix, DHCP lease, and gateway |
| DMZ access restriction | Firewall denial recorded | Correlate firewall rules and 5-tuple with timestamps |
| Unexpected listening service | Unapproved listener reported | Determine owning process, interface binding, and business need |

Each case models *observations* rather than live measurements. The tool produces **candidate fault domains and recommended next checks**, never a definitive root cause or an automatic remediation command.

## Data model

Every case has a unique id and an observations object with these required fields:

- link_up, ip_configuration_valid, gateway_reachable, dns_answer_expected, remote_ip_reachable, application_port_reachable, firewall_deny_logged, unexpected_traffic: each true, false, or null when unobserved.
- unexpected_listening_ports: up to 32 unique integer port numbers or null if not observed. An empty list means no unexpected listeners were reported.

Explicit null values matter: absence of evidence must not be interpreted as evidence of failure. The input model rejects missing or unknown fields and limits the JSON file to 128 KiB and 32 cases.

## What this does not do

This is a deterministic, offline diagnostic reasoning exercise. It does **not** run ping, traceroute, nslookup, packet capture, ss, firewall queries, SSH, or AWS API calls. It does not prove a firewall blocked a connection, diagnose an actual device, or modify anything. Reachability probes can be affected by ICMP policy, and a symptom alone cannot establish causation.

The original WGU case study reports historical troubleshooting experience. The current code and its [automated tests](../tests/test_triage.py) are **independent evidence of Python implementation and testing**, not proof that the historical lab is still operating.

See the [evidence map](../docs/evidence-map.md) for a reviewer-oriented comparison of the two kinds of evidence.
