# Engineering Evidence Map

This repository contains two distinct kinds of evidence. They must **not** be presented as interchangeable.

## Historical academic case study

The [main README](../README.md) describes six categories of troubleshooting explored during prior WGU work: packet analysis, incorrect DNS results, network routing, host IP configuration, DMZ firewall policy, and unauthorized listeners. The public write-up is a **sanitized narrative**; it does not contain the university's original instructions, device files, captures, screenshots, or a reproducible copy of its lab network.

## New, independent executable evidence

| Original case-study subject | Fictional observation in [sample JSON](../portfolio_demo/sample_cases.json) | Independently tested Python behavior | Verification boundary |
|---|---|---|---|
| Suspicious network traffic | Unexpected traffic flag | Suggests packet/flow review | No PCAP read, capture, or traffic inspection |
| DNS redirection | Unexpected DNS answer | Flags possible DNS mismatch; suggests resolver/record checks | No live DNS queries |
| Routing/forwarding | Gateway reachable, remote IP test fails | Suggests remote-path investigation | No actual ping or traceroute |
| Endpoint IP configuration | Invalid reported host addressing | Suggests DHCP, gateway and prefix review | No local NIC changes |
| DMZ firewall access | Reported firewall deny event | Suggests policy/log correlation | No firewall API or live rule evaluation |
| Unapproved listening ports | Reported unknown port | Suggests process ownership/exposure review | No socket enumeration or port scanning |

The [independent Python tool](../portfolio_demo/triage.py) validates inputs and emits **candidate fault domains** with specific, non-destructive next checks. Its [unit tests](../tests/test_triage.py) cover deterministic results, multiple simultaneous clues, unknown observations, and invalid inputs. [GitHub Actions](../.github/workflows/verify-triage.yml) runs tests on Linux and Windows.

The synthetic flags are **not actual observed outcomes** from the prior WGU exercise. Automated CI confirms only that this program performs its modeled checks consistently; it does not prove a real service is available, a firewall policy is correct, or a root cause has been discovered.

## Interview explanation

Describe the original project as evidence of your hands-on troubleshooting workflow, and the independent code as proof you can encode that workflow into repeatable, testable logic.

A useful engineering sequence is: establish impact; collect observations; isolate possible fault domains; check positive and negative evidence; change only the responsible configuration with authorization; verify functionality; document findings.

**Limitations and next iteration:** A later independently developed version could collect optional local diagnostics from a test container, parse sanitized fixture logs, or analyze explicitly provided mock packet metadata. Those capabilities have not been implemented here.
