#!/usr/bin/env python3
"""Classify synthetic network observations into investigation candidates.

Independent portfolio demonstration: no packet capture, device access, DNS
queries, network changes, or privileged operations are performed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

MAX_BYTES = 128 * 1024
SIGNALS = (
    "link_up",
    "ip_configuration_valid",
    "gateway_reachable",
    "dns_answer_expected",
    "remote_ip_reachable",
    "application_port_reachable",
    "firewall_deny_logged",
    "unexpected_traffic",
    "unexpected_listening_ports",
)
BOOL_SIGNALS = SIGNALS[:-1]


class DiagnosticInputError(ValueError):
    """The synthetic observation model is malformed or inconsistent."""


def validate_cases(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise DiagnosticInputError("document must be an object")
    cases = payload.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 32:
        raise DiagnosticInputError("cases must contain 1-32 objects")
    seen: set[str] = set()
    validated = []
    for index, case in enumerate(cases):
        prefix = f"cases[{index}]"
        if not isinstance(case, dict):
            raise DiagnosticInputError(f"{prefix} must be an object")
        case_id = case.get("id")
        if (
            not isinstance(case_id, str)
            or not 1 <= len(case_id) <= 64
            or not all(char.isascii() and (char.isalnum() or char in "-_") for char in case_id)
        ):
            raise DiagnosticInputError(f"{prefix}.id must be 1-64 ASCII letters, digits, '-' or '_'")
        if case_id in seen:
            raise DiagnosticInputError(f"duplicate case id: {case_id}")
        seen.add(case_id)
        observations = case.get("observations")
        if not isinstance(observations, dict):
            raise DiagnosticInputError(f"{prefix}.observations must be an object")
        if set(observations) != set(SIGNALS):
            missing = sorted(set(SIGNALS) - set(observations))
            extra = sorted(set(observations) - set(SIGNALS))
            raise DiagnosticInputError(f"{prefix}: missing signals={missing}, unexpected signals={extra}")
        for key in BOOL_SIGNALS:
            value = observations[key]
            if value is not None and type(value) is not bool:
                raise DiagnosticInputError(f"{prefix}.{key} must be true, false, or null")
        ports = observations["unexpected_listening_ports"]
        if ports is not None:
            if (
                not isinstance(ports, list)
                or len(ports) > 32
                or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)
                or len(ports) != len(set(ports))
            ):
                raise DiagnosticInputError(
                    f"{prefix}.unexpected_listening_ports must be null or up to 32 unique TCP/UDP port numbers"
                )
        validated.append({"id": case_id, "observations": observations})
    return validated


def analyze_case(case: dict[str, Any]) -> dict[str, Any]:
    """Generate candidate investigations, not a proven root-cause diagnosis."""
    o = case["observations"]
    findings: list[dict[str, str]] = []

    def add(code: str, evidence: str, next_check: str) -> None:
        findings.append({"code": code, "evidence": evidence, "next_check": next_check})

    if o["link_up"] is False:
        add("LINK_DOWN", "The reported interface link is down.",
            "Confirm power, cable, link LEDs, port status, and interface error history.")
    if o["ip_configuration_valid"] is False:
        add("ADDRESSING_MISMATCH", "The reported endpoint IP configuration is invalid.",
            "Inspect DHCP lease, subnet prefix, gateway, and assigned DNS settings.")
    if (
        o["gateway_reachable"] is False
        and o["link_up"] is not False
        and o["ip_configuration_valid"] is not False
    ):
        add("GATEWAY_PATH", "The default gateway is reported unreachable.",
            "Check local VLAN, switch port, ARP, gateway interface, and filtering; ICMP may be blocked.")
    if o["dns_answer_expected"] is False:
        add("DNS_MISMATCH", "The observed DNS answer does not match the reference.",
            "Compare resolver selection, authoritative records, caches, and known-good responses.")
    if o["remote_ip_reachable"] is False and o["gateway_reachable"] is True:
        add("REMOTE_PATH", "The gateway is reachable but the remote IP test failed.",
            "Inspect routes, traceroute, network filtering, destination state, and ICMP policy.")
    if o["firewall_deny_logged"] is True:
        add("FIREWALL_POLICY", "A relevant firewall denial was reported in logs.",
            "Correlate rule, source, destination, protocol, port, and timestamp before changes.")
    if (
        o["application_port_reachable"] is False
        and o["remote_ip_reachable"] is True
        and o["firewall_deny_logged"] is not True
    ):
        add("APPLICATION_PATH", "IP test succeeded but application port test failed.",
            "Check host listeners, service health, ACLs, and TCP connection logs.")
    if o["unexpected_traffic"] is True:
        add("TRAFFIC_REVIEW", "Traffic not matching the expected baseline was reported.",
            "Review a sanctioned packet capture, flow metadata, destination, and process ownership.")
    if o["unexpected_listening_ports"]:
        add("LISTENER_REVIEW", "Unexpected listening ports were reported.",
            "Confirm process ownership, interface binding, business need, and firewall exposure.")

    gaps = [signal for signal in SIGNALS if o[signal] is None]
    return {
        "id": case["id"],
        "status": "INVESTIGATE" if findings else "NO_ANOMALY_CONFIRMED",
        "findings": findings,
        "missing_evidence": gaps,
    }


def analyze_document(payload: Any) -> list[dict[str, Any]]:
    return [analyze_case(case) for case in validate_cases(payload)]


def load_document(path: Path) -> Any:
    try:
        with path.open("rb") as file:
            data = file.read(MAX_BYTES + 1)
    except OSError as exc:
        raise DiagnosticInputError(f"unable to read file: {type(exc).__name__}") from exc
    if len(data) > MAX_BYTES:
        raise DiagnosticInputError("input exceeds 128 KiB")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DiagnosticInputError("input must be valid UTF-8 JSON") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path(__file__).with_name("sample_cases.json"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        results = analyze_document(load_document(args.input))
    except DiagnosticInputError as exc:
        parser.exit(2, f"Invalid synthetic observations: {exc}\n")
    if args.json:
        print(json.dumps({"mode": "offline_triage", "cases": results}, indent=2))
    else:
        for result in results:
            codes = [finding["code"] for finding in result["findings"]]
            print(f'{result["id"]}: {result["status"]} | candidates={codes}')
        print("Simulation only: findings are hypotheses, not verified root causes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
