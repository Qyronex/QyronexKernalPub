#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PROBE = ROOT / "tests/qemu-prep/step34/network_probe.c"


class Step34NetworkProbeContractTest(unittest.TestCase):
    def test_probe_covers_required_reference_surfaces(self) -> None:
        text = PROBE.read_text(encoding="utf-8")
        for fragment in (
            "AF_UNIX",
            "unix.stream-child-exit",
            "AF_INET6",
            "IPV6_V6ONLY",
            "ipv6.loopback-child-exit",
            "AF_NETLINK",
            "NETLINK_ROUTE",
            "netlink.malformed state=",
            "KERNAL_TCP_HOST",
            "tcp.host-endpoint-reply",
            "KERNAL_UDP_HOST",
            "udp.host-endpoint-reply",
            "KERNAL_DNS_NAME",
            "dns.address family=",
            "PASS step34.network-probe.complete",
        ):
            self.assertIn(fragment, text)

    def test_netlink_probe_is_observational_not_mutating(self) -> None:
        text = PROBE.read_text(encoding="utf-8")
        self.assertIn("RTM_GETLINK", text)
        for mutating_type in (
            "RTM_NEWLINK",
            "RTM_DELLINK",
            "RTM_NEWADDR",
            "RTM_DELADDR",
            "RTM_NEWROUTE",
            "RTM_DELROUTE",
        ):
            self.assertNotIn(mutating_type, text)

    def test_external_network_destinations_are_parameterized(self) -> None:
        text = PROBE.read_text(encoding="utf-8")
        self.assertIn('getenv("KERNAL_TCP_HOST")', text)
        self.assertIn('getenv("KERNAL_TCP_PORT")', text)
        self.assertIn('getenv("KERNAL_UDP_HOST")', text)
        self.assertIn('getenv("KERNAL_UDP_PORT")', text)
        self.assertIn('getenv("KERNAL_DNS_NAME")', text)


if __name__ == "__main__":
    unittest.main()
