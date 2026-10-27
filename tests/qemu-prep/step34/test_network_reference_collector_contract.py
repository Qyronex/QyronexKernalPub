#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
COLLECTOR = ROOT / "tools/qemu-prep/step34/collect_network_reference.sh"


class Step34NetworkReferenceCollectorContractTest(unittest.TestCase):
    def test_reference_is_source_target_and_arch_bound(self) -> None:
        text = COLLECTOR.read_text(encoding="utf-8")
        for fragment in (
            'reference guest must be ARM64',
            'reference guest must be Debian 13',
            'reference guest must be Trixie',
            'SOURCE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)',
            'TARGET_SHA256=$(sha256sum "$TARGET"',
            'STEP34_NETWORK_REFERENCE_OK',
        ):
            self.assertIn(fragment, text)

    def test_active_probe_is_explicitly_authorized(self) -> None:
        text = COLLECTOR.read_text(encoding="utf-8")
        self.assertIn('KERNAL_STEP34_RUN_ACTIVE_PROBE:-0', text)
        self.assertIn('KERNAL_REFERENCE_NETWORK_PROBE_CONFIRMED:-0', text)
        self.assertIn('active network probe requires KERNAL_REFERENCE_NETWORK_PROBE_CONFIRMED=1', text)

    def test_dns_capture_uses_glibc_consumer_and_optional_network_strace(self) -> None:
        text = COLLECTOR.read_text(encoding="utf-8")
        self.assertIn('getent ahosts "$KERNAL_DNS_NAME"', text)
        self.assertIn('strace -f -s 256 -yy -e trace=network', text)
        self.assertIn('dns-network.strace', text)

    def test_collector_is_observational(self) -> None:
        text = COLLECTOR.read_text(encoding="utf-8")
        forbidden = (
            'ip link set',
            'ip addr add',
            'ip route add',
            'resolvectl dns',
            'systemctl restart',
        )
        for fragment in forbidden:
            self.assertNotIn(fragment, text)


if __name__ == "__main__":
    unittest.main()
