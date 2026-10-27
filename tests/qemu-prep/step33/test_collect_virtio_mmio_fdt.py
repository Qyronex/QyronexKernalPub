#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tools/qemu-prep/step33/collect_virtio_mmio_fdt.py"
SPEC = importlib.util.spec_from_file_location("step33_fdt", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def cells(*values: int) -> bytes:
    return struct.pack(f">{len(values)}I", *values)


class Step33VirtioMmioFdtTest(unittest.TestCase):
    def make_fixture(self, root: Path, *, size: int = 0x200, include_reg: bool = True) -> tuple[Path, Path]:
        dt = root / "dt"
        sysfs = root / "sysfs"
        dt.mkdir()
        sysfs.mkdir()
        (dt / "#address-cells").write_bytes(cells(2))
        (dt / "#size-cells").write_bytes(cells(2))
        node = dt / "virtio_mmio@a000000"
        node.mkdir()
        (node / "compatible").write_bytes(b"virtio,mmio\0")
        if include_reg:
            (node / "reg").write_bytes(cells(0, 0x0A000000, 0, size))
        (node / "interrupts").write_bytes(cells(0, 16, 4))
        virtio = sysfs / "virtio0"
        virtio.mkdir()
        (virtio / "device").write_text("0x0002\n", encoding="ascii")
        (virtio / "vendor").write_text("0x1af4\n", encoding="ascii")
        return dt, sysfs

    def test_collects_discovered_address_without_hardcoding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dt, sysfs = self.make_fixture(Path(tmp))
            result = MODULE.collect(dt, sysfs)
        self.assertFalse(result["fdt"]["hardcoded_address_required"])
        self.assertEqual(result["fdt"]["virtio_mmio_nodes"][0]["reg"][0]["base"], 0x0A000000)
        self.assertEqual(result["fdt"]["virtio_mmio_nodes"][0]["reg"][0]["size"], 0x200)
        self.assertEqual(result["virtio"]["block_device_count"], 1)

    def test_rejects_missing_reg_property(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dt, sysfs = self.make_fixture(Path(tmp), include_reg=False)
            with self.assertRaisesRegex(ValueError, "lacks reg/interrupts"):
                MODULE.collect(dt, sysfs)

    def test_rejects_zero_length_mmio_range(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dt, sysfs = self.make_fixture(Path(tmp), size=0)
            with self.assertRaisesRegex(ValueError, "zero-length MMIO range"):
                MODULE.collect(dt, sysfs)

    def test_rejects_truncated_reg_cells(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dt, sysfs = self.make_fixture(Path(tmp))
            node = next(dt.glob("virtio_mmio@*"))
            (node / "reg").write_bytes(cells(0, 0x0A000000, 0))
            with self.assertRaisesRegex(ValueError, "truncated reg"):
                MODULE.collect(dt, sysfs)


if __name__ == "__main__":
    unittest.main()
