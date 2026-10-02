from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import struct
import tempfile
import unittest

from pe_hardening_review import PEFormatError, inspect_bytes, inspect_file
from pe_hardening_review.cli import main


def fixture(*, pe_plus: bool, flags: int, characteristics: int = 0) -> bytes:
    pe = 0x80
    optional_size = 0xF0 if pe_plus else 0xE0
    result = bytearray(pe + 24 + optional_size + 40)
    result[:2] = b"MZ"
    struct.pack_into("<I", result, 0x3C, pe)
    result[pe:pe + 4] = b"PE\0\0"
    coff = pe + 4
    struct.pack_into("<HH", result, coff, 0x8664 if pe_plus else 0x14C, 1)
    struct.pack_into("<HH", result, coff + 16, optional_size, characteristics)
    optional = coff + 20
    struct.pack_into("<H", result, optional, 0x20B if pe_plus else 0x10B)
    struct.pack_into("<H", result, optional + 70, flags)
    return bytes(result)


class PEReviewTests(unittest.TestCase):
    def test_pe32_plus_declarations(self):
        report = inspect_bytes(fixture(pe_plus=True, flags=0x0020 | 0x0040 | 0x0100 | 0x4000))
        self.assertEqual(report.format, "PE32+")
        self.assertEqual(report.machine, "0x8664")
        self.assertEqual(report.review_notes, ())
        self.assertTrue(report.high_entropy_va_declared)

    def test_pe32_missing_flags_are_review_notes(self):
        report = inspect_bytes(fixture(pe_plus=False, flags=0, characteristics=1))
        self.assertEqual(report.format, "PE32")
        self.assertIsNone(report.high_entropy_va_declared)
        self.assertEqual(len(report.review_notes), 4)
        self.assertTrue(report.relocations_stripped)

    def test_rejects_truncated_or_invalid_layout(self):
        original = fixture(pe_plus=True, flags=0)
        for data in (b"", original[:0x40], original[:-1]):
            with self.subTest(length=len(data)), self.assertRaises(PEFormatError):
                inspect_bytes(data)
        bad_offset = bytearray(original)
        struct.pack_into("<I", bad_offset, 0x3C, len(original) - 2)
        with self.assertRaises(PEFormatError):
            inspect_bytes(bytes(bad_offset))
        bad_magic = bytearray(original)
        struct.pack_into("<H", bad_magic, 0x80 + 24, 0x999)
        with self.assertRaises(PEFormatError):
            inspect_bytes(bytes(bad_magic))
        short_optional = bytearray(original)
        struct.pack_into("<H", short_optional, 0x80 + 4 + 16, 72)
        with self.assertRaises(PEFormatError):
            inspect_bytes(bytes(short_optional))

    def test_file_cli_json_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "owned.exe"
            path.write_bytes(fixture(pe_plus=True, flags=0x0040 | 0x0100))
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(main([str(path), "--json"]), 0)
            self.assertEqual(json.loads(output.getvalue())["section_count"], 1)
            self.assertEqual(inspect_file(path).format, "PE32+")
            link = root / "linked.exe"
            link.symlink_to(path)
            with self.assertRaises(PEFormatError):
                inspect_file(link)


if __name__ == "__main__":
    unittest.main()
