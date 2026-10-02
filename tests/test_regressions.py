from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from pe_hardening_review import inspect_file, PEFormatError
from test_parser import fixture


class RegressionTests(unittest.TestCase):
    def test_file_reader_limit_is_enforced(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"owned.exe"
            path.write_bytes(fixture(pe_plus=True,flags=0))
            with patch("pe_hardening_review.parser.MAX_FILE_BYTES",128),self.assertRaises(PEFormatError):
                inspect_file(path)
