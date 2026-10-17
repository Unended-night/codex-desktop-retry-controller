"""Fast tests: no Codex process, no installed-program writes, no network."""
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from controller.core import ControllerError, b64, profile, recover_baseline, sha
from controller.core import exclusive_binary, version_of


class Inputs(unittest.TestCase):
    def test_zero_and_fractional_seconds(self):
        self.assertEqual(profile("0", "0"), {"max_retries": 0, "interval_ms": 0})
        self.assertEqual(profile("1000", "0.5"), {"max_retries": 1000, "interval_ms": 500})
        self.assertEqual(profile(1000000, "60"), {"max_retries": 1000000, "interval_ms": 60000})
        self.assertEqual(profile(3, "0.001")["interval_ms"], 1)

    def test_invalid_inputs_fail_before_write(self):
        for count, interval in [(-1, "0.5"), ("1.2", "0.5"), (True, "1"), (1000001, "1"),
                                (3, "NaN"), (3, "Infinity"), (3, "-1"), (3, "0.0001"), (3, "61")]:
            with self.subTest(count=count, interval=interval), self.assertRaises(ControllerError):
                profile(count, interval)


class Undo(unittest.TestCase):
    def setUp(self):
        self.original = b"HEADER-original-FOOTER"
        self.journal = {"format": 1, "size": len(self.original), "base_sha256": sha(self.original),
                        "slots": [{"offset": 7, "before": b64(b"original"),
                                   "after": b64(b"newvalue"), "previous": b64(b"oldvalue")} ]}

    def test_undo_new_and_previous_profile(self):
        for middle in [b"newvalue", b"oldvalue", b"original"]:
            self.assertEqual(recover_baseline(b"HEADER-" + middle + b"-FOOTER", self.journal), self.original)

    def test_interrupted_write_is_recoverable(self):
        for index in range(9):
            middle = b"newvalue"[:index] + b"oldvalue"[index:]
            self.assertEqual(recover_baseline(b"HEADER-" + middle + b"-FOOTER", self.journal), self.original)

    def test_unrelated_modification_refused(self):
        with self.assertRaises(ControllerError):
            recover_baseline(b"HEADER-newvalue-FOOTEr", self.journal)

    def test_unknown_modified_bytes_refused(self):
        with self.assertRaises(ControllerError):
            recover_baseline(b"HEADER-xxxxxxxx-FOOTER", self.journal)

    def test_overlapping_or_out_of_bounds_journal_refused(self):
        for off in [-1, 1000]:
            journal = dict(self.journal, slots=[dict(self.journal["slots"][0], offset=off)])
            with self.assertRaises(ControllerError):
                recover_baseline(self.original, journal)


class FileSafety(unittest.TestCase):
    def test_unknown_build_refused(self):
        with self.assertRaises(ControllerError):
            version_of(b"MZ-not-the-verified-engine")

    def test_open_file_refused_without_modification(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.exe"
            path.write_bytes(b"unchanged")
            with path.open("rb"), patch("controller.core.time.monotonic", side_effect=[0, 100]):
                with self.assertRaises(ControllerError):
                    with exclusive_binary(path):
                        self.fail("Opened an occupied file for writing")
            self.assertEqual(path.read_bytes(), b"unchanged")


if __name__ == "__main__":
    unittest.main()
