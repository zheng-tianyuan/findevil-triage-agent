import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from find_evil_agent import run


class FindEvilAgentTest(unittest.TestCase):
    def test_run_self_corrects_unsupported_claim(self):
        out_dir = ROOT / "artifacts-test"
        if out_dir.exists():
            for child in out_dir.iterdir():
                child.unlink()
            out_dir.rmdir()

        report = run(ROOT / "data" / "case-001", out_dir)

        self.assertEqual(len(report["supportedFindings"]), 8)
        self.assertEqual(report["summary"]["supportedFindingCount"], 8)
        self.assertEqual(report["summary"]["selfCorrectionCount"], 2)
        self.assertGreaterEqual(report["summary"]["topRiskScore"], 90)
        self.assertTrue(any(item["action"] == "removed" for item in report["selfCorrections"]))
        self.assertTrue(all(item["evidence"] for item in report["supportedFindings"]))
        self.assertTrue((out_dir / "execution-log.jsonl").exists())
        self.assertTrue((out_dir / "report.json").exists())

        for child in out_dir.iterdir():
            child.unlink()
        out_dir.rmdir()


if __name__ == "__main__":
    unittest.main()
