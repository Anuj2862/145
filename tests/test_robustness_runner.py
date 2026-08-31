"""Unit tests for Phase 2E Adversarial Robustness & Evasion Boundary Runner."""

import os
import tempfile
import unittest
from pathlib import Path

from evaluation.runners.robustness_runner import RobustnessTestbedGenerator, RobustnessAnalysisRunner


class TestRobustnessRunner(unittest.TestCase):
    def test_robustness_suite_generation_and_execution(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            testbed_dir = Path(tmpdir) / "pcaps"
            results_dir = Path(tmpdir) / "results"
            reports_dir = Path(tmpdir) / "reports"

            suite = RobustnessTestbedGenerator.generate_perturbations(testbed_dir)
            self.assertGreaterEqual(len(suite), 10)

            # Ensure all PCAPs are written and readable
            for item in suite:
                self.assertTrue(os.path.exists(item["pcap_path"]))
                self.assertGreater(os.path.getsize(item["pcap_path"]), 24)

            runner = RobustnessAnalysisRunner(artifact_dir="models/artifacts")
            payload = runner.run_robustness_study(
                testbed_dir=str(testbed_dir),
                output_dir=str(results_dir),
                report_dir=str(reports_dir),
            )

            self.assertEqual(payload["status"], "COMPLETED")
            self.assertIn("categories", payload["results"])
            self.assertIn("C2_BEACON_JITTER", payload["results"]["categories"])
            self.assertIn("RECON_SCAN_RATE", payload["results"]["categories"])
            self.assertIn("DDOS_VELOCITY_SCALING", payload["results"]["categories"])

            self.assertEqual(len(list(results_dir.glob("*.json"))), 1)
            self.assertEqual(len(list(reports_dir.glob("*.md"))), 1)


if __name__ == "__main__":
    unittest.main()
