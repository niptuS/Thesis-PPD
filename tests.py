#!/usr/bin/env python3
"""
Entrada: None
Salida: int (exit code)
Descripción: SH-DATASET — Test Runner & Quality Report.
             Runs: unittest suite + flake8 + pylint.
             Generates: reports/test_report.txt
"""
import sys
import os
import unittest
import subprocess
from datetime import datetime

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)


def run_unit_tests():
    """
    Entrada: None
    Salida: unittest.TestResult
    Descripción: Runs the unittest suite and returns the result.
    """
    print("=" * 60)
    print("  UNITTEST — Unit Test Suite")
    print("=" * 60)
    loader = unittest.TestLoader()
    suite = loader.discover("tests", pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result


def run_flake8():
    """
    Entrada: None
    Salida: tuple[str, int]
    Descripción: Runs flake8 and returns (output, returncode).
    """
    print("\n" + "=" * 60)
    print("  FLAKE8 — PEP 8 Compliance")
    print("=" * 60)
    targets = ["modules/", "design/handlers/"]
    try:
        result = subprocess.run(
            [sys.executable, "-m", "flake8", "--config=.flake8"] + targets,
            capture_output=True, timeout=60,
            encoding="utf-8", errors="replace",
        check=False,
        )
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0:
            print("  ✓ No style violations")
        else:
            print(output)
        return output, result.returncode
    except FileNotFoundError:
        msg = "  flake8 not installed: pip install flake8"
        print(msg)
        return msg, -1


def run_pylint():
    """
    Entrada: None
    Salida: tuple[str, str]
    Descripción: Runs pylint and returns (output, score_line).
    """
    print("\n" + "=" * 60)
    print("  PYLINT — Code Score")
    print("=" * 60)
    targets = [
        "modules/attacks/__init__.py",
        "modules/attacks/base.py",
        "modules/timeline/timeline_manager.py",
        "modules/profiles/profile_schema.py",
        "modules/profiles/endpoint_scanner.py",
        "modules/comms/__init__.py",
        "modules/comms/base.py",
        "modules/comms/http_channel.py",
        "modules/comms/ssh_channel.py",
        "modules/comms/dispatcher.py",
        "modules/services/__init__.py",
        "modules/services/capture_service.py",
        "modules/services/event_executor.py",
        "modules/services/flow_extractor.py",
        "modules/services/flow_labeler.py",
        "modules/services/artifact_manifest_writer.py",
        "modules/live_executions/live_execution.py",
        "modules/devices/scanner.py",
        "modules/devices/host_detector.py",
    ]
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pylint", "--rcfile=.pylintrc"] + targets,
            capture_output=True, timeout=120,
            encoding="utf-8", errors="replace",
        check=False,
        )
        output = (result.stdout or "") + (result.stderr or "")
        score_line = ""
        for line in output.split("\n"):
            if "rated at" in line.lower() or "your code has been" in line.lower():
                score_line = line.strip()
                break
        print(output[-500:] if len(output) > 500 else output)
        return output, score_line
    except FileNotFoundError:
        msg = "  pylint not installed: pip install pylint"
        print(msg)
        return msg, ""


def generate_report(test_result, flake8_output, flake8_rc, pylint_output, pylint_score):
    """
    Entrada: test_result, flake8_output, flake8_rc, pylint_output, pylint_score
    Salida: str
    Descripción: Generates the combined quality report and returns its path.
    """
    report_path = os.path.join(REPORT_DIR, f"quality_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("  SH-DATASET — Software Quality Report\n")
        f.write(f"  Date: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")

        f.write("1. UNIT TESTS (unittest)\n")
        f.write("-" * 40 + "\n")
        f.write(f"  Tests run    : {test_result.testsRun}\n")
        f.write(f"  Successful   : {test_result.testsRun - len(test_result.failures) - len(test_result.errors)}\n")
        f.write(f"  Failures     : {len(test_result.failures)}\n")
        f.write(f"  Errors       : {len(test_result.errors)}\n")
        f.write(f"  Result       : {'PASSED ✓' if test_result.wasSuccessful() else 'FAILED ✗'}\n")

        if test_result.failures:
            f.write("\n  Failures:\n")
            for test, traceback in test_result.failures:
                f.write(f"    - {test}: {traceback[:200]}\n")
        if test_result.errors:
            f.write("\n  Errors:\n")
            for test, traceback in test_result.errors:
                f.write(f"    - {test}: {traceback[:200]}\n")

        f.write("\n\n2. PEP 8 COMPLIANCE (flake8)\n")
        f.write("-" * 40 + "\n")
        if flake8_rc == 0:
            f.write("  Result: PASS ✓ (0 violations)\n")
        elif flake8_rc == -1:
            f.write("  Result: NOT RUN (flake8 not installed)\n")
        else:
            violations = len([l for l in flake8_output.split("\n") if l.strip() and ":" in l])
            f.write(f"  Violations: {violations}\n")
            f.write(f"  Detail:\n{flake8_output[:2000]}\n")

        f.write("\n\n3. CODE SCORE (pylint)\n")
        f.write("-" * 40 + "\n")
        if pylint_score:
            f.write(f"  {pylint_score}\n")
        else:
            f.write("  Not run or no score\n")

        f.write("\n" + "=" * 70 + "\n")
        f.write("  End of report\n")
        f.write("=" * 70 + "\n")

    print(f"\n{'=' * 60}")
    print(f"  Report saved: {report_path}")
    print(f"{'=' * 60}")
    return report_path


if __name__ == "__main__":
    test_result = run_unit_tests()
    flake8_out, flake8_rc = run_flake8()
    pylint_out, pylint_score = run_pylint()
    report = generate_report(test_result, flake8_out, flake8_rc, pylint_out, pylint_score)

    sys.exit(0 if test_result.wasSuccessful() else 1)
