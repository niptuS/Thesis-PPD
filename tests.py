#!/usr/bin/env python3
"""
SH-DATASET — Test Runner & Quality Report
Ejecuta: unittest suite + flake8 + pylint
Genera: reports/test_report.txt
"""
import sys
import os
import unittest
import subprocess
from datetime import datetime

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)


def run_unit_tests():
    """Run unittest suite and return results."""
    print("=" * 60)
    print("  UNITTEST — Suite de Pruebas Unitarias")
    print("=" * 60)
    loader = unittest.TestLoader()
    suite = loader.discover("tests", pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result


def run_flake8():
    """Run flake8 and return output."""
    print("\n" + "=" * 60)
    print("  FLAKE8 — Cumplimiento PEP 8")
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
            print("  ✓ Sin violaciones de estilo")
        else:
            print(output)
        return output, result.returncode
    except FileNotFoundError:
        msg = "  flake8 no instalado: pip install flake8"
        print(msg)
        return msg, -1


def run_pylint():
    """Run pylint and return score."""
    print("\n" + "=" * 60)
    print("  PYLINT — Puntuación de Código")
    print("=" * 60)
    targets = [
        "modules/attacks/__init__.py",
        "modules/attacks/base.py",
        "modules/timeline/timeline_manager.py",
        "modules/profiles/profile_schema.py",
        "modules/profiles/endpoint_scanner.py",
        "modules/communication/ssh_executor.py",
        "modules/communication/http_executor.py",
        "modules/communication/attacker_profile.py",
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
        # extract score
        score_line = ""
        for line in output.split("\n"):
            if "rated at" in line.lower() or "your code has been" in line.lower():
                score_line = line.strip()
                break
        print(output[-500:] if len(output) > 500 else output)
        return output, score_line
    except FileNotFoundError:
        msg = "  pylint no instalado: pip install pylint"
        print(msg)
        return msg, ""


def generate_report(test_result, flake8_output, flake8_rc, pylint_output, pylint_score):
    """Generate combined quality report."""
    report_path = os.path.join(REPORT_DIR, f"quality_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("  SH-DATASET — Reporte de Calidad de Software\n")
        f.write(f"  Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")

        # unittest results
        f.write("1. PRUEBAS UNITARIAS (unittest)\n")
        f.write("-" * 40 + "\n")
        f.write(f"  Tests ejecutados : {test_result.testsRun}\n")
        f.write(f"  Exitosos         : {test_result.testsRun - len(test_result.failures) - len(test_result.errors)}\n")
        f.write(f"  Fallidos         : {len(test_result.failures)}\n")
        f.write(f"  Errores          : {len(test_result.errors)}\n")
        f.write(f"  Resultado        : {'PASSED ✓' if test_result.wasSuccessful() else 'FAILED ✗'}\n")

        if test_result.failures:
            f.write("\n  Failures:\n")
            for test, traceback in test_result.failures:
                f.write(f"    - {test}: {traceback[:200]}\n")
        if test_result.errors:
            f.write("\n  Errors:\n")
            for test, traceback in test_result.errors:
                f.write(f"    - {test}: {traceback[:200]}\n")

        # flake8
        f.write("\n\n2. CUMPLIMIENTO PEP 8 (flake8)\n")
        f.write("-" * 40 + "\n")
        if flake8_rc == 0:
            f.write("  Resultado: CUMPLE ✓ (0 violaciones)\n")
        elif flake8_rc == -1:
            f.write("  Resultado: NO EJECUTADO (flake8 no instalado)\n")
        else:
            violations = len([l for l in flake8_output.split("\n") if l.strip() and ":" in l])
            f.write(f"  Violaciones: {violations}\n")
            f.write(f"  Detalle:\n{flake8_output[:2000]}\n")

        # pylint
        f.write("\n\n3. PUNTUACIÓN DE CÓDIGO (pylint)\n")
        f.write("-" * 40 + "\n")
        if pylint_score:
            f.write(f"  {pylint_score}\n")
        else:
            f.write("  No ejecutado o sin puntuación\n")

        f.write("\n" + "=" * 70 + "\n")
        f.write("  Fin del reporte\n")
        f.write("=" * 70 + "\n")

    print(f"\n{'=' * 60}")
    print(f"  Reporte guardado: {report_path}")
    print(f"{'=' * 60}")
    return report_path


if __name__ == "__main__":
    test_result = run_unit_tests()
    flake8_out, flake8_rc = run_flake8()
    pylint_out, pylint_score = run_pylint()
    report = generate_report(test_result, flake8_out, flake8_rc, pylint_out, pylint_score)

    # exit code: 0 if all tests passed
    sys.exit(0 if test_result.wasSuccessful() else 1)
