import os
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

PIN = PROJECT_ROOT / "pin_kit/pin"

PINTOOL = (
    PROJECT_ROOT /
    "pin_kit/source/tools/MyPinTool/obj-intel64/MyPinTool.so"
)

TESTS_DIR = PROJECT_ROOT / "tests"
BIN_DIR = TESTS_DIR / "bin"
REPORTS_DIR = PROJECT_ROOT / "reports"

BIN_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

cpp_files = list(TESTS_DIR.glob("*.cpp"))

if not cpp_files:
    print("No test files found.")
    exit(0)

print(f"Found {len(cpp_files)} test files.\n")

for cpp_file in cpp_files:
    test_name = cpp_file.stem
    binary_path = BIN_DIR / test_name
    report_path = REPORTS_DIR / f"{test_name}.json"

    print("=" * 60)
    print(f"TEST: {test_name}")
    print("=" * 60)

    compile_cmd = [
        "g++",
        str(cpp_file),
        "-o",
        str(binary_path)
    ]

    print("\n[1] Compiling...")

    compile_result = subprocess.run(
        compile_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if compile_result.returncode != 0:
        print("Compilation FAILED\n")
        print(compile_result.stderr)
        continue

    print("Compilation SUCCESS")

    pin_cmd = [
        str(PIN),
        "-t",
        str(PINTOOL),
        "-o",
        str(report_path),
        "--",
        str(binary_path)
    ]

    print("\n[2] Running Pintool...")

    run_result = subprocess.run(
        pin_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if run_result.returncode != 0:
        print("Pintool execution FAILED\n")
        print(run_result.stderr)
        continue

    print("Pintool SUCCESS")

    print(f"\nGenerated report:")
    print(report_path)

print("\n")
print("=" * 60)
print("BATCH TESTING COMPLETE")
print("=" * 60)