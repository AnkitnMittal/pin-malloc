from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import json
import tempfile
import subprocess

from pathlib import Path

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"

PIN_PATH = PROJECT_ROOT / "pin_kit/pin"

PINTOOL_PATH = (
    PROJECT_ROOT /
    "pin_kit/source/tools/MyPinTool/obj-intel64/MyPinTool.so"
)

class CodeRequest(BaseModel):
    code: str

@app.get("/")
def root():
    return {
        "message": "Memory Trace Backend Running"
    }

@app.get("/reports")
def get_reports():
    reports = []
    
    for file in REPORTS_DIR.glob("*.json"):
        with open(file, "r") as f:
            data = json.load(f)

            reports.append({
                "test_name": file.stem,
                "data": data
            })

    return reports

@app.get("/reports/{test_name}")
def get_single_report(test_name: str):
    
    file_path = REPORTS_DIR / f"{test_name}.json"

    if not file_path.exists():
        return {"error": "Report not found"}

    with open(file_path, "r") as f:
        return json.load(f)
    
@app.post("/analyze")
def analyze_code(req: CodeRequest):

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        source_path = tmpdir / "user.cpp"
        binary_path = tmpdir / "user_bin"
        report_path = tmpdir / "report.json"

        with open(source_path, "w") as f:
            f.write(req.code)

        compile_cmd = [
            "g++",
            "-g",
            str(source_path),
            "-o",
            str(binary_path)
        ]

        compile_result = subprocess.run(
            compile_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )

        if compile_result.returncode != 0:
            return {
                "success": False,
                "compile_error": compile_result.stderr
            }

        pin_cmd = [
            str(PIN_PATH),
            "-t",
            str(PINTOOL_PATH),
            "-o",
            str(report_path),
            "--",
            str(binary_path)
        ]

        try:
            run_result = subprocess.run(
                pin_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10
            )

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "runtime_error": "Execution timed out"
            }

        if run_result.returncode != 0:
            return {
                "success": False,
                "runtime_error": run_result.stderr
            }

        if not report_path.exists():
            return {
                "success": False,
                "runtime_error": "Report generation failed"
            }

        with open(report_path, "r") as f:
            report = json.load(f)

        diagnostics = []

        for leak in report.get("leaks", []):
            if leak.get("line", -1) < 1:
                continue
            
            diagnostics.append({
                "line": leak.get("line", 1),
                "message": f"Memory leak detected ({leak.get('size', 0)} bytes)",
                "severity": "error"
            })

        return {
            "success": True,
            "report": report,
            "diagnostics": diagnostics
        }