from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import os
import json
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