# Memory Trace Dashboard using Intel PIN

A full-stack dynamic memory tracing and leak analysis platform built using Intel PIN, FastAPI, React, and Python automation.

This project instruments binaries at runtime using Intel PIN to analyze dynamic memory behavior such as:

- malloc
- calloc
- realloc
- free
- memory leaks
- allocation statistics
- memory access tracing

The system automatically:

- compiles test programs
- runs them through Intel PIN
- generates structured JSON reports
- visualizes results through a web dashboard

---

# Features

## Dynamic Memory Instrumentation

The Pintool intercepts:

- `malloc`
- `calloc`
- `realloc`
- `free`

---

## Memory Event Tracking

For every allocation/free event, the tool records:

- allocation type
- memory address
- allocation size
- calling function

---

## Leak Detection

Detects:

- leaked allocations
- partially freed programs
- unfreed reallocations

---

## Function-Level Statistics

Tracks:

- allocation count per function
- total allocated bytes per function

---

## JSON Report Generation

Each execution generates a structured JSON report.

Example:

```json
{
  "summary": {
    "total_allocations": 10,
    "total_frees": 9,
    "total_leaks": 1
  },

  "allocations": [],
  "frees": [],
  "leaks": [],
  "function_stats": []
}
```

---

## Automated Batch Testing

The Python batch runner:

- scans all `.cpp` test files
- compiles them automatically
- executes them through Intel PIN
- generates corresponding JSON reports

---

## Interactive Web Dashboard

The React dashboard provides:

- global memory statistics
- leak visualization charts
- searchable test explorer
- per-test inspection
- leak details table
- allocation statistics

---

# Tech Stack

| Component              | Technology |
| ---------------------- | ---------- |
| Binary Instrumentation | Intel PIN  |
| Reporting              | JSON       |
| Automation             | Python     |
| Backend API            | FastAPI    |
| Charts                 | Recharts   |
| Frontend               | React      |

---

# Project Architecture

```text
pin-malloc/
│
├── pin_kit/                  # Intel PIN framework
│   └── source/tools/MyPinTool/
│                    ├── MyPinTool.cpp
│                    └── obj-intel64/
│
├── reports/                  # Generated JSON reports
│
├── scripts/
│   └── run_batch.py          # Batch test runner
│
├── tests/
│   ├── t1.cpp
│   ├── t2.cpp
│   └── bin/                  # Compiled test binaries
│
├── web/
│   ├── backend/
│   │   └── app.py            # FastAPI backend
│   │
│   └── frontend/             # React dashboard
│
└── source/tools/MyPinTool/
    ├── MyPinTool.cpp
    └── obj-intel64/
```

---

# Commands Summary

## Build Pintool

```bash
cd pin_kit/source/tools/MyPinTool
make obj-intel64/MyPinTool.so
```

---

## Run Batch Testing

```bash
python3 scripts/run_batch.py
```

---

## Start Backend

```bash
source venv/bin/activate
cd web/backend
uvicorn app:app --reload
```

---

## Start Frontend

```bash
cd web/frontend
npm run dev
```

---

# Full System Workflow

```text
CPP Test Files
       ↓
Batch Runner
       ↓
Intel PIN Instrumentation
       ↓
JSON Reports
       ↓
FastAPI Backend
       ↓
React Dashboard
```

---

# Current Capabilities

- Dynamic memory tracing
- Leak detection
- Allocation statistics
- Function-level profiling
- Batch execution
- JSON report generation
- FastAPI backend API
- React visualization dashboard
- Search/filter support
- Leak inspection UI

---

# Example Dashboard Features

- Leak distribution graphs
- Allocation statistics
- Leak severity visualization
- Per-test inspection
- Function-level statistics
- Searchable test explorer

---

# Notes

- Supports 64-bit Linux binaries
- Uses Intel PIN dynamic instrumentation
- Tested with GCC-generated executables
- JSON reports are frontend-compatible
- Batch runner automatically compiles test binaries

---

# Author

Ankit Mittal
Dynamic Memory Tracing & Observability Platform using Intel PIN
