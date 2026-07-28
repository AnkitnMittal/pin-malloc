# Memory Trace Dashboard using Intel PIN

A full-stack dynamic memory tracing and leak analysis platform built using Intel PIN, Node.js (Express), React, and Tailwind CSS.

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
- provides live, in-browser C++ compilation and analysis, mapping memory leaks directly to code line numbers.

---

# Features

## Live Code Analysis
The platform features a live Monaco-based C++ editor. The Node.js backend handles:
- temporary directory setup and source compilation via `g++`
- dynamic instrumentation execution
- returning diagnostic markers mapping leaks directly to the editor's line numbers

## Dynamic Memory Instrumentation
The Pintool intercepts:
- `malloc`
- `calloc`
- `realloc`
- `free`

## Memory Event Tracking
For every allocation/free event, the tool records:
- allocation type
- memory address
- allocation size
- calling function

## Leak Detection
Detects:
- leaked allocations
- partially freed programs
- unfreed reallocations

## Function-Level Statistics
Tracks:
- allocation count per function
- total allocated bytes per function

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

## Interactive Web Dashboard
The React dashboard provides:
- global memory statistics
- leak visualization charts using Recharts
- searchable test explorer
- per-test inspection
- leak details table
- allocation statistics
- distinct UI themes (`light` for Dashboard, `dark` for Analyze)

---

# Tech Stack

| Component | Technology |
|-----------|------------|
| Binary Instrumentation | Intel PIN |
| Reporting | JSON |
| Backend API | Node.js, Express, `child_process` |
| Code Editor | Monaco Editor (`@monaco-editor/react`) |
| Charts | Recharts |
| Frontend | React, Tailwind CSS, React Router |

---

# Project Architecture

```text
pin-malloc/
│
├── pin_kit/
│   └── source/tools/MyPinTool/
│       ├── MyPinTool.cpp
│       └── obj-intel64/
│
├── reports/
│
├── web/
│   ├── backend/
│   │   ├── config/
│   │   ├── controllers/
│   │   ├── routes/
│   │   ├── services/
│   │   ├── app.js
│   │   └── server.js
│   │
│   └── frontend/
│       ├── src/
│       │   ├── api/
│       │   ├── components/
│       │   ├── pages/
│       │   ├── utils/
│       │   ├── App.jsx
│       │   └── main.jsx
│       ├── index.css
│       └── package.json
```

---

# Commands

## Build Pintool

```bash
cd pin_kit/source/tools/MyPinTool
make obj-intel64/MyPinTool.so
```

## Start Backend

```bash
cd web/backend
npm install
npm run dev
# Runs on http://localhost:8000
```

## Start Frontend

```bash
cd web/frontend
npm install
npm run dev
```

---

# System Workflow

```text
User C++ Code (Monaco Editor)
       ↓
POST /analyze (Express Backend)
       ↓
g++ Compilation (Temporary Directory)
       ↓
Intel PIN Instrumentation
       ↓
JSON Diagnostic Reports
       ↓
React Dashboard Visualization
```

---

# Current Capabilities

- Dynamic memory tracing
- Leak detection
- Allocation statistics
- Function-level profiling
- Real-time compiler feedback and runtime analysis
- JSON report generation
- Node.js Express backend API
- React visualization dashboard
- Search and filter support
- Leak inspection UI

---

# Notes

- Supports 64-bit Linux binaries
- Uses Intel PIN dynamic instrumentation
- Tested with GCC-generated executables
- Frontend uses the `VITE_API_URL` environment variable to adapt to different backend hosts

---

# Author

**Ankit Mittal**

*Dynamic Memory Tracing & Observability Platform using Intel PIN*