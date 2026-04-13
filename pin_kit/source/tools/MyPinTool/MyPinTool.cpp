/*
 * Copyright (C) 2007-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*! @file
 *  MyPinTool.cpp
 *  Dynamic memory allocation analysis tool using Intel PIN.
 *
 *  Week 1-4 scope:
 *  - Hook malloc/free/calloc/realloc
 *  - Track allocation metadata at runtime
 *  - Aggregate memory usage per calling function
 *  - Generate a report at program exit
 */

#include "pin.H"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

/* ================================================================== */
// Global variables
/* ================================================================== */

std::ostream *out = &std::cerr;
PIN_LOCK lock;

struct AllocationInfo
{
    ADDRINT addr;
    size_t size;
    std::string funcName;
    bool freed;
};

struct FunctionStats
{
    UINT64 allocCount = 0;
    UINT64 freeCount = 0;
    UINT64 bytesAllocated = 0;
    UINT64 bytesFreed = 0;
};

static std::map<ADDRINT, AllocationInfo> allocations;
static std::map<std::string, FunctionStats> functionStats;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for MyPinTool output");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

INT32 Usage()
{
    std::cerr << "This tool tracks dynamic memory allocations (malloc/free/calloc/realloc)." << std::endl;
    std::cerr << "It reports allocation counts and total bytes per calling function." << std::endl;
    std::cerr << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

static std::string GetRoutineNameByAddress(ADDRINT ip)
{
    std::string name = "UNKNOWN";

    PIN_LockClient();
    RTN rtn = RTN_FindByAddress(ip);
    if (RTN_Valid(rtn))
    {
        name = RTN_Name(rtn);
    }
    PIN_UnlockClient();

    return name;
}

static void AddAllocation(ADDRINT addr, size_t size, ADDRINT callerIp)
{
    if (addr == 0)
        return;

    std::string caller = GetRoutineNameByAddress(callerIp);

    PIN_GetLock(&lock, 1);

    AllocationInfo info;
    info.addr = addr;
    info.size = size;
    info.funcName = caller;
    info.freed = false;
    allocations[addr] = info;

    FunctionStats &stats = functionStats[caller];
    stats.allocCount++;
    stats.bytesAllocated += size;

    PIN_ReleaseLock(&lock);
}

static void AddFree(ADDRINT addr)
{
    if (addr == 0)
        return;

    PIN_GetLock(&lock, 2);

    std::map<ADDRINT, AllocationInfo>::iterator it = allocations.find(addr);
    if (it != allocations.end() && !it->second.freed)
    {
        it->second.freed = true;
        FunctionStats &stats = functionStats[it->second.funcName];
        stats.freeCount++;
        stats.bytesFreed += it->second.size;
    }

    PIN_ReleaseLock(&lock);
}

/* ===================================================================== */
// Replacement routines for memory allocators
/* ===================================================================== */

typedef VOID *(*MALLOC_FUNCPTR)(size_t);
typedef VOID (*FREE_FUNCPTR)(VOID *);
typedef VOID *(*CALLOC_FUNCPTR)(size_t, size_t);
typedef VOID *(*REALLOC_FUNCPTR)(VOID *, size_t);

VOID *MallocReplacement(AFUNPTR origMalloc, size_t size, ADDRINT callerIp)
{
    VOID *ret = ((MALLOC_FUNCPTR)origMalloc)(size);
    AddAllocation((ADDRINT)ret, size, callerIp);
    return ret;
}

VOID FreeReplacement(AFUNPTR origFree, VOID *ptr)
{
    AddFree((ADDRINT)ptr);
    ((FREE_FUNCPTR)origFree)(ptr);
}

VOID *CallocReplacement(AFUNPTR origCalloc, size_t nmemb, size_t size, ADDRINT callerIp)
{
    VOID *ret = ((CALLOC_FUNCPTR)origCalloc)(nmemb, size);
    AddAllocation((ADDRINT)ret, nmemb * size, callerIp);
    return ret;
}

VOID *ReallocReplacement(AFUNPTR origRealloc, VOID *ptr, size_t size, ADDRINT callerIp)
{
    // Treat realloc as free(old) + alloc(new) for analysis purposes.
    if (ptr != NULL)
    {
        AddFree((ADDRINT)ptr);
    }

    VOID *ret = ((REALLOC_FUNCPTR)origRealloc)(ptr, size);
    AddAllocation((ADDRINT)ret, size, callerIp);
    return ret;
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID ImageLoad(IMG img, VOID *v)
{
    if (!IMG_Valid(img))
        return;

    RTN rtn = RTN_FindByName(img, "malloc");
    if (RTN_Valid(rtn))
    {
        RTN_Open(rtn);
        RTN_ReplaceSignature(rtn, AFUNPTR(MallocReplacement),
                             IARG_ORIG_FUNCPTR,
                             IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                             IARG_RETURN_IP,
                             IARG_END);
        RTN_Close(rtn);
    }

    rtn = RTN_FindByName(img, "free");
    if (RTN_Valid(rtn))
    {
        RTN_Open(rtn);
        RTN_ReplaceSignature(rtn, AFUNPTR(FreeReplacement),
                             IARG_ORIG_FUNCPTR,
                             IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                             IARG_END);
        RTN_Close(rtn);
    }

    rtn = RTN_FindByName(img, "calloc");
    if (RTN_Valid(rtn))
    {
        RTN_Open(rtn);
        RTN_ReplaceSignature(rtn, AFUNPTR(CallocReplacement),
                             IARG_ORIG_FUNCPTR,
                             IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                             IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                             IARG_RETURN_IP,
                             IARG_END);
        RTN_Close(rtn);
    }

    rtn = RTN_FindByName(img, "realloc");
    if (RTN_Valid(rtn))
    {
        RTN_Open(rtn);
        RTN_ReplaceSignature(rtn, AFUNPTR(ReallocReplacement),
                             IARG_ORIG_FUNCPTR,
                             IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                             IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                             IARG_RETURN_IP,
                             IARG_END);
        RTN_Close(rtn);
    }
}

/* ===================================================================== */
// Final report
/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
    std::ostream &os = *out;

    os << "===============================================" << std::endl;
    os << "Memory Allocation Report" << std::endl;
    os << "===============================================" << std::endl;

    std::vector<std::pair<std::string, FunctionStats>> vec(functionStats.begin(), functionStats.end());
    std::sort(vec.begin(), vec.end(),
              [](const std::pair<std::string, FunctionStats> &a,
                 const std::pair<std::string, FunctionStats> &b)
              {
                  return a.second.bytesAllocated > b.second.bytesAllocated;
              });

    os << "Per-function allocation summary:" << std::endl;
    for (size_t i = 0; i < vec.size(); ++i)
    {
        const std::string &name = vec[i].first;
        const FunctionStats &st = vec[i].second;
        os << name << " | allocs: " << st.allocCount
           << " | frees: " << st.freeCount
           << " | bytes allocated: " << st.bytesAllocated
           << " | bytes freed: " << st.bytesFreed
           << " | bytes active: " << (st.bytesAllocated - st.bytesFreed)
           << std::endl;
    }

    os << std::endl;
    os << "Active allocations:" << std::endl;
    UINT64 activeCount = 0;
    UINT64 activeBytes = 0;

    for (std::map<ADDRINT, AllocationInfo>::iterator it = allocations.begin(); it != allocations.end(); ++it)
    {
        if (!it->second.freed)
        {
            activeCount++;
            activeBytes += it->second.size;
            os << "addr=0x" << std::hex << it->second.addr << std::dec
               << " size=" << it->second.size
               << " func=" << it->second.funcName << std::endl;
        }
    }

    os << std::endl;
    os << "Summary:" << std::endl;
    os << "Total unique allocations tracked: " << allocations.size() << std::endl;
    os << "Active allocations remaining: " << activeCount << std::endl;
    os << "Active bytes remaining: " << activeBytes << std::endl;
    os << "===============================================" << std::endl;
}

/* ===================================================================== */
// Main
/* ===================================================================== */

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    PIN_InitLock(&lock);

    std::string fileName = KnobOutputFile.Value();
    if (fileName.empty())
    {
        fileName = "mypintool.out";
    }

    out = new std::ofstream(fileName.c_str());

    if (!out || !(*out))
    {
        std::cerr << "Failed to open output file: " << fileName << std::endl;
        return 1;
    }

    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);

    std::cerr << "===============================================" << std::endl;
    std::cerr << "This application is instrumented by MyPinTool" << std::endl;
    if (!KnobOutputFile.Value().empty())
    {
        std::cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << std::endl;
    }
    std::cerr << "===============================================" << std::endl;

    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
