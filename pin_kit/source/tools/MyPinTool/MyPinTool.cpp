#include "pin.H"

#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

using std::cerr;
using std::endl;
using std::map;
using std::ofstream;
using std::string;
using std::vector;

ofstream outFile;

PIN_LOCK lock;

KNOB<string> KnobOutputFile(
    KNOB_MODE_WRITEONCE,
    "pintool",
    "o",
    "mem_report.json",
    "output file");

struct AllocInfo
{
    size_t size;
    string funcName;
    string file;
    INT32 line;
};

struct TraceEvent
{
    string type;
    ADDRINT address;
    size_t size;
    string function;
    string file;
    INT32 line;
};

map<ADDRINT, AllocInfo> activeAllocs;
map<string, size_t> totalMemPerFunc;
map<string, size_t> allocCountPerFunc;

vector<TraceEvent> allocEvents;
vector<TraceEvent> freeEvents;

UINT64 totalAllocations = 0;
UINT64 totalFrees = 0;
UINT64 totalBytesAllocated = 0;

typedef VOID *(*malloc_t)(size_t);
typedef VOID *(*calloc_t)(size_t, size_t);
typedef VOID *(*realloc_t)(VOID *, size_t);
typedef VOID (*free_t)(VOID *);

malloc_t real_malloc = NULL;
calloc_t real_calloc = NULL;
realloc_t real_realloc = NULL;
free_t real_free = NULL;

VOID GetSourceInfo(ADDRINT ip, string &file, INT32 &line)
{
    PIN_LockClient();

    INT32 column;
    PIN_GetSourceLocation(
        ip,
        &column,
        &line,
        &file);

    PIN_UnlockClient();

    if (file.empty())
    {
        file = "UNKNOWN";
        line = -1;
    }
}

bool IsUserCode(const string &file)
{
    if (file == "UNKNOWN")
        return false;

    return file.find("/tests/") != string::npos;
}

string GetFuncName(ADDRINT ip)
{
    PIN_LockClient();
    RTN rtn = RTN_FindByAddress(ip);
    string name = "UNKNOWN";
    if (RTN_Valid(rtn))
        name = RTN_Name(rtn);
    PIN_UnlockClient();
    return name;
}

VOID *MyMalloc(size_t size, ADDRINT ip)
{
    VOID *ret = real_malloc(size);
    if (!ret)
        return ret;

    THREADID tid = PIN_ThreadId();
    PIN_GetLock(&lock, tid + 1);

    string func = GetFuncName(ip);
    string file;
    INT32 line;
    GetSourceInfo(ip, file, line);

    if (!IsUserCode(file))
    {
        PIN_ReleaseLock(&lock);
        return ret;
    }

    activeAllocs[(ADDRINT)ret] = {size, func, file, line};
    totalMemPerFunc[func] += size;
    allocCountPerFunc[func]++;

    totalAllocations++;
    totalBytesAllocated += size;

    TraceEvent ev;
    ev.type = "ALLOC";
    ev.address = (ADDRINT)ret;
    ev.size = size;
    ev.function = func;
    ev.file = file;
    ev.line = line;
    allocEvents.push_back(ev);

    PIN_ReleaseLock(&lock);
    return ret;
}

VOID *MyCalloc(size_t nmemb, size_t size, ADDRINT ip)
{
    VOID *ret = real_calloc(nmemb, size);
    if (!ret)
        return ret;

    THREADID tid = PIN_ThreadId();
    PIN_GetLock(&lock, tid + 1);

    size_t total = nmemb * size;
    string func = GetFuncName(ip);
    string file;
    INT32 line;
    GetSourceInfo(ip, file, line);

    if (!IsUserCode(file))
    {
        PIN_ReleaseLock(&lock);
        return ret;
    }

    activeAllocs[(ADDRINT)ret] = {total, func, file, line};
    totalMemPerFunc[func] += total;
    allocCountPerFunc[func]++;

    totalAllocations++;
    totalBytesAllocated += total;

    TraceEvent ev;
    ev.type = "CALLOC";
    ev.address = (ADDRINT)ret;
    ev.size = total;
    ev.function = func;
    ev.file = file;
    ev.line = line;
    allocEvents.push_back(ev);

    PIN_ReleaseLock(&lock);
    return ret;
}

VOID *MyRealloc(VOID *ptr, size_t size, ADDRINT ip)
{
    VOID *ret = real_realloc(ptr, size);

    THREADID tid = PIN_ThreadId();
    PIN_GetLock(&lock, tid + 1);

    if (ret == NULL)
    {
        PIN_ReleaseLock(&lock);
        return ret;
    }

    if (ptr != NULL)
    {
        auto it = activeAllocs.find((ADDRINT)ptr);
        if (it != activeAllocs.end())
            activeAllocs.erase(it);
    }

    if (ret != NULL)
    {
        string func = GetFuncName(ip);
        string file;
        INT32 line;
        GetSourceInfo(ip, file, line);

        if (!IsUserCode(file))
        {
            PIN_ReleaseLock(&lock);
            return ret;
        }

        activeAllocs[(ADDRINT)ret] = {size, func, file, line};
        totalMemPerFunc[func] += size;
        allocCountPerFunc[func]++;

        totalAllocations++;
        totalBytesAllocated += size;

        TraceEvent ev;
        ev.type = "REALLOC";
        ev.address = (ADDRINT)ret;
        ev.size = size;
        ev.function = func;
        ev.file = file;
        ev.line = line;
        allocEvents.push_back(ev);
    }

    PIN_ReleaseLock(&lock);
    return ret;
}

VOID MyFree(VOID *ptr)
{
    THREADID tid = PIN_ThreadId();
    PIN_GetLock(&lock, tid + 1);

    auto it = activeAllocs.find((ADDRINT)ptr);

    if (it != activeAllocs.end())
    {
        totalFrees++;

        TraceEvent ev;
        ev.type = "FREE";
        ev.address = (ADDRINT)ptr;
        ev.size = it->second.size;
        ev.function = it->second.funcName;
        ev.file = it->second.file;
        ev.line = it->second.line;
        freeEvents.push_back(ev);

        activeAllocs.erase(it);
    }

    PIN_ReleaseLock(&lock);
    real_free(ptr);
}

VOID WriteJSONReport()
{
    outFile << "{\n";

    outFile << "  \"summary\": {\n";
    outFile << "    \"total_allocations\": " << totalAllocations << ",\n";
    outFile << "    \"total_frees\": " << totalFrees << ",\n";
    outFile << "    \"total_bytes_allocated\": " << totalBytesAllocated << ",\n";
    outFile << "    \"total_leaks\": " << activeAllocs.size() << "\n";
    outFile << "  },\n";

    outFile << "  \"allocations\": [\n";

    for (size_t i = 0; i < allocEvents.size(); i++)
    {
        auto &e = allocEvents[i];

        outFile << "    {\n";
        outFile << "      \"type\": \"" << e.type << "\",\n";
        outFile << "      \"address\": \"" << std::hex << e.address << "\",\n";
        outFile << "      \"size\": " << std::dec << e.size << ",\n";
        outFile << "      \"function\": \"" << e.function << "\",\n";
        outFile << "      \"file\": \"" << e.file << "\",\n";
        outFile << "      \"line\": " << e.line << "\n";
        outFile << "    }";

        if (i != allocEvents.size() - 1)
            outFile << ",";

        outFile << "\n";
    }

    outFile << "  ],\n";

    outFile << "  \"frees\": [\n";

    for (size_t i = 0; i < freeEvents.size(); i++)
    {
        auto &e = freeEvents[i];

        outFile << "    {\n";
        outFile << "      \"type\": \"" << e.type << "\",\n";
        outFile << "      \"address\": \"" << std::hex << e.address << "\",\n";
        outFile << "      \"size\": " << std::dec << e.size << ",\n";
        outFile << "      \"function\": \"" << e.function << "\",\n";
        outFile << "      \"file\": \"" << e.file << "\",\n";
        outFile << "      \"line\": " << e.line << "\n";
        outFile << "    }";

        if (i != freeEvents.size() - 1)
            outFile << ",";

        outFile << "\n";
    }

    outFile << "  ],\n";

    outFile << "  \"leaks\": [\n";

    size_t leakIndex = 0;

    for (auto &p : activeAllocs)
    {
        outFile << "    {\n";
        outFile << "      \"address\": \"" << std::hex << p.first << "\",\n";
        outFile << "      \"size\": " << std::dec << p.second.size << ",\n";
        outFile << "      \"function\": \"" << p.second.funcName << "\",\n";
        outFile << "      \"file\": \"" << p.second.file << "\",\n";
        outFile << "      \"line\": " << p.second.line << "\n";
        outFile << "    }";

        leakIndex++;

        if (leakIndex != activeAllocs.size())
            outFile << ",";

        outFile << "\n";
    }

    outFile << "  ],\n";

    outFile << "  \"function_stats\": [\n";

    size_t funcIndex = 0;

    for (auto &p : totalMemPerFunc)
    {
        outFile << "    {\n";
        outFile << "      \"function\": \"" << p.first << "\",\n";
        outFile << "      \"total_bytes\": " << p.second << ",\n";
        outFile << "      \"alloc_count\": " << allocCountPerFunc[p.first] << "\n";
        outFile << "    }";

        funcIndex++;

        if (funcIndex != totalMemPerFunc.size())
            outFile << ",";

        outFile << "\n";
    }

    outFile << "  ]\n";

    outFile << "}\n";
}

VOID ImageLoad(IMG img, VOID *v)
{
    cerr << "Loaded Image: " << IMG_Name(img) << endl;

    RTN mallocRtn = RTN_FindByName(img, "malloc");
    if (RTN_Valid(mallocRtn))
    {
        PROTO proto = PROTO_Allocate(
            PIN_PARG(void *), CALLINGSTD_DEFAULT,
            "malloc",
            PIN_PARG(size_t),
            PIN_PARG_END());

        real_malloc = (malloc_t)RTN_ReplaceSignature(
            mallocRtn, AFUNPTR(MyMalloc),
            IARG_PROTOTYPE, proto,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_RETURN_IP,
            IARG_END);

        PROTO_Free(proto);
    }

    RTN callocRtn = RTN_FindByName(img, "calloc");
    if (!RTN_Valid(callocRtn))
        callocRtn = RTN_FindByName(img, "__libc_calloc");

    if (RTN_Valid(callocRtn))
    {
        PROTO proto = PROTO_Allocate(
            PIN_PARG(void *), CALLINGSTD_DEFAULT,
            "calloc",
            PIN_PARG(size_t),
            PIN_PARG(size_t),
            PIN_PARG_END());

        real_calloc = (calloc_t)RTN_ReplaceSignature(
            callocRtn, AFUNPTR(MyCalloc),
            IARG_PROTOTYPE, proto,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_RETURN_IP,
            IARG_END);

        PROTO_Free(proto);
    }

    RTN reallocRtn = RTN_FindByName(img, "realloc");
    if (RTN_Valid(reallocRtn))
    {
        PROTO proto = PROTO_Allocate(
            PIN_PARG(void *), CALLINGSTD_DEFAULT,
            "realloc",
            PIN_PARG(void *),
            PIN_PARG(size_t),
            PIN_PARG_END());

        real_realloc = (realloc_t)RTN_ReplaceSignature(
            reallocRtn, AFUNPTR(MyRealloc),
            IARG_PROTOTYPE, proto,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_RETURN_IP,
            IARG_END);

        PROTO_Free(proto);
    }

    RTN freeRtn = RTN_FindByName(img, "free");
    if (RTN_Valid(freeRtn))
    {
        PROTO proto = PROTO_Allocate(
            PIN_PARG(void), CALLINGSTD_DEFAULT,
            "free",
            PIN_PARG(void *),
            PIN_PARG_END());

        real_free = (free_t)RTN_ReplaceSignature(
            freeRtn, AFUNPTR(MyFree),
            IARG_PROTOTYPE, proto,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_END);

        PROTO_Free(proto);
    }
}

VOID Fini(INT32 code, VOID *v)
{
    WriteJSONReport();

    outFile.close();
    cerr << "JSON memory report generated successfully.\n";
}

int main(int argc, char *argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv))
    {
        cerr << "PIN Init failed\n";
        return -1;
    }

    PIN_InitLock(&lock);

    outFile.open(KnobOutputFile.Value().c_str());
    if (!outFile.is_open())
    {
        cerr << "Error opening output file\n";
        return -1;
    }

    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);

    cerr << "Running Memory Allocation Pintool...\n";

    PIN_StartProgram();

    return 0;
}