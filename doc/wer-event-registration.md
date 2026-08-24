# Generic Event Registration — WSL Linux Process Crash

> **Status**: Draft — items marked **[TBD]** require review/completion before submission.

---

## 1. Person requesting the event (who is accountable)?

**[TBD]** — Name and alias of the responsible engineer or PM.

---

## 2. What product is this event for?

**Windows Subsystem for Linux (WSL)** — specifically the WSLC (containerized) session host
(`wslcsession.exe`), which runs Linux distributions inside an isolated virtualization container.

---

## 3. Detailed error reporting scenario — what causes the Watson report to be generated?

A Linux guest process running inside a WSLC container crashes (receives a fatal signal such as
`SIGSEGV`, `SIGBUS`, `SIGABRT`, `SIGILL`, or `SIGFPE`).  The Linux kernel writes an ELF core
dump to a host-side temporary directory (`%TEMP%\wslc-crashes\`).  `wslcsession.exe` detects
the file, parses the ELF core (reading NT\_PRSTATUS, NT\_SIGINFO, NT\_AUXV, and NT\_FILE notes
plus GNU build-ID notes from module ELF headers embedded in the core), and calls
`WerReportCreate` / `WerReportSubmit` to submit a WER report with the ELF core attached.

The report is generated **once per Linux process crash** that produces a core dump.  No report
is generated when core dumps are disabled inside the container or the dump file cannot be
parsed.

---

## 4. How will this event be used to solve the errors?

WER buckets aggregate crashes by (ProcessName, ProcessBuildId, ModuleName, ModuleBuildId,
ModuleOffset, SignalNumber, SICode, Architecture).  This lets the WSL engineering team:

- Identify the most-impactful crash buckets across the Linux userspace ecosystem on WSL.
- Correlate crashes to specific build-ID-stamped binaries shipped in WSL distributions
  (e.g. musl libc, glibc, system Python).
- Distinguish signal sub-types (`si_code`) to differentiate, say, null-pointer dereferences
  (`SI_SEGV_MAPERR`) from access-violation guard-page hits.
- Attach the raw ELF core dump for offline analysis with Linux tooling (GDB, `eu-stack`, etc.)
  or for symbol-server-assisted stack reconstruction.

---

## 5. Have you had a Privacy review with LCA in regards to this Event Registration?

**[TBD]** — Privacy review status with LCA.

---

## 6. What generic event name do you want to register (less than 50 characters)?

```
WSLCProcessCrash
```

(16 characters)

---

## 7. What are your bucketing parameters?

| Arg # | Name | Description | Value (Type / Format / Max Length / Example) | Unique Count |
|-------|------|-------------|----------------------------------------------|--------------|
| P0 | ProcessName | Basename of the crashed Linux executable, extracted from `AT_EXECFN` in `NT_AUXV`. | `string` / executable basename / 128 chars / `python3` | High (any process name) |
| P1 | ProcessBuildId | Hex-encoded GNU build ID of the main executable, read from the executable's own ELF PT\_NOTE embedded in the core. `<unknown>` when binary has no build ID. | `string` / lowercase hex / 128 chars / `a8e75dfc9750b78c12d01d3517e10cd27d7a4a60` | Very high (per binary build) |
| P2 | ModuleName | Basename of the shared library or executable segment that contains the faulting instruction pointer, from NT\_FILE. Falls back to `<unknown>` when not found. | `string` / shared-library basename / 128 chars / `ld-musl-x86_64.so.1` | Medium (common runtime libs) |
| P3 | ModuleBuildId | Hex-encoded GNU build ID of the blamed module, read from its ELF PT\_NOTE embedded in the core. `<unknown>` when module has no build ID. | `string` / lowercase hex / 128 chars / `25262d1f0190fa67ac8949c47edb1488aae52fcd` | Very high (per binary build) |
| P4 | ModuleOffset | Offset of the faulting instruction from the module's ELF load base (i.e. crash-IP minus module load address). Used to identify the faulting code location within the module even without symbols. | `string` / `0x`-prefixed lowercase hex / 32 chars / `0x20104` | High (per crash site) |
| P5 | SignalNumber | Linux signal number that terminated the process (from `NT_PRSTATUS.pr_info.si_signo`). | `string` / decimal integer / 8 chars / `11` (SIGSEGV) | Low (≤ ~10 common fatal signals) |
| P6 | SICode | Signal sub-code from `NT_SIGINFO.si_code`. Classifies the cause within the signal, e.g. `SEGV_MAPERR` (1) vs `SEGV_ACCERR` (2). | `string` / decimal integer / 8 chars / `1` | Low–medium (dozens of values) |
| P7 | Architecture | ELF machine type of the crashed process, derived from `e_machine` in the core ELF header. | `string` / enum string / 16 chars / `x86_64` or `aarch64` | Very low (2 values) |
| P8 | — | Reserved / unused | — | — |
| P9 | — | Reserved / unused | — | — |

---

## 8. Is the intent of the Event to collect Personally Identifiable Information?

**No.**

- **ProcessName** is the executable filename only (e.g. `python3`, `bash`), not a path and
  not the user's username or home directory.
- **ModuleName** is the library basename (e.g. `ld-musl-x86_64.so.1`).
- **Build IDs** are opaque hashes derived from binary content, not user data.
- **ModuleOffset**, **SignalNumber**, **SICode**, and **Architecture** are numeric crash
  metadata with no user-identifying content.
- The ELF core dump attached to the CAB is flagged `WER_FILE_ANONYMOUS_DATA`, which directs
  WER to anonymize it before transmission.

---

## 9. Provide a description and examples of the data collected in each CAB file.

**CAB contents: one ELF core dump per report.**

| File | Description | Example filename |
|------|-------------|-----------------|
| `wsl-crash-<pid>-<tid>-<basename>-<n>.dmp` | ELF core dump written by the Linux kernel. Contains: one PT\_NOTE segment (NT\_PRSTATUS, NT\_SIGINFO, NT\_AUXV, NT\_FILE, NT\_FPREGSET, etc.) and PT\_LOAD segments covering the stack, heap, and the first page of each mapped shared library (ELF header page). Does **not** contain full heap or anonymous mappings beyond what the kernel includes by default. | `wsl-crash-1785783556-1-_usr_local_bin_python3.12-11.dmp` |

The core file follows the standard Linux `coredump_filter` defaults.  By default, anonymous
private mappings (heap, stack) and mapped file ELF header pages are included; shared file
mappings are excluded.

---

## 10. Will the CAB contain memory dumps that need to be processed in Watson?

**No** — the attachment is an ELF core dump (Linux format), not a Windows Minidump.  Watson's
standard Windows symbol-stack unwinding does not apply.

If offline stack analysis is needed, Linux tooling (GDB, `eu-stack`, DWARF unwinding) is used
against the attached ELF core together with symbols from the distribution's debug package
feeds, keyed by GNU build ID.

**[TBD]** — Confirm with WER team whether ELF cores can be attached as `WerFileTypeOther`
and whether any additional processing pipeline is needed.

---

## 11. What is the expected volume?

**[TBD]** — Estimate from the WSL telemetry team.

Rough order-of-magnitude guidance:
- WSL has millions of monthly active users.
- Linux process crashes in typical developer workloads are relatively rare (single-digit per
  user per month or less).
- Expected volume: likely **tens of thousands to low hundreds of thousands of reports per
  month** across the fleet, concentrated in a small number of high-frequency buckets.

---

## 12. How many CABs do you need collected per Bucket?

**[TBD]** — Recommend **10–100 CABs per bucket** to ensure representative core dumps for
analysis while limiting storage cost.  Subject to WER team guidance.

---

## 13. What is the average size of a CAB?

**Approximately 1–4 MB per CAB.**

A default ELF core with stack, heap, and ELF header pages is typically 1–8 MB for common
developer tools (Python, Bash, Node.js) depending on heap and stack usage.  CAB compression
typically yields 30–60 % reduction.

---

## 14. Do you want to lock down access to your CAB files?

No special lockdown requested.

---

## 15. Do you want real-time CAB arrival notification?

**No** (default).

---

## 16. How long do you need to retain the CAB files?

**30 days** (current maximum).

---

## 17. What operating systems are you targeting?

**Windows 11** (any edition that ships WSLC / `wslcsession.exe`).

- x86\_64 (AMD64) hosts
- ARM64 hosts

The *Linux* guest can be any architecture supported by the WSL distribution (x86\_64,
aarch64), but the WER report is submitted from the Windows host process.

---

## 18. Links to your Watson specs

**[TBD]** — Add links to the internal Watson/WER spec or OneNote page once created.

---

## 19. Dev, PM and Test contacts

| Role | Name / Alias |
|------|--------------|
| Dev lead | **[TBD]** |
| PM | **[TBD]** |
| Test | **[TBD]** |

---

## 20. Team Alias

**[TBD]** — WSL team alias (e.g. `wslteam`).

---

## 21. Product Group

**Windows** — Windows Subsystem for Linux (WSL), under the Windows Core OS / Fundamentals group.
