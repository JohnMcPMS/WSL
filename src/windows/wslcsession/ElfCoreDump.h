// Copyright (C) Microsoft Corporation. All rights reserved.

#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace wsl::windows::service::wslc {

// Crash information extracted from an ELF core dump for WER bucketing.
// All string fields are best-effort; empty means "not available" (e.g. no build ID).
struct ElfCrashInfo
{
    std::string processName;    // basename of crashed executable (from NT_AUXV AT_EXECFN)
    std::string moduleName;     // basename of the blamed module (contains crash IP)
    uint64_t moduleOffset{};    // crash IP minus module base address
    uint32_t siCode{};          // si_code from NT_SIGINFO (signal sub-classification)
    std::string processBuildId; // hex-encoded GNU build ID of the main executable
    std::string moduleBuildId;  // hex-encoded GNU build ID of the blamed module
    uint16_t elfMachine{};      // ELF e_machine: 62 = x86_64, 183 = aarch64
};

// Parse an ELF core dump written by the Linux kernel and extract crash bucketing
// information. Throws on hard parse failures (not ELF, not a core, missing
// required structures). Optional fields (build IDs, process name, module name)
// are left empty when absent rather than treated as failures.
ElfCrashInfo ParseElfCoreDump(const std::filesystem::path& dumpPath);

} // namespace wsl::windows::service::wslc
