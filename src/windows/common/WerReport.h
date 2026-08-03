// Copyright (C) Microsoft Corporation. All rights reserved.

#pragma once

#include <filesystem>
#include <string>
#include "ElfCoreDump.h"

namespace wsl::windows::common {

// Parse the ELF core dump at dumpPath, then submit a WER report via WerReportCreate
// and emit a local-only ETW trace event containing all bucketing parameters.
//
// processNameFallback is used for ProcessName when the core dump does not contain
// AT_EXECFN. signal is the signal number from LX_PROCESS_CRASH.
//
// This function is best-effort: failures are logged but not propagated.
// It must be called after the dump file has been fully written and before any
// code that may delete or move the file.
void SubmitLinuxCrashWerReport(const std::filesystem::path& dumpPath, const std::string& processNameFallback, ULONG signal, const ElfCrashInfo& crashInfo);

} // namespace wsl::windows::common
