// Copyright (C) Microsoft Corporation. All rights reserved.

#include "precomp.h"
#include "WerReport.h"

#include <werapi.h>
#include <format>
#include <string>
#include "WslTelemetry.h"

using namespace wsl::windows::common;
using namespace wsl::windows::common::string;

namespace {

// Convert an ELF e_machine value to a human-readable string for display.
constexpr std::string_view MachineToString(uint16_t machine) noexcept
{
    switch (machine)
    {
    case 62:
        return "x86_64";
    case 183:
        return "aarch64";
    default:
        return "unknown";
    }
}

// WER parameter helper: set a wide-string parameter, truncating to fit WER's 128-char limit.
HRESULT SetWerParam(HREPORT report, DWORD paramId, PCWSTR name, const std::wstring& value)
{
    // WER truncates parameters longer than MAX_PATH; do it explicitly to avoid a failure.
    constexpr size_t c_maxWerParamLen = 128;
    const auto truncated = value.substr(0, c_maxWerParamLen);
    return WerReportSetParameter(report, paramId, name, truncated.c_str());
}

HRESULT SetWerParam(HREPORT report, DWORD paramId, PCWSTR name, const std::string& value)
{
    return SetWerParam(report, paramId, name, MultiByteToWide(value.c_str()));
}

} // anonymous namespace

void wsl::windows::common::SubmitLinuxCrashWerReport(
    const std::filesystem::path& dumpPath, const std::string& processNameFallback, ULONG signal, const ElfCrashInfo& crashInfo)
{
    const std::string& processName = !crashInfo.processName.empty() ? crashInfo.processName : processNameFallback;

    const std::string moduleName = !crashInfo.moduleName.empty() ? crashInfo.moduleName : "<unknown>";

    const std::string moduleOffset = std::format("0x{:x}", crashInfo.moduleOffset);
    const std::string siCode = std::to_string(crashInfo.siCode);
    const std::string signalStr = std::to_string(signal);
    const std::string architecture = std::string{MachineToString(crashInfo.elfMachine)};
    const std::string& processBuildId = crashInfo.processBuildId;
    const std::string& moduleBuildId = crashInfo.moduleBuildId;

    // --- Local-only ETW trace event ---
    // No MICROSOFT_KEYWORD_MEASURES keyword → captured locally by ETW but not uploaded.
    WSL_LOG(
        "WSLCLinuxCrashWer",
        TraceLoggingValue(processName.c_str(), "ProcessName"),
        TraceLoggingValue(processBuildId.c_str(), "ProcessBuildId"),
        TraceLoggingValue(moduleName.c_str(), "ModuleName"),
        TraceLoggingValue(moduleBuildId.c_str(), "ModuleBuildId"),
        TraceLoggingValue(moduleOffset.c_str(), "ModuleOffset"),
        TraceLoggingValue(signalStr.c_str(), "SignalNumber"),
        TraceLoggingValue(siCode.c_str(), "SICode"),
        TraceLoggingValue(architecture.c_str(), "Architecture"),
        TraceLoggingValue(dumpPath.c_str(), "DumpPath"));

    // --- WER report ---
    // Suppressed in debug builds to avoid polluting WER with intentional test crashes.
    if constexpr (!wsl::shared::Debug)
    {
        using unique_hreport = wil::unique_any<HREPORT, decltype(&WerReportCloseHandle), WerReportCloseHandle>;
        unique_hreport hReport;
        // WerReportApplicationCrash attributes the report to this process but uses custom
        // parameters for backend bucketing. WerReportCritical is inappropriate here because
        // wslcsession.exe is not crashing; a Linux guest process is.
        THROW_IF_FAILED(WerReportCreate(L"WSLLinuxProcessCrash", WerReportApplicationCrash, nullptr, hReport.put()));

        // Parameters match the WER bucketing schema (P0–P7); order must stay stable.
        // TODO: confirm final parameter names and order with the WER event registration owner.
        THROW_IF_FAILED(SetWerParam(hReport.get(), WER_P0, L"ProcessName", processName));
        THROW_IF_FAILED(SetWerParam(hReport.get(), WER_P1, L"ProcessBuildId", processBuildId));
        THROW_IF_FAILED(SetWerParam(hReport.get(), WER_P2, L"ModuleName", moduleName));
        THROW_IF_FAILED(SetWerParam(hReport.get(), WER_P3, L"ModuleBuildId", moduleBuildId));
        THROW_IF_FAILED(SetWerParam(hReport.get(), WER_P4, L"ModuleOffset", moduleOffset));
        THROW_IF_FAILED(SetWerParam(hReport.get(), WER_P5, L"SignalNumber", signalStr));
        THROW_IF_FAILED(SetWerParam(hReport.get(), WER_P6, L"SICode", siCode));
        THROW_IF_FAILED(SetWerParam(hReport.get(), WER_P7, L"Architecture", architecture));

        // Attach the ELF core dump. WER copies it into its staging directory synchronously
        // before WerReportSubmit returns, so there is no file lifetime concern.
        // WerFileTypeOther is used since the file is not a Windows minidump.
        LOG_IF_FAILED(WerReportAddFile(hReport.get(), dumpPath.c_str(), WerFileTypeOther, WER_FILE_ANONYMOUS_DATA));

        WER_SUBMIT_RESULT submitResult{};
        THROW_IF_FAILED(WerReportSubmit(hReport.get(), WerConsentNotAsked, WER_SUBMIT_QUEUE | WER_SUBMIT_NO_CLOSE_UI, &submitResult));
    }
}
