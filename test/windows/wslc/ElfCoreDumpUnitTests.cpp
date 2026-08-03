// Copyright (C) Microsoft Corporation. All rights reserved.

/*++

Module Name:

    ElfCoreDumpUnitTests.cpp

Abstract:

    Unit tests for ParseElfCoreDump. Uses synthetic byte-level ELF core fixtures
    written to temp files. No running container is required.

--*/

#include "precomp.h"
#include "windows/Common.h"
#include "ElfCoreDump.h"

#include <vector>

using namespace wsl::windows::common;
using namespace WEX::Logging;

namespace ElfCoreDumpUnitTests {

// ---------------------------------------------------------------------------
// Minimal ELF core builder
//
// Produces a valid 64-bit ET_CORE ELF file with:
//   - One PT_NOTE phdr
//   - One NT_PRSTATUS note (RIP = 0xdeadbeef00000001, not in any NT_FILE entry)
//
// Optional fields (process name, build IDs, module name) are intentionally absent.
// ---------------------------------------------------------------------------

namespace {

    // Helper: append a little-endian integer to a buffer.
    void Append16(std::vector<uint8_t>& buf, uint16_t v)
    {
        buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&v), reinterpret_cast<uint8_t*>(&v) + 2);
    }
    void Append32(std::vector<uint8_t>& buf, uint32_t v)
    {
        buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&v), reinterpret_cast<uint8_t*>(&v) + 4);
    }
    void Append64(std::vector<uint8_t>& buf, uint64_t v)
    {
        buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&v), reinterpret_cast<uint8_t*>(&v) + 8);
    }
    void AppendZero(std::vector<uint8_t>& buf, size_t count)
    {
        buf.insert(buf.end(), count, 0);
    }

    // Build a single ELF note (nhdr + padded name + padded desc).
    std::vector<uint8_t> BuildNote(uint32_t ntype, std::string_view ownerWithNull, std::vector<uint8_t> desc)
    {
        const uint32_t namesz = static_cast<uint32_t>(ownerWithNull.size());
        const uint32_t namePad = (4 - (namesz % 4)) % 4;
        const uint32_t descsz = static_cast<uint32_t>(desc.size());
        const uint32_t descPad = (4 - (descsz % 4)) % 4;

        std::vector<uint8_t> note;
        Append32(note, namesz);
        Append32(note, descsz);
        Append32(note, ntype);
        note.insert(
            note.end(), reinterpret_cast<const uint8_t*>(ownerWithNull.data()), reinterpret_cast<const uint8_t*>(ownerWithNull.data()) + namesz);
        AppendZero(note, namePad);
        note.insert(note.end(), desc.begin(), desc.end());
        AppendZero(note, descPad);
        return note;
    }

    // Build a minimal valid NT_PRSTATUS desc (248 bytes) for a 64-bit x86_64 process.
    // Sets RIP to 0xdeadbeef00000001 (won't match any NT_FILE entry).
    std::vector<uint8_t> BuildPrstatusDesc64()
    {
        // prRegOffset64 = 112, ipRegX86_64 = 16, regWidth = 8
        constexpr size_t c_descSize = 248; // ipOffset(240) + regWidth(8)
        constexpr size_t c_ripOffset = 240;

        std::vector<uint8_t> desc(c_descSize, 0);
        const uint64_t rip = 0xdeadbeef00000001ULL;
        std::memcpy(desc.data() + c_ripOffset, &rip, sizeof(rip));
        return desc;
    }

    // Build a complete minimal 64-bit ELF core file with one NT_PRSTATUS note.
    std::vector<uint8_t> BuildMinimalCore64()
    {
        // Build the note first so we know its size.
        const auto prstatusNote = BuildNote(1 /* NT_PRSTATUS */, std::string_view("CORE\0", 5), BuildPrstatusDesc64());

        // Layout:
        //   [0,  64)  ELF header
        //   [64, 120) PT_NOTE phdr
        //   [120, .)  Note data
        constexpr uint64_t c_phdrOffset = 64;
        constexpr uint64_t c_noteOffset = 120;
        const uint64_t noteSize = prstatusNote.size();

        std::vector<uint8_t> buf;
        buf.reserve(static_cast<size_t>(c_noteOffset) + prstatusNote.size());

        // ELF ident (16 bytes)
        buf.push_back(0x7f);
        buf.push_back('E');
        buf.push_back('L');
        buf.push_back('F');
        buf.push_back(2);   // ELFCLASS64
        buf.push_back(1);   // ELFDATA2LSB
        buf.push_back(1);   // EV_CURRENT
        AppendZero(buf, 9); // OSABI, ABIVERSION, padding

        // ELF header fields
        Append16(buf, 4);            // e_type = ET_CORE
        Append16(buf, 62);           // e_machine = EM_X86_64
        Append32(buf, 1);            // e_version
        Append64(buf, 0);            // e_entry
        Append64(buf, c_phdrOffset); // e_phoff
        Append64(buf, 0);            // e_shoff
        Append32(buf, 0);            // e_flags
        Append16(buf, 64);           // e_ehsize
        Append16(buf, 56);           // e_phentsize
        Append16(buf, 1);            // e_phnum
        Append16(buf, 64);           // e_shentsize
        Append16(buf, 0);            // e_shnum
        Append16(buf, 0);            // e_shstrndx

        // PT_NOTE phdr (56 bytes)
        Append32(buf, 4);            // p_type = PT_NOTE
        Append32(buf, 0);            // p_flags
        Append64(buf, c_noteOffset); // p_offset
        Append64(buf, 0);            // p_vaddr
        Append64(buf, 0);            // p_paddr
        Append64(buf, noteSize);     // p_filesz
        Append64(buf, 0);            // p_memsz
        Append64(buf, 0);            // p_align

        // Note data
        buf.insert(buf.end(), prstatusNote.begin(), prstatusNote.end());
        return buf;
    }

    // Write bytes to a temp file and return an RAII handle that deletes the file on destruction.
    struct TempCoreFile
    {
        std::filesystem::path path;

        explicit TempCoreFile(const std::vector<uint8_t>& data)
        {
            wchar_t tempDir[MAX_PATH]{}, tempFile[MAX_PATH]{};
            THROW_LAST_ERROR_IF(GetTempPathW(MAX_PATH, tempDir) == 0);
            THROW_LAST_ERROR_IF(GetTempFileNameW(tempDir, L"elf", 0, tempFile) == 0);
            path = tempFile;

            wil::unique_hfile f{CreateFileW(tempFile, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr)};
            THROW_LAST_ERROR_IF(!f);

            DWORD written{};
            THROW_IF_WIN32_BOOL_FALSE(WriteFile(f.get(), data.data(), static_cast<DWORD>(data.size()), &written, nullptr));
        }

        ~TempCoreFile()
        {
            std::filesystem::remove(path);
        }

        NON_COPYABLE(TempCoreFile);
        NON_MOVABLE(TempCoreFile);
    };

    // Helper: assert that ParseElfCoreDump throws a wil::ResultException whose what() string
    // contains the expected message substring. Re-throws anything that is not a ResultException
    // so unexpected failures are not silently swallowed.
    void VerifyThrows(const std::filesystem::path& path, std::string_view expectedMessage)
    {
        try
        {
            ParseElfCoreDump(path);
            VERIFY_FAIL(L"Expected ParseElfCoreDump to throw but it did not");
        }
        catch (const wil::ResultException& e)
        {
            const std::string_view what{e.what()};
            VERIFY_IS_TRUE(
                what.find(expectedMessage) != std::string_view::npos,
                WEX::Common::String().Format(
                    L"Exception message \"%S\" does not contain expected substring \"%S\"", e.what(), expectedMessage.data()));
        }
    }

} // anonymous namespace

class ElfCoreDumpUnitTests
{
    BEGIN_TEST_CLASS(ElfCoreDumpUnitTests)
        TEST_CLASS_PROPERTY(L"TestCategory", L"ElfCoreDumpUnit")
    END_TEST_CLASS()

    // Not an ELF file at all.
    TEST_METHOD(NotElfFile)
    {
        const TempCoreFile tmp{std::vector<uint8_t>(64, 0xCC)};
        VerifyThrows(tmp.path, "ELF magic");
    }

    // Valid ELF ident but big-endian data encoding.
    TEST_METHOD(BigEndianCore)
    {
        auto buf = BuildMinimalCore64();
        buf[5] = 2; // EI_DATA = ELFDATA2MSB
        const TempCoreFile tmp{buf};
        VerifyThrows(tmp.path, "not little-endian");
    }

    // Valid ELF ident but EI_VERSION != EV_CURRENT.
    TEST_METHOD(InvalidVersion)
    {
        auto buf = BuildMinimalCore64();
        buf[6] = 0; // EI_VERSION = 0 (invalid)
        const TempCoreFile tmp{buf};
        VerifyThrows(tmp.path, "Unsupported ELF version");
    }

    // Valid ELF header but e_type = ET_EXEC (not a core dump).
    TEST_METHOD(NotACoreFile)
    {
        auto buf = BuildMinimalCore64();
        // e_type is at byte 16 (after 16-byte ident); write 2 (ET_EXEC) little-endian.
        buf[16] = 2;
        buf[17] = 0;
        const TempCoreFile tmp{buf};
        VerifyThrows(tmp.path, "not a core dump");
    }

    // Valid ET_CORE header but e_phnum = 0 (no program headers).
    TEST_METHOD(NoProgramHeaders)
    {
        auto buf = BuildMinimalCore64();
        // e_phnum is at byte 56 (after ident(16) + type(2) + machine(2) + version(4)
        //   + entry(8) + phoff(8) + shoff(8) + flags(4) + ehsize(2) + phentsize(2) = 56).
        buf[56] = 0;
        buf[57] = 0;
        const TempCoreFile tmp{buf};
        VerifyThrows(tmp.path, "no program headers");
    }

    // Valid ET_CORE header + one PT_LOAD phdr (no PT_NOTE segments).
    TEST_METHOD(NoPtNoteSegments)
    {
        auto buf = BuildMinimalCore64();
        // Replace PT_NOTE (4) with PT_LOAD (1) by changing the first 4 bytes of the phdr.
        buf[64] = 1;
        buf[65] = 0;
        buf[66] = 0;
        buf[67] = 0;
        const TempCoreFile tmp{buf};
        VerifyThrows(tmp.path, "no PT_NOTE segments");
    }

    // Valid PT_NOTE segment but note type is not NT_PRSTATUS — no crash IP available.
    TEST_METHOD(NoNtPrstatus)
    {
        // Build a core with an NT_SIGINFO note (type=0x53494749) instead of NT_PRSTATUS.
        // siginfo_t: si_signo=11, si_errno=0, si_code=1
        std::vector<uint8_t> siginfoDesc(12, 0);
        siginfoDesc[0] = 11; // si_signo = SIGSEGV
        siginfoDesc[8] = 1;  // si_code = SEGV_MAPERR

        const auto siginfoNote = BuildNote(0x53494749u /* NT_SIGINFO */, std::string_view("CORE\0", 5), siginfoDesc);

        constexpr uint64_t c_phdrOffset = 64;
        constexpr uint64_t c_noteOffset = 120;

        std::vector<uint8_t> buf;
        buf.reserve(c_noteOffset + siginfoNote.size());

        // ELF ident
        buf.push_back(0x7f);
        buf.push_back('E');
        buf.push_back('L');
        buf.push_back('F');
        buf.push_back(2);
        buf.push_back(1);
        buf.push_back(1);
        AppendZero(buf, 9);

        Append16(buf, 4);
        Append16(buf, 62);
        Append32(buf, 1);
        Append64(buf, 0);
        Append64(buf, c_phdrOffset);
        Append64(buf, 0);
        Append32(buf, 0);
        Append16(buf, 64);
        Append16(buf, 56);
        Append16(buf, 1);
        Append16(buf, 64);
        Append16(buf, 0);
        Append16(buf, 0);

        Append32(buf, 4);
        Append32(buf, 0);
        Append64(buf, c_noteOffset);
        Append64(buf, 0);
        Append64(buf, 0);
        Append64(buf, static_cast<uint64_t>(siginfoNote.size()));
        Append64(buf, 0);
        Append64(buf, 0);

        buf.insert(buf.end(), siginfoNote.begin(), siginfoNote.end());

        const TempCoreFile tmp{buf};
        VerifyThrows(tmp.path, "No NT_PRSTATUS note found");
    }

    // Valid 64-bit core with NT_PRSTATUS only (no NT_FILE, NT_AUXV, NT_GNU_BUILD_ID).
    // Parsing must succeed; optional string fields are empty.
    TEST_METHOD(MissingOptionalFields)
    {
        const TempCoreFile tmp{BuildMinimalCore64()};

        const auto info = ParseElfCoreDump(tmp.path);

        VERIFY_ARE_EQUAL(info.elfMachine, static_cast<uint16_t>(62)); // EM_X86_64
        VERIFY_IS_TRUE(info.processName.empty());
        VERIFY_IS_TRUE(info.moduleName.empty());
        VERIFY_IS_TRUE(info.processBuildId.empty());
        VERIFY_IS_TRUE(info.moduleBuildId.empty());
        VERIFY_ARE_EQUAL(info.moduleOffset, static_cast<uint64_t>(0));
        VERIFY_ARE_EQUAL(info.siCode, static_cast<uint32_t>(0));
    }
};

} // namespace ElfCoreDumpUnitTests
