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

    // Core contains a GNU/NT_GNU_BUILD_ID note directly in the core's own PT_NOTE section
    // (the fallback path).  Verifies that all desc bytes are correctly hex-encoded.
    TEST_METHOD(ProcessBuildIdFromCoreNote)
    {
        // Four known bytes so the expected hex string is easy to compute.
        const std::vector<uint8_t> c_buildIdBytes = {0x12, 0x34, 0xAB, 0xCD};
        const std::string c_expectedHex = "1234abcd";

        // Build minimal core and then splice a GNU/3 note into the PT_NOTE segment.
        // The approach: append the GNU note to the existing core buffer and update
        // the PT_NOTE filesz in the phdr.
        auto buf = BuildMinimalCore64();

        // The original core has one PT_NOTE phdr at byte 64 (p_offset at 64+16=80).
        // Build the extra note.
        const auto gnuNote = BuildNote(3 /* NT_GNU_BUILD_ID */, std::string_view("GNU\0", 4), c_buildIdBytes);

        // Current note size (original PT_NOTE content).
        // Phdr p_filesz is a uint64_t at offset 64 (phdr base) + 32 (p_filesz offset in
        // Elf64Phdr: 4+4+8+8+8=32).
        constexpr size_t c_phdrBase = 64;
        constexpr size_t c_filesz64Offset = c_phdrBase + 32; // p_filesz in 64-bit phdr

        uint64_t origFilesz{};
        std::memcpy(&origFilesz, buf.data() + c_filesz64Offset, sizeof(origFilesz));

        // Append the GNU note after the existing note content.
        buf.insert(buf.end(), gnuNote.begin(), gnuNote.end());

        // Update p_filesz.
        const uint64_t newFilesz = origFilesz + gnuNote.size();
        std::memcpy(buf.data() + c_filesz64Offset, &newFilesz, sizeof(newFilesz));

        const TempCoreFile tmp{buf};
        const auto info = ParseElfCoreDump(tmp.path);

        VERIFY_ARE_EQUAL(c_expectedHex, info.processBuildId);
    }

    // Core with a PT_LOAD segment that backs a miniature module ELF image.  The module
    // image embeds a GNU/NT_GNU_BUILD_ID note in its own PT_NOTE phdr.  The crash IP
    // falls inside the module's mapped range so the parser chooses it as the blamed module
    // and must return the correct hex build ID in moduleBuildId.
    //
    // This test exercises the ReadModuleBuildId code path — in particular the
    // BytesToHex(std::vector<BYTE>(desc, desc + descSize)) conversion.
    TEST_METHOD(ModuleBuildIdExtractedFromElfPage)
    {
        // --- Build ID bytes and expected output ---
        const std::vector<uint8_t> c_buildIdBytes = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23};
        const std::string c_expectedHex = "deadbeef0123";

        // --- Module ELF page layout ---
        // Virtual address where the module is mapped in the fake process.
        constexpr uint64_t c_moduleBase = 0x400000;
        // Crash IP inside the module's mapped range.
        constexpr uint64_t c_crashIp = 0x400F00;

        // Build the GNU note that will live inside the module ELF image.
        const auto buildIdNote = BuildNote(3 /* NT_GNU_BUILD_ID */, std::string_view("GNU\0", 4), c_buildIdBytes);

        // Module page layout (all offsets within the module ELF page, which starts at VA c_moduleBase):
        //   [0,   64)   Module ELF header: ELFCLASS64, ET_DYN, phnum=2, phoff=64, phentsize=56
        //   [64, 120)   Module phdr[0]: PT_LOAD, p_vaddr=0, p_offset=0, p_filesz=pageSize
        //   [120, 176)  Module phdr[1]: PT_NOTE, p_vaddr=176, p_offset=176, p_filesz=sizeof(buildIdNote)
        //   [176, ...)  GNU build-ID note data
        constexpr uint64_t c_noteRelOffset = 176; // = 64 (ehdr) + 56 + 56 (2 phdrs)
        const size_t modulePageSize = c_noteRelOffset + buildIdNote.size();

        std::vector<uint8_t> modulePage(modulePageSize, 0);

        // ELF ident
        modulePage[0] = 0x7f; modulePage[1] = 'E'; modulePage[2] = 'L'; modulePage[3] = 'F';
        modulePage[4] = 2; // ELFCLASS64
        modulePage[5] = 1; // ELFDATA2LSB
        modulePage[6] = 1; // EV_CURRENT

        auto write16m = [&](size_t off, uint16_t v) { std::memcpy(modulePage.data() + off, &v, 2); };
        auto write32m = [&](size_t off, uint32_t v) { std::memcpy(modulePage.data() + off, &v, 4); };
        auto write64m = [&](size_t off, uint64_t v) { std::memcpy(modulePage.data() + off, &v, 8); };

        // ELF header fields (at offset 0)
        write16m(16, 3);    // e_type = ET_DYN
        write16m(18, 62);   // e_machine = EM_X86_64
        write32m(20, 1);    // e_version
        write64m(24, 0);    // e_entry
        write64m(32, 64);   // e_phoff
        write64m(40, 0);    // e_shoff
        write32m(48, 0);    // e_flags
        write16m(52, 64);   // e_ehsize
        write16m(54, 56);   // e_phentsize
        write16m(56, 2);    // e_phnum
        write16m(58, 64);   // e_shentsize
        write16m(60, 0);    // e_shnum
        write16m(62, 0);    // e_shstrndx

        // Module phdr[0]: PT_LOAD covering the whole page (p_vaddr=0, bias = c_moduleBase)
        write32m(64, 1);                          // p_type = PT_LOAD
        write32m(68, 5);                          // p_flags = PF_R|PF_X
        write64m(72, 0);                          // p_offset = 0
        write64m(80, 0);                          // p_vaddr = 0
        write64m(88, 0);                          // p_paddr
        write64m(96, static_cast<uint64_t>(modulePageSize)); // p_filesz
        write64m(104, static_cast<uint64_t>(modulePageSize)); // p_memsz
        write64m(112, 0x1000);                    // p_align

        // Module phdr[1]: PT_NOTE at relative offset c_noteRelOffset
        write32m(120, 4);                                        // p_type = PT_NOTE
        write32m(124, 0);                                        // p_flags
        write64m(128, c_noteRelOffset);                          // p_offset
        write64m(136, c_noteRelOffset);                          // p_vaddr (+ loadBias = processVA)
        write64m(144, 0);                                        // p_paddr
        write64m(152, static_cast<uint64_t>(buildIdNote.size())); // p_filesz
        write64m(160, 0);                                        // p_memsz
        write64m(168, 8);                                        // p_align

        // Copy the build-ID note into the module page at the expected offset.
        std::memcpy(modulePage.data() + c_noteRelOffset, buildIdNote.data(), buildIdNote.size());

        // --- Build core file ---
        //
        // Core layout:
        //   [0,   64)   Core ELF header (phnum=2)
        //   [64,  120)  Core phdr[0]: PT_NOTE pointing at core notes
        //   [120, 176)  Core phdr[1]: PT_LOAD → maps c_moduleBase → module page
        //   [176, ...)  Core notes (NT_PRSTATUS with crashIp, NT_FILE listing the module)
        //   [176+coreNotesSize, ...)  Module ELF page bytes

        // Build NT_PRSTATUS note: RIP = c_crashIp.
        auto prstatusDesc = BuildPrstatusDesc64();
        std::memcpy(prstatusDesc.data() + 240, &c_crashIp, sizeof(c_crashIp)); // overwrite RIP
        const auto prstatusNote = BuildNote(1 /* NT_PRSTATUS */, std::string_view("CORE\0", 5), prstatusDesc);

        // Build NT_FILE note for the module.
        // NT_FILE desc (64-bit):
        //   count (8), pageSize (8),
        //   { start(8), end(8), filePageOffset(8) } × count,
        //   NUL-terminated filenames
        const std::string c_modulePath = "/usr/lib/libfoo.so.1";
        const uint64_t c_moduleEnd = c_moduleBase + 0x1000; // module VA range: [c_moduleBase, c_moduleEnd)
        std::vector<uint8_t> ntFileDesc;
        auto appendU64 = [&](uint64_t v) { ntFileDesc.insert(ntFileDesc.end(), reinterpret_cast<uint8_t*>(&v), reinterpret_cast<uint8_t*>(&v) + 8); };
        appendU64(1);              // count = 1
        appendU64(0x1000);         // pageSize
        appendU64(c_moduleBase);   // start
        appendU64(c_moduleEnd);    // end
        appendU64(0);              // file page offset
        // Append path with NUL terminator.
        ntFileDesc.insert(ntFileDesc.end(), c_modulePath.begin(), c_modulePath.end());
        ntFileDesc.push_back('\0');
        const auto ntFileNote = BuildNote(0x46494c45u /* NT_FILE */, std::string_view("CORE\0", 5), ntFileDesc);

        // Concatenate core notes.
        std::vector<uint8_t> coreNotes;
        coreNotes.insert(coreNotes.end(), prstatusNote.begin(), prstatusNote.end());
        coreNotes.insert(coreNotes.end(), ntFileNote.begin(), ntFileNote.end());
        const uint64_t coreNotesSize = coreNotes.size();

        // File offset where the module page will live.
        constexpr uint64_t c_coreHdrSize = 64;
        constexpr uint64_t c_corePhdrsSize = 2 * 56; // 2 phdrs × 56 bytes
        constexpr uint64_t c_coreNotesOffset = c_coreHdrSize + c_corePhdrsSize; // = 176
        const uint64_t c_modulePageOffset = c_coreNotesOffset + coreNotesSize;

        // Assemble the core ELF file.
        std::vector<uint8_t> core;
        core.reserve(static_cast<size_t>(c_modulePageOffset) + modulePageSize);

        // ELF ident
        core.push_back(0x7f); core.push_back('E'); core.push_back('L'); core.push_back('F');
        core.push_back(2); // ELFCLASS64
        core.push_back(1); // ELFDATA2LSB
        core.push_back(1); // EV_CURRENT
        core.insert(core.end(), 9, 0); // padding

        auto write16c = [&](uint16_t v) { core.insert(core.end(), reinterpret_cast<uint8_t*>(&v), reinterpret_cast<uint8_t*>(&v) + 2); };
        auto write32c = [&](uint32_t v) { core.insert(core.end(), reinterpret_cast<uint8_t*>(&v), reinterpret_cast<uint8_t*>(&v) + 4); };
        auto write64c = [&](uint64_t v) { core.insert(core.end(), reinterpret_cast<uint8_t*>(&v), reinterpret_cast<uint8_t*>(&v) + 8); };

        // Core ELF header
        write16c(4);                // e_type = ET_CORE
        write16c(62);               // e_machine = EM_X86_64
        write32c(1);                // e_version
        write64c(0);                // e_entry
        write64c(c_coreHdrSize);    // e_phoff
        write64c(0);                // e_shoff
        write32c(0);                // e_flags
        write16c(64);               // e_ehsize
        write16c(56);               // e_phentsize
        write16c(2);                // e_phnum
        write16c(64);               // e_shentsize
        write16c(0);                // e_shnum
        write16c(0);                // e_shstrndx

        // Core phdr[0]: PT_NOTE
        write32c(4);                // p_type = PT_NOTE
        write32c(0);                // p_flags
        write64c(c_coreNotesOffset);// p_offset
        write64c(0);                // p_vaddr
        write64c(0);                // p_paddr
        write64c(coreNotesSize);    // p_filesz
        write64c(0);                // p_memsz
        write64c(0);                // p_align

        // Core phdr[1]: PT_LOAD → backs c_moduleBase with the module ELF page
        write32c(1);                // p_type = PT_LOAD
        write32c(5);                // p_flags = PF_R|PF_X
        write64c(c_modulePageOffset);// p_offset
        write64c(c_moduleBase);     // p_vaddr
        write64c(0);                // p_paddr
        write64c(static_cast<uint64_t>(modulePageSize)); // p_filesz
        write64c(0x1000);           // p_memsz
        write64c(0x1000);           // p_align

        // Core notes
        core.insert(core.end(), coreNotes.begin(), coreNotes.end());

        // Module ELF page
        core.insert(core.end(), modulePage.begin(), modulePage.end());

        const TempCoreFile tmp{core};
        const auto info = ParseElfCoreDump(tmp.path);

        VERIFY_ARE_EQUAL(c_expectedHex, info.moduleBuildId);
        VERIFY_ARE_EQUAL(std::string("libfoo.so.1"), info.moduleName);
        VERIFY_ARE_EQUAL(c_crashIp - c_moduleBase, info.moduleOffset);
    }

    // Same as ModuleBuildIdExtractedFromElfPage but with TWO NT_FILE entries for the
    // same library.  The crash IP falls in the SECOND segment (no ELF header there),
    // and only the FIRST segment's page is captured in the core.  The parser must scan
    // all entries for the module path and use the lowest start VA as the ELF base.
    //
    // This exercises the "moduleElfBase = min start VA" fix that prevents an incorrect
    // blamedEntry->start (a mid-library segment with no captured pages) from being
    // passed to ReadModuleBuildId.
    TEST_METHOD(ModuleBuildIdFromFirstSegmentWhenCrashInSecond)
    {
        const std::vector<uint8_t> c_buildIdBytes = {0x11, 0x22, 0x33, 0x44};
        const std::string c_expectedHex = "11223344";

        // First segment: ELF header base — has captured pages.
        constexpr uint64_t c_seg1Base = 0x500000;
        constexpr uint64_t c_seg1End  = 0x501000; // 1 page

        // Second segment: later mapping — NOT captured in core but contains the crash IP.
        constexpr uint64_t c_seg2Base = 0x502000;
        constexpr uint64_t c_seg2End  = 0x504000;
        constexpr uint64_t c_crashIp  = 0x502F00; // inside seg2, not seg1

        const std::string c_modulePath = "/usr/lib/libbar.so.2";

        // Build the GNU build-ID note (goes into the ELF header page at seg1Base).
        const auto buildIdNote = BuildNote(3 /* NT_GNU_BUILD_ID */, std::string_view("GNU\0", 4), c_buildIdBytes);

        constexpr uint64_t c_noteRelOffset = 176; // = 64 (ehdr) + 56 + 56 (2 phdrs)
        const size_t modulePageSize = c_noteRelOffset + buildIdNote.size();

        std::vector<uint8_t> modulePage(modulePageSize, 0);

        modulePage[0] = 0x7f; modulePage[1] = 'E'; modulePage[2] = 'L'; modulePage[3] = 'F';
        modulePage[4] = 2; modulePage[5] = 1; modulePage[6] = 1;

        auto write16m = [&](size_t off, uint16_t v) { std::memcpy(modulePage.data() + off, &v, 2); };
        auto write32m = [&](size_t off, uint32_t v) { std::memcpy(modulePage.data() + off, &v, 4); };
        auto write64m = [&](size_t off, uint64_t v) { std::memcpy(modulePage.data() + off, &v, 8); };

        write16m(16, 3); write16m(18, 62); write32m(20, 1);
        write64m(24, 0); write64m(32, 64); write64m(40, 0);
        write32m(48, 0); write16m(52, 64); write16m(54, 56); write16m(56, 2);
        write16m(58, 64); write16m(60, 0); write16m(62, 0);

        // PT_LOAD covering first page
        write32m(64, 1);  write32m(68, 5);  write64m(72, 0); write64m(80, 0);
        write64m(88, 0);  write64m(96, static_cast<uint64_t>(modulePageSize));
        write64m(104, static_cast<uint64_t>(modulePageSize)); write64m(112, 0x1000);

        // PT_NOTE
        write32m(120, 4);  write32m(124, 0); write64m(128, c_noteRelOffset);
        write64m(136, c_noteRelOffset); write64m(144, 0);
        write64m(152, static_cast<uint64_t>(buildIdNote.size())); write64m(160, 0); write64m(168, 8);

        std::memcpy(modulePage.data() + c_noteRelOffset, buildIdNote.data(), buildIdNote.size());

        // Build NT_PRSTATUS with crashIp in seg2.
        auto prstatusDesc = BuildPrstatusDesc64();
        std::memcpy(prstatusDesc.data() + 240, &c_crashIp, sizeof(c_crashIp));
        const auto prstatusNote = BuildNote(1, std::string_view("CORE\0", 5), prstatusDesc);

        // Build NT_FILE with TWO entries for the same module path.
        std::vector<uint8_t> ntFileDesc;
        auto appendU64 = [&](uint64_t v) {
            ntFileDesc.insert(ntFileDesc.end(), reinterpret_cast<uint8_t*>(&v), reinterpret_cast<uint8_t*>(&v) + 8);
        };
        appendU64(2);           // count = 2
        appendU64(0x1000);      // pageSize
        // Entry 0: seg1 (ELF base)
        appendU64(c_seg1Base); appendU64(c_seg1End); appendU64(0);
        // Entry 1: seg2 (crash IP lives here)
        appendU64(c_seg2Base); appendU64(c_seg2End); appendU64(0x1000);
        // Names: same path for both
        ntFileDesc.insert(ntFileDesc.end(), c_modulePath.begin(), c_modulePath.end());
        ntFileDesc.push_back('\0');
        ntFileDesc.insert(ntFileDesc.end(), c_modulePath.begin(), c_modulePath.end());
        ntFileDesc.push_back('\0');
        const auto ntFileNote = BuildNote(0x46494c45u, std::string_view("CORE\0", 5), ntFileDesc);

        std::vector<uint8_t> coreNotes;
        coreNotes.insert(coreNotes.end(), prstatusNote.begin(), prstatusNote.end());
        coreNotes.insert(coreNotes.end(), ntFileNote.begin(), ntFileNote.end());
        const uint64_t coreNotesSize = coreNotes.size();

        constexpr uint64_t c_coreNotesOffset = 64 + 2 * 56; // ehdr + 2 phdrs (PT_NOTE + PT_LOAD)
        const uint64_t c_modulePageOffset = c_coreNotesOffset + coreNotesSize;

        std::vector<uint8_t> core;
        // ELF ident
        core.push_back(0x7f); core.push_back('E'); core.push_back('L'); core.push_back('F');
        core.push_back(2); core.push_back(1); core.push_back(1);
        core.insert(core.end(), 9, 0);

        auto write16c = [&](uint16_t v) { core.insert(core.end(), reinterpret_cast<uint8_t*>(&v), reinterpret_cast<uint8_t*>(&v) + 2); };
        auto write32c = [&](uint32_t v) { core.insert(core.end(), reinterpret_cast<uint8_t*>(&v), reinterpret_cast<uint8_t*>(&v) + 4); };
        auto write64c = [&](uint64_t v) { core.insert(core.end(), reinterpret_cast<uint8_t*>(&v), reinterpret_cast<uint8_t*>(&v) + 8); };

        write16c(4); write16c(62); write32c(1); write64c(0); write64c(64); write64c(0);
        write32c(0); write16c(64); write16c(56); write16c(2); write16c(64); write16c(0); write16c(0);

        // PT_NOTE phdr
        write32c(4); write32c(0); write64c(c_coreNotesOffset); write64c(0);
        write64c(0); write64c(coreNotesSize); write64c(0); write64c(0);

        // PT_LOAD: maps seg1Base to module ELF page (seg2 has NO PT_LOAD — not captured)
        write32c(1); write32c(5); write64c(c_modulePageOffset); write64c(c_seg1Base);
        write64c(0); write64c(static_cast<uint64_t>(modulePageSize)); write64c(0x1000); write64c(0x1000);

        core.insert(core.end(), coreNotes.begin(), coreNotes.end());
        core.insert(core.end(), modulePage.begin(), modulePage.end());

        const TempCoreFile tmp{core};
        const auto info = ParseElfCoreDump(tmp.path);

        VERIFY_ARE_EQUAL(c_expectedHex, info.moduleBuildId);
        VERIFY_ARE_EQUAL(std::string("libbar.so.2"), info.moduleName);
        // moduleOffset must be relative to the ELF base (seg1), not seg2.
        VERIFY_ARE_EQUAL(c_crashIp - c_seg1Base, info.moduleOffset);
    }
};

} // namespace ElfCoreDumpUnitTests
