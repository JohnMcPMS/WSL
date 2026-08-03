// Copyright (C) Microsoft Corporation. All rights reserved.

#include "precomp.h"
#include "ElfCoreDump.h"

#include <algorithm>
#include <string_view>
#include <vector>

using namespace wsl::windows::common;
using namespace wsl::windows::common::string;

namespace {

// ---------------------------------------------------------------------------
// Minimal ELF type definitions (Windows-side; no Linux SDK dependency)
// Names and values follow the Linux UAPI / System V ABI specification.
// ---------------------------------------------------------------------------

// The 16-byte ELF identification header common to all ELF files.
// Appears at offset 0 and can be read before the bitness class is known.
struct ElfIdent
{
    uint8_t magic[4];     // \x7fELF
    uint8_t elfClass;     // EI_CLASS: 1 = 32-bit, 2 = 64-bit
    uint8_t dataEncoding; // EI_DATA
    uint8_t version;      // EI_VERSION
    uint8_t osAbi;        // EI_OSABI
    uint8_t abiVersion;   // EI_ABIVERSION
    uint8_t pad[7];       // EI_PAD

    bool HasValidMagic() const noexcept
    {
        return magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F';
    }

    uint8_t Class() const noexcept
    {
        return elfClass;
    }
    bool IsLittleEndian() const noexcept
    {
        return dataEncoding == Encoding2LSB;
    }
    uint8_t Version() const noexcept
    {
        return version;
    }

    static constexpr uint8_t Class32 = 1;
    static constexpr uint8_t Class64 = 2;
    static constexpr uint8_t Encoding2LSB = 1; // little-endian
    static constexpr uint8_t VersionCurrent = 1;
};
static_assert(sizeof(ElfIdent) == 16);

// e_type values
constexpr uint16_t c_etCore = 4;

// p_type values
constexpr uint32_t c_ptLoad = 1;
constexpr uint32_t c_ptNote = 4;

// Note n_type values (owner "CORE")
constexpr uint32_t c_ntPrstatus = 1;
constexpr uint32_t c_ntAuxv = 6;
constexpr uint32_t c_ntSiginfo = 0x53494749u; // 'SIGI'
constexpr uint32_t c_ntFile = 0x46494c45u;    // 'FILE'

// Note n_type value (owner "GNU")
constexpr uint32_t c_ntGnuBuildId = 3;

// AT_* auxiliary vector types
constexpr uint64_t c_atNull = 0;
constexpr uint64_t c_atExecfn = 31;

// e_machine values
constexpr uint16_t c_emX86_64 = 62;
constexpr uint16_t c_emAarch64 = 183;

// Index of the instruction pointer register in elf_gregset_t
// x86_64 (ELF_NGREG=27): r15,r14,r13,r12,rbp,rbx,r11,r10,r9,r8,rax,rcx,rdx,rsi,rdi,orig_rax,rip,...
constexpr size_t c_ipRegX86_64 = 16; // RIP
// aarch64 (ELF_NREG=34): x0-x30, sp, pc, pstate
constexpr size_t c_ipRegAarch64 = 32; // PC

// Offset of pr_reg within elf_prstatus for each bitness.
// 64-bit: elf_siginfo(12) + cursig(2) + pad(2) + sigpend(8) + sighold(8) + pid*4(16) + timeval*4(64) = 112
// 32-bit: elf_siginfo(12) + cursig(2) + pad(2) + sigpend(4) + sighold(4) + pid*4(16) + timeval*4(32) = 72
constexpr size_t c_prRegOffset64 = 112;
constexpr size_t c_prRegOffset32 = 72;

// Maximum number of entries we're willing to read from NT_FILE to avoid
// excessive allocation on a malformed core.
constexpr uint64_t c_maxFileMapEntries = 65536;

struct Elf64Ehdr
{
    ElfIdent e_ident;
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
};
static_assert(sizeof(Elf64Ehdr) == 64);

struct Elf32Ehdr
{
    ElfIdent e_ident;
    uint16_t e_type, e_machine;
    uint32_t e_version, e_entry, e_phoff, e_shoff, e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
};
static_assert(sizeof(Elf32Ehdr) == 52);

struct Elf64Phdr
{
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
};
static_assert(sizeof(Elf64Phdr) == 56);

struct Elf32Phdr
{
    uint32_t p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align;
};
static_assert(sizeof(Elf32Phdr) == 32);

struct ElfNhdr
{
    uint32_t n_namesz, n_descsz, n_type;
};
static_assert(sizeof(ElfNhdr) == 12);

// ---------------------------------------------------------------------------
// Read-only memory-mapped view of the core dump file
// ---------------------------------------------------------------------------

class CoreView
{
public:
    explicit CoreView(const std::filesystem::path& path)
    {
        m_file.reset(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        THROW_LAST_ERROR_IF(!m_file);

        LARGE_INTEGER size{};
        THROW_IF_WIN32_BOOL_FALSE(GetFileSizeEx(m_file.get(), &size));
        m_size = static_cast<uint64_t>(size.QuadPart);
        THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_EMPTY), m_size == 0);

        m_mapping.reset(CreateFileMappingW(m_file.get(), nullptr, PAGE_READONLY, 0, 0, nullptr));
        THROW_LAST_ERROR_IF(!m_mapping);

        m_view = static_cast<const uint8_t*>(MapViewOfFile(m_mapping.get(), FILE_MAP_READ, 0, 0, 0));
        THROW_LAST_ERROR_IF(!m_view);
    }

    ~CoreView()
    {
        if (m_view)
        {
            UnmapViewOfFile(m_view);
        }
    }

    NON_COPYABLE(CoreView);
    NON_MOVABLE(CoreView);

    // Return a pointer to a T at byte offset, or nullptr if it would exceed the file.
    template <typename T>
    const T* At(uint64_t offset) const noexcept
    {
        if (offset + sizeof(T) > m_size || offset + sizeof(T) < offset)
        {
            return nullptr;
        }
        return reinterpret_cast<const T*>(m_view + offset);
    }

    // Return a pointer to len bytes at offset, or nullptr if it would exceed the file.
    const uint8_t* Ptr(uint64_t offset, uint64_t len) const noexcept
    {
        if (len == 0 || offset + len > m_size || offset + len < offset)
        {
            return nullptr;
        }
        return m_view + offset;
    }

    uint64_t Size() const noexcept
    {
        return m_size;
    }

private:
    wil::unique_hfile m_file;
    wil::unique_handle m_mapping;
    const uint8_t* m_view = nullptr;
    uint64_t m_size = 0;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ELF note fields are rounded up to 4-byte alignment.
constexpr uint32_t Align4(uint32_t x) noexcept
{
    return (x + 3u) & ~3u;
}
constexpr uint64_t Align4(uint64_t x) noexcept
{
    return (x + 3ull) & ~3ull;
}

// Return the filename component of a Linux path string (after last '/').
std::string LinuxBasename(std::string_view path)
{
    const auto pos = path.rfind('/');
    return std::string(pos == std::string_view::npos ? path : path.substr(pos + 1));
}

// ---------------------------------------------------------------------------
// Note iteration
// ---------------------------------------------------------------------------

// Invoke fn(type, ownerName, descPtr, descSize) for each note in the buffer.
// Stops early if fn returns false. Safely skips malformed entries.
template <typename Fn>
void IterateNotes(const uint8_t* noteData, uint64_t noteSize, Fn&& fn)
{
    uint64_t pos = 0;
    while (pos + sizeof(ElfNhdr) <= noteSize)
    {
        const auto* nhdr = reinterpret_cast<const ElfNhdr*>(noteData + pos);
        pos += sizeof(ElfNhdr);

        const uint32_t nameBytes = Align4(nhdr->n_namesz);
        const uint32_t descBytes = Align4(nhdr->n_descsz);

        if (pos + nameBytes + descBytes > noteSize)
        {
            break;
        }

        const char* name = reinterpret_cast<const char*>(noteData + pos);
        const uint8_t* desc = noteData + pos + nameBytes;

        // n_namesz includes the null terminator; expose the name without it.
        const auto nameView = (nhdr->n_namesz > 1) ? std::string_view(name, nhdr->n_namesz - 1) : std::string_view{};

        if (!fn(nhdr->n_type, nameView, desc, nhdr->n_descsz))
        {
            return;
        }

        pos += nameBytes + descBytes;
    }
}

// ---------------------------------------------------------------------------
// VA → core file offset translation
// ---------------------------------------------------------------------------

struct LoadSegment
{
    uint64_t vaddr;
    uint64_t filesz;
    uint64_t fileOffset;
};

// Given a virtual address, return its byte offset in the core file, or nullopt
// if no PT_LOAD segment covers it (e.g., the page was not dumped).
std::optional<uint64_t> VaToFileOffset(const std::vector<LoadSegment>& loads, uint64_t va)
{
    for (const auto& seg : loads)
    {
        if (va >= seg.vaddr && va - seg.vaddr < seg.filesz)
        {
            return seg.fileOffset + (va - seg.vaddr);
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Build ID extraction from a module's in-memory ELF image
// ---------------------------------------------------------------------------

// Attempt to read the GNU build ID of the module whose first byte is at
// virtual address moduleBase. We read the module's own ELF header from the
// core's PT_LOAD snapshot, then follow the module's PT_NOTE program header
// to find its embedded NT_GNU_BUILD_ID note.
std::string ReadModuleBuildId(const CoreView& core, const std::vector<LoadSegment>& loads, uint64_t moduleBase)
{
    // --- Read the module's ELF header from the core ---
    const auto ehdrOffset = VaToFileOffset(loads, moduleBase);
    if (!ehdrOffset)
    {
        return {};
    }

    const auto* ident = core.Ptr(*ehdrOffset, 16);
    if (!ident || ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F')
    {
        return {};
    }

    const uint8_t elfClass = ident[4];

    uint64_t phoff{};
    uint16_t phentsize{}, phnum{};
    uint64_t firstLoadVaddr = UINT64_MAX;

    if (elfClass == ElfIdent::Class64)
    {
        const auto* ehdr = core.At<Elf64Ehdr>(*ehdrOffset);
        if (!ehdr)
        {
            return {};
        }
        phoff = ehdr->e_phoff;
        phentsize = ehdr->e_phentsize;
        phnum = ehdr->e_phnum;
    }
    else if (elfClass == ElfIdent::Class32)
    {
        const auto* ehdr = core.At<Elf32Ehdr>(*ehdrOffset);
        if (!ehdr)
        {
            return {};
        }
        phoff = ehdr->e_phoff;
        phentsize = ehdr->e_phentsize;
        phnum = ehdr->e_phnum;
    }
    else
    {
        return {};
    }

    if (phentsize == 0 || phnum == 0)
    {
        return {};
    }

    // --- Determine load bias = moduleBase - firstLoadVaddr ---
    // We need to translate the module's own p_vaddr values to process VAs.
    // Read the module's program header table from the core.
    for (uint16_t i = 0; i < phnum; ++i)
    {
        const uint64_t phdrsVa = moduleBase + phoff + static_cast<uint64_t>(i) * phentsize;
        const auto phdrsOffset = VaToFileOffset(loads, phdrsVa);
        if (!phdrsOffset)
        {
            continue;
        }

        if (elfClass == ElfIdent::Class64)
        {
            const auto* phdr = core.At<Elf64Phdr>(*phdrsOffset);
            if (phdr && phdr->p_type == c_ptLoad && phdr->p_vaddr < firstLoadVaddr)
            {
                firstLoadVaddr = phdr->p_vaddr;
            }
        }
        else
        {
            const auto* phdr = core.At<Elf32Phdr>(*phdrsOffset);
            if (phdr && phdr->p_type == c_ptLoad && phdr->p_vaddr < firstLoadVaddr)
            {
                firstLoadVaddr = phdr->p_vaddr;
            }
        }
    }

    if (firstLoadVaddr == UINT64_MAX)
    {
        return {};
    }

    const uint64_t loadBias = moduleBase - firstLoadVaddr;

    // --- Find the module's PT_NOTE and extract NT_GNU_BUILD_ID ---
    for (uint16_t i = 0; i < phnum; ++i)
    {
        const uint64_t phdrsVa = moduleBase + phoff + static_cast<uint64_t>(i) * phentsize;
        const auto phdrsOffset = VaToFileOffset(loads, phdrsVa);
        if (!phdrsOffset)
        {
            continue;
        }

        uint32_t noteType{};
        uint64_t noteVaddr{};
        uint64_t noteFilesz{};

        if (elfClass == ElfIdent::Class64)
        {
            const auto* phdr = core.At<Elf64Phdr>(*phdrsOffset);
            if (!phdr || phdr->p_type != c_ptNote)
            {
                continue;
            }
            noteType = phdr->p_type;
            noteVaddr = phdr->p_vaddr + loadBias;
            noteFilesz = phdr->p_filesz;
        }
        else
        {
            const auto* phdr = core.At<Elf32Phdr>(*phdrsOffset);
            if (!phdr || phdr->p_type != c_ptNote)
            {
                continue;
            }
            noteType = phdr->p_type;
            noteVaddr = phdr->p_vaddr + loadBias;
            noteFilesz = phdr->p_filesz;
        }

        if (noteFilesz == 0 || noteFilesz > 1024 * 1024)
        {
            continue;
        }

        const auto noteOffset = VaToFileOffset(loads, noteVaddr);
        if (!noteOffset)
        {
            continue;
        }

        const auto* noteData = core.Ptr(*noteOffset, noteFilesz);
        if (!noteData)
        {
            continue;
        }

        std::string buildId;
        IterateNotes(noteData, noteFilesz, [&](uint32_t type, std::string_view name, const uint8_t* desc, uint32_t descSize) {
            if (type == c_ntGnuBuildId && name == "GNU" && descSize > 0)
            {
                buildId = WideToMultiByte(BytesToHex({desc, desc + descSize}).substr(2));
                return false; // stop
            }
            return true;
        });

        if (!buildId.empty())
        {
            return buildId;
        }
    }

    return {};
}

// ---------------------------------------------------------------------------
// Concrete parsing for 64-bit and 32-bit cores
// ---------------------------------------------------------------------------

template <typename Ehdr, typename Phdr>
ElfCrashInfo DoParse(const CoreView& core, const Ehdr& ehdr)
{
    const bool is64 = (ehdr.e_ident.Class() == ElfIdent::Class64);

    THROW_HR_IF_MSG(E_INVALIDARG, ehdr.e_phentsize == 0 || ehdr.e_phnum == 0, "ELF core has no program headers");

    // --- Collect PT_NOTE and PT_LOAD segments ---
    std::vector<std::pair<uint64_t, uint64_t>> noteParts; // {file offset, size}
    std::vector<LoadSegment> loads;

    for (uint16_t i = 0; i < ehdr.e_phnum; ++i)
    {
        const uint64_t phdrOffset = static_cast<uint64_t>(ehdr.e_phoff) + static_cast<uint64_t>(i) * ehdr.e_phentsize;
        const auto* phdr = core.At<Phdr>(phdrOffset);
        THROW_HR_IF_MSG(E_INVALIDARG, !phdr, "Program header %u is truncated or out of bounds", i);

        if (phdr->p_type == c_ptNote && phdr->p_filesz > 0)
        {
            noteParts.emplace_back(static_cast<uint64_t>(phdr->p_offset), static_cast<uint64_t>(phdr->p_filesz));
        }
        else if (phdr->p_type == c_ptLoad)
        {
            loads.push_back({static_cast<uint64_t>(phdr->p_vaddr), static_cast<uint64_t>(phdr->p_filesz), static_cast<uint64_t>(phdr->p_offset)});
        }
    }

    THROW_HR_IF_MSG(E_INVALIDARG, noteParts.empty(), "ELF core has no PT_NOTE segments");

    // --- Extract information from notes ---
    ElfCrashInfo info;
    info.elfMachine = ehdr.e_machine;

    uint64_t crashIp = 0;
    bool hasCrashIp = false;

    // Map from module start VA to module path (from NT_FILE).
    // We collect all entries then find the one containing crashIp afterwards.
    struct FileEntry
    {
        uint64_t start, end;
        std::string path;
    };
    std::vector<FileEntry> fileMap;

    for (const auto& [noteFileOffset, noteFileSize] : noteParts)
    {
        const auto* noteData = core.Ptr(noteFileOffset, noteFileSize);
        if (!noteData)
        {
            continue;
        }

        IterateNotes(noteData, noteFileSize, [&](uint32_t type, std::string_view name, const uint8_t* desc, uint32_t descSize) {
            if (name == "CORE")
            {
                if (type == c_ntPrstatus && !hasCrashIp)
                {
                    // pr_reg starts at c_prRegOffset64/32; each register is pointer-sized.
                    const size_t prRegOffset = is64 ? c_prRegOffset64 : c_prRegOffset32;
                    const size_t regWidth = is64 ? 8u : 4u;
                    const size_t ipReg = (ehdr.e_machine == c_emAarch64) ? c_ipRegAarch64 : c_ipRegX86_64;
                    const size_t ipOffset = prRegOffset + ipReg * regWidth;

                    if (descSize >= ipOffset + regWidth)
                    {
                        if (is64)
                        {
                            uint64_t ip{};
                            std::memcpy(&ip, desc + ipOffset, sizeof(ip));
                            crashIp = ip;
                            hasCrashIp = true;
                        }
                        else
                        {
                            uint32_t ip{};
                            std::memcpy(&ip, desc + ipOffset, sizeof(ip));
                            crashIp = ip;
                            hasCrashIp = true;
                        }
                    }
                }
                else if (type == c_ntSiginfo && descSize >= 12)
                {
                    // siginfo_t layout: si_signo(4), si_errno(4), si_code(4)
                    int32_t siCode{};
                    std::memcpy(&siCode, desc + 8, sizeof(siCode));
                    info.siCode = static_cast<uint32_t>(siCode);
                }
                else if (type == c_ntFile && fileMap.empty())
                {
                    // Header: count, page_size; then count * {start, end, file_ofs}; then filenames.
                    const size_t wordSize = is64 ? 8u : 4u;
                    if (descSize < 2 * wordSize)
                    {
                        return true;
                    }

                    uint64_t count{}, pageSize{};
                    if (is64)
                    {
                        std::memcpy(&count, desc, sizeof(uint64_t));
                        std::memcpy(&pageSize, desc + 8, sizeof(uint64_t));
                    }
                    else
                    {
                        uint32_t c32{}, p32{};
                        std::memcpy(&c32, desc, sizeof(uint32_t));
                        std::memcpy(&p32, desc + 4, sizeof(uint32_t));
                        count = c32;
                        pageSize = p32;
                    }

                    if (count == 0 || count > c_maxFileMapEntries)
                    {
                        return true;
                    }

                    const size_t tripletSize = 3 * wordSize;
                    const size_t headerSize = 2 * wordSize;
                    const size_t tableSize = count * tripletSize;
                    if (descSize < headerSize + tableSize)
                    {
                        return true;
                    }

                    const uint8_t* nameBase = desc + headerSize + tableSize;
                    const uint8_t* descEnd = desc + descSize;

                    for (uint64_t j = 0; j < count; ++j)
                    {
                        const uint8_t* entry = desc + headerSize + j * tripletSize;
                        uint64_t start{}, end{};
                        if (is64)
                        {
                            std::memcpy(&start, entry, sizeof(uint64_t));
                            std::memcpy(&end, entry + 8, sizeof(uint64_t));
                        }
                        else
                        {
                            uint32_t s32{}, e32{};
                            std::memcpy(&s32, entry, sizeof(uint32_t));
                            std::memcpy(&e32, entry + 4, sizeof(uint32_t));
                            start = s32;
                            end = e32;
                        }

                        // Find the null-terminated filename for entry j.
                        const uint8_t* namePtr = nameBase;
                        for (uint64_t k = 0; k < j; ++k)
                        {
                            const uint8_t* nul =
                                static_cast<const uint8_t*>(std::memchr(namePtr, '\0', static_cast<size_t>(descEnd - namePtr)));
                            if (!nul)
                            {
                                namePtr = descEnd;
                                break;
                            }
                            namePtr = nul + 1;
                        }

                        std::string path;
                        if (namePtr < descEnd)
                        {
                            const uint8_t* nul =
                                static_cast<const uint8_t*>(std::memchr(namePtr, '\0', static_cast<size_t>(descEnd - namePtr)));
                            path = (nul != nullptr) ? std::string(reinterpret_cast<const char*>(namePtr), nul - namePtr)
                                                    : std::string(reinterpret_cast<const char*>(namePtr), descEnd - namePtr);
                        }

                        fileMap.push_back({start, end, std::move(path)});
                    }
                }
                else if (type == c_ntAuxv && info.processName.empty())
                {
                    // Array of {a_type, a_val} pairs; terminated by AT_NULL.
                    const size_t pairSize = is64 ? 16u : 8u;
                    for (size_t off = 0; off + pairSize <= descSize; off += pairSize)
                    {
                        uint64_t aType{}, aVal{};
                        if (is64)
                        {
                            std::memcpy(&aType, desc + off, sizeof(uint64_t));
                            std::memcpy(&aVal, desc + off + 8, sizeof(uint64_t));
                        }
                        else
                        {
                            uint32_t t32{}, v32{};
                            std::memcpy(&t32, desc + off, sizeof(uint32_t));
                            std::memcpy(&v32, desc + off + 4, sizeof(uint32_t));
                            aType = t32;
                            aVal = v32;
                        }

                        if (aType == c_atNull)
                        {
                            break;
                        }

                        if (aType == c_atExecfn && aVal != 0)
                        {
                            // aVal is a VA pointing to the executable path string.
                            const auto strOffset = VaToFileOffset(loads, aVal);
                            if (strOffset)
                            {
                                const auto* strPtr = core.Ptr(*strOffset, 1);
                                if (strPtr)
                                {
                                    // Read up to 4096 bytes for safety.
                                    constexpr size_t c_maxPathLen = 4096;
                                    const size_t remaining = core.Size() - *strOffset;
                                    const size_t maxLen = std::min(remaining, c_maxPathLen);
                                    const auto* nul = static_cast<const uint8_t*>(std::memchr(strPtr, '\0', maxLen));
                                    const size_t len = nul ? static_cast<size_t>(nul - strPtr) : maxLen;
                                    const auto fullPath = std::string(reinterpret_cast<const char*>(strPtr), len);
                                    info.processName = LinuxBasename(fullPath);
                                }
                            }
                        }
                    }
                }
            }
            else if (name == "GNU" && type == c_ntGnuBuildId && info.processBuildId.empty() && descSize > 0)
            {
                // The first GNU build ID note in the core's own PT_NOTE is for the main executable.
                info.processBuildId = WideToMultiByte(BytesToHex({desc, desc + descSize}).substr(2));
            }

            return true; // continue iteration
        });
    }

    THROW_HR_IF_MSG(E_INVALIDARG, !hasCrashIp, "No NT_PRSTATUS note found; cannot determine crash instruction pointer");

    // --- Identify the blamed module from NT_FILE ---
    const FileEntry* blamedEntry = nullptr;
    for (const auto& entry : fileMap)
    {
        if (crashIp >= entry.start && crashIp < entry.end && !entry.path.empty())
        {
            blamedEntry = &entry;
            break;
        }
    }

    if (blamedEntry)
    {
        info.moduleName = LinuxBasename(blamedEntry->path);
        info.moduleOffset = crashIp - blamedEntry->start;

        // Attempt to extract the blamed module's build ID from its in-memory ELF image.
        info.moduleBuildId = ReadModuleBuildId(core, loads, blamedEntry->start);
    }

    return info;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

ElfCrashInfo wsl::windows::common::ParseElfCoreDump(const std::filesystem::path& dumpPath)
{
    const CoreView core(dumpPath);

    const auto* ident = core.At<ElfIdent>(0);
    THROW_HR_IF_MSG(E_INVALIDARG, !ident || !ident->HasValidMagic(), "File does not begin with ELF magic");
    THROW_HR_IF_MSG(E_INVALIDARG, !ident->IsLittleEndian(), "ELF file is not little-endian (EI_DATA=%u)", ident->dataEncoding);
    THROW_HR_IF_MSG(E_INVALIDARG, ident->Version() != ElfIdent::VersionCurrent, "Unsupported ELF version (EI_VERSION=%u)", ident->version);

    if (ident->Class() == ElfIdent::Class64)
    {
        const auto* ehdr = core.At<Elf64Ehdr>(0);
        THROW_HR_IF_MSG(E_INVALIDARG, !ehdr, "ELF64 header is truncated");
        THROW_HR_IF_MSG(E_INVALIDARG, ehdr->e_type != c_etCore, "ELF file is not a core dump (e_type=%u)", ehdr->e_type);
        return DoParse<Elf64Ehdr, Elf64Phdr>(core, *ehdr);
    }
    else if (ident->Class() == ElfIdent::Class32)
    {
        const auto* ehdr = core.At<Elf32Ehdr>(0);
        THROW_HR_IF_MSG(E_INVALIDARG, !ehdr, "ELF32 header is truncated");
        THROW_HR_IF_MSG(E_INVALIDARG, ehdr->e_type != c_etCore, "ELF file is not a core dump (e_type=%u)", ehdr->e_type);
        return DoParse<Elf32Ehdr, Elf32Phdr>(core, *ehdr);
    }

    THROW_HR_MSG(E_INVALIDARG, "Unsupported ELF class %u (expected 32-bit or 64-bit)", ident->Class());
}
