#include <array>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <span>
#include <string_view>
#include <variant>
#include <bit>
#include "json.hpp"

uint32_t offset = 0;

using std::cout, std::endl;

using json = nlohmann::json;
using ByteBuf = std::array<std::byte, 256>;
using PeHeaderBuf = std::array<std::byte, 20>;
using DynamicBuffer = std::vector<char>;
using BYTE = uint8_t;
using WORD = uint16_t;
using DWORD = uint32_t;

ByteBuf read_prefix(const std::filesystem::path& p);
enum class Format { Unknown, Elf32, Elf64, Pe };
Format detect_format(std::span<const std::byte> ptr_to_buffer);

struct ElfInfo { /* minimal fields */ };

// TIL [[gnu::packed]] removes invisible paddings created by the compiler.
// This allows for a one-shot memcpy from the buffer (.exe) to the struct.
struct [[gnu::packed]] PeInfo  
{ 
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;

};


PeHeaderBuf read_pe_header(const std::filesystem::path& p, uint32_t offset);

struct [[gnu::packed]] PeOptionalHeaderInfo
{
    WORD    Magic;                          // Important field defines architecture of executable (32-bit or 64-bit)
    BYTE    MajorLinkerVersion; 
    BYTE    MinorLinkerVersion; 
    DWORD   SizeOfCode; 
    DWORD   SizeOfInitializedData;  
    DWORD   SizeOfUninitializedData;    
    DWORD   AddressOfEntryPoint;            // Address where the windows loader will begin execution
    DWORD   BaseOfCode;                     // Relative Virtual Address to Code section
    DWORD   BaseOfData;                     // Relative Virtual Address to Data section
    DWORD   ImageBase;  
    DWORD   SectionAlignment;               // Indicates alignment of sections of PE in the memory
    DWORD   FileAlignment;                  // Indicates alignment of sections of PE in the file
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;                    // Indicates memory size occupied by the PE file on runtime (has to be a multipule of the SectionAlignment values)
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;                      // Identifies the target subsystem for an executable file
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
};

std::variant<std::monostate, ElfInfo, PeInfo>
parse_header(Format, std::span<const std::byte>, const std::filesystem::path& p);

DynamicBuffer read_n_bytes_from_bin(const std::filesystem::path& p, uint32_t offset, uint16_t size);

int main(int argc, char** argv)
{
    if (argc != 2) { std::cerr << "usage: binheaderscout <file>\n..."; return 1; }
    auto buf   = read_prefix(argv[1]);      // read first 256 bytes
    auto fmt   = detect_format(buf);        // look at magic bytes
    auto info  = parse_header(fmt, buf, argv[1]);    // reinterpret into structs

    if (auto peInfo = std::get_if<PeInfo>(&info))
    {
        // This section deals with reading the optional header from the PE bin.
        offset += 24;
        DynamicBuffer pe_optional_header_buffer = read_n_bytes_from_bin(argv[1], offset, peInfo->SizeOfOptionalHeader);
        PeOptionalHeaderInfo pe_optional_header_info;
        std::memcpy(&pe_optional_header_info, pe_optional_header_buffer.data(), sizeof(pe_optional_header_info));

        cout << "This is a PE file! But there's still much more to do" << endl;
    } else
    {
        cout << "Not a PE file or invalid format" << endl;
    }

    // json j;
    // std::visit([&](auto&& hdr){
    //     using H = std::decay_t<decltype(hdr)>;
    //     if constexpr (std::is_same_v<H, ElfInfo>) j["format"]="ELF", j["entry"]=hdr.entry;
    //     else if constexpr (std::is_same_v<H, PeInfo>) j["format"]="PE",  j["entry"]=hdr.entry;
    //     else j["error"] = "unknown";
    // }, info);

    // std::cout << j.dump(2) << '\n';

    return 0;
}


ByteBuf read_prefix(const std::filesystem::path& p)
{
    // Opening file from path provided by argv[1]
    std::ifstream ReadFile(p, std::ifstream::binary);

    if(!ReadFile)
        throw std::runtime_error("Cannot open " + p.string());

    ByteBuf buffer{};

    // read() still needs a char* because the API predates std::byte. A one-off reitnerpret_cast<char*>(buf.data())
    //      bridges that I/O boundry without needing to setup ByteBuf as char[].
    ReadFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
    std::size_t bytesRead = ReadFile.gcount();

    // Aborting when the file is less than 256 bytes.
    if(bytesRead < 256)
        throw std::runtime_error("Invalid file input... aborting.");

    return buffer;
}

Format detect_format(std::span<const std::byte> buffer)
{
    // Checking the first two bytes (e_magic) to determine if it's a PE file
    if(buffer.size() >= 2 &&
        buffer[0] == std::byte{'M'} &&
        buffer[1] == std::byte{'Z'})
        {
            return Format::Pe;
        }
    // else if(ptr_to_buffer.size() >= 4 &&
    //         ptr_to_buffer[1] == std::byte{'E'} &&
    //         ptr_to_buffer[2] == std::byte{'L'} &&
    //         ptr_to_buffer[3] == std::byte{'F'})
    //         {
    //             return Format::
    //         }
    
    return Format::Unknown;
}

//Not really sure what I want to do with this yet...
// Let's just start by grabbing the file header and populating the struct PeInfo
// PE signature starts at (0x50 0x45 0x00 0x00) : "PE.."
// Updating this to also grab the PE optional header
std::variant<std::monostate, ElfInfo, PeInfo>
parse_header(Format fmt, std::span<const std::byte> buffer, const std::filesystem::path& p)
{
    // I can just write a loop to get to the hex "PE..".
    // Might be a little more efficient to use the address from e_lfanew instead

    if(fmt == Format::Unknown)
        return std::monostate{};

    // e_lfanew is always 0x3C (60 in dec) and is 4 bytes long
    std::span<const std::byte> e_lfanew = buffer.subspan(60, 4);

    std::array<std::byte, 4> tmp;
    std::copy_n(e_lfanew.begin(), 4, tmp.begin());

    // Address to the PE header in uint32_t
    offset = std::bit_cast<std::uint32_t>(tmp);

    PeInfo peinfo;

    // Might have to read more to grab the PE signature.
    // 24 = "PE  " (4 bytes) + PE header (20 bytes)
    if((offset + 24) > buffer.size())
    {
        auto pe_buffer = read_pe_header(p, offset);

        // TODO - Write into PE struct
    }
    else
    {
        // PE signature is part of initial 256 buffer.

        const std::byte* src = buffer.data() + offset + 4; // 4 bytes for "PE"
        std::memcpy(&peinfo, src, sizeof(peinfo));
    }

    return peinfo;
}

// Same logic as read_prefix but includes offset and reads 20 bytes (pe signature)
// Is there a better way to do this?
PeHeaderBuf read_pe_header(const std::filesystem::path& p, uint32_t offset)
{
    std::ifstream ReadFile(p, std::ifstream::binary);

    if(!ReadFile)
        throw std::runtime_error("Cannot open " + p.string());

    PeHeaderBuf pe_buffer{};

    // set position in input sequence to the offset
    ReadFile.seekg(offset, ReadFile.beg);

    ReadFile.read(reinterpret_cast<char*>(pe_buffer.data()), pe_buffer.size());
    std::size_t bytesRead = ReadFile.gcount();

    // Aborting when the file is less than 20 bytes.
    if(bytesRead < 20)
        throw std::runtime_error("Invalid file input... aborting.");

    return pe_buffer;
}


DynamicBuffer read_n_bytes_from_bin(const std::filesystem::path& p, uint32_t offset, uint16_t size)
{
    std::ifstream ReadFile(p, std::ifstream::binary);

    if(!ReadFile)
        throw std::runtime_error("Cannot open " + p.string());

    DynamicBuffer buffer(size);

    // set position in input sequence to the offset
    ReadFile.seekg(offset, ReadFile.beg);

    ReadFile.read(reinterpret_cast<char*>(buffer.data()), size);
    std::size_t bytesRead = ReadFile.gcount();

    // Aborting when the file is less than 20 bytes.
    if(bytesRead < size)
        throw std::runtime_error("Invalid file input... aborting.");

    return buffer;

}