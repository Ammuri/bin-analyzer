#include <array>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <span>
#include <string_view>
#include <variant>
#include <bit>
#include "json.hpp"

using std::cout;

using json = nlohmann::json;
using ByteBuf = std::array<std::byte, 256>;
using Word_64 = std::array<std::byte, 8>; // 8 bytes in a 64-bit architecture
using Dword_64 = std::array<std::byte, 16>;

ByteBuf read_prefix(const std::filesystem::path& p);
enum class Format { Unknown, Elf32, Elf64, Pe };
Format detect_format(std::span<const std::byte> ptr_to_buffer);

struct ElfInfo { /* minimal fields */ };

struct PeInfo  
{ 
    Word_64 Machine;
    Word_64 NumberOfSections;
    Dword_64 TimeDateStamp;
    Dword_64 PointerToSymbolTable;
    Dword_64 NumberOfSymbols;
    Word_64 SizeOfOptionalHeader;
    Word_64 Characteristics;

};

std::variant<std::monostate, ElfInfo, PeInfo>
parse_header(Format, std::span<const std::byte>);

int main(int argc, char** argv)
{
    if (argc != 2) { std::cerr << "usage: binheaderscout <file>\n..."; return 1; }
    auto buf   = read_prefix(argv[1]);      // read first 256 bytes
    auto fmt   = detect_format(buf);        // look at magic bytes
    auto info  = parse_header(fmt, buf);    // reinterpret into structs

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
        throw std::runtime_error("Cannot open" + p.string());

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
std::variant<std::monostate, ElfInfo, PeInfo>
parse_header(Format fmt, std::span<const std::byte> buffer)
{
    // I can just write a loop to get to the hex "PE..".
    // Might be a little more efficient to use the address from e_lfanew instead

    if(fmt == Format::Unknown)
        return std::monostate{};

    // e_lfanew is always 0x3C (60 in dec) and is 4 bytes long
    std::span<const std::byte> e_lfanew = buffer.subspan(60, 4);

    std::array<std::byte, 4> tmp;
    std::copy_n(e_lfanew.begin(), 4, tmp.begin());

    auto offset = std::bit_cast<std::uint32_t>(tmp);

}