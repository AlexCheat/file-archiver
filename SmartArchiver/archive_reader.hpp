#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sarc
{
    struct ListEntry
    {
        std::string name;
        std::uint64_t size = 0;
        std::uint32_t crc32 = 0;
        std::uint8_t type = 0;       // FileType
        std::uint8_t strategy = 0;   // Strategy
    };

    // The file table is encrypted, so listing needs the password too.
    // volume_paths: every volume of ONE archive, in any order.
    std::vector<ListEntry> list_archive(
        const std::vector<std::string>& volume_paths,
        const std::string& password);

    // Atomic: everything is restored into a staging folder, verified
    // (HMAC, structure, CRC32) and only then moved into output_folder.
    // Existing files are never overwritten.
    void extract_archive(
        const std::vector<std::string>& volume_paths,
        const std::string& output_folder,
        const std::string& password);
}
