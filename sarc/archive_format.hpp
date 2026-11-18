#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>

namespace sarc
{
    constexpr char MAGIC[4] = { 'S', 'A', 'R', 'C' };
    constexpr std::uint8_t VERSION = 1;

    constexpr std::uint32_t MAX_FILES = 100000;
    constexpr std::uint32_t MAX_FILENAME_SIZE = 4096;
    constexpr std::uint64_t BUFFER_SIZE = 64 * 1024;

    constexpr std::size_t SALT_SIZE = 16;
    constexpr std::size_t NONCE_SIZE = 12;
    constexpr std::size_t KEY_SIZE = 32;
    constexpr std::size_t MAC_SIZE = 32;
    constexpr std::uint32_t PBKDF2_ITERATIONS = 100000;

    constexpr std::size_t TRANSPORT_HEADER_SIZE = 41;
    constexpr std::size_t PAYLOAD_HEAD_SIZE = 6;        // file_count, flags, reserved, block_count
    constexpr std::size_t FILE_ENTRY_FIXED_SIZE = 12;
    constexpr std::size_t BLOCK_HEADER_SIZE = 15;       // "weight = coded_len + 15"

    constexpr std::uint8_t FLAG_PREDICTION = 0x01;
    constexpr std::uint8_t MAX_FILE_TYPE = 6;
    constexpr std::uint64_t MAX_FILE_BYTES = 0xFFFFFFFFull;
    constexpr std::uint32_t MAX_ITEMS_PER_VOLUME = 0xFFFF;    // file_count / block_count are u16

    constexpr std::uint32_t DEFAULT_BLOCK_SIZE = 64 * 1024;
    constexpr std::uint32_t MAX_BLOCK_SIZE = 16 * 1024 * 1024;
    constexpr std::uint32_t MAX_VOLUMES = 0xFFFF;

    // The value is the block_flags byte itself.
    enum class BlockMode : std::uint8_t
    {
        Compressed = 0,  // LZ77 + canonical Huffman block (sarc_codec)
        Stored = 1       // NO_COMPRESSION: coded_len == raw_len
    };

    // Only a bare file name is allowed. Forbidden: / \ : NUL, "." and "..".
    inline bool is_safe_filename(const std::string& name)
    {
        if (name.empty() || name.size() > MAX_FILENAME_SIZE)
            return false;

        if (name == "." || name == "..")
            return false;

        for (unsigned char c : name)
        {
            if (c == '/' || c == '\\' || c == ':' || c == 0)
                return false;
        }

        return true;
    }

    // Names inside the archive are UTF-8 on every platform.
    inline std::string to_utf8(const std::filesystem::path& p)
    {
#if defined(__cpp_char8_t)
        const auto s = p.u8string();
        return std::string(s.begin(), s.end());
#else
        return p.u8string();
#endif
    }

    inline std::filesystem::path from_utf8(const std::string& s)
    {
#if defined(__cpp_char8_t)
        return std::filesystem::path(std::u8string(s.begin(), s.end()));
#else
        return std::filesystem::u8path(s);
#endif
    }
}
