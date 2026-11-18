#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

// ---------------------------------------------------------------------------
// Container layout used by this code base.
//
// NOTE: the exact byte layout must match FORMAT_SPEC_P2.md. Everything that
// depends on it lives in this header, in archive_writer.cpp (serialisation)
// and in archive_reader.cpp (parsing). Numbers that the task text states
// explicitly are kept (41-byte transport header, 15-byte block overhead,
// PBKDF2 100000 iterations, 16-byte salt, 12-byte nonce); the field order
// inside them is an assumption and must be checked against the spec.
//
// Volume file:
//   transport header (41 bytes, plaintext)
//       magic[4] "SARC" | version u8 | volume_index u16 | volume_count u16 |
//       salt[16] | nonce[12] | ciphertext_len u32          (all big-endian)
//   ciphertext (ciphertext_len bytes) = AES-256-CTR(K_enc, nonce, payload)
//   HMAC-SHA256 (32 bytes) over transport header || ciphertext, key K_mac
//
// Payload (encrypted):
//   file_count u32 | block_count u32 | block_size u32
//   file table, file_count entries:
//       name_len u16 | name | size u64 | crc32 u32 | type u8 | strategy u8
//   block_count records:
//       file_idx u16 | block_idx u32 | raw_len u32 | coded_len u32 | mode u8
//       followed by coded_len bytes
// ---------------------------------------------------------------------------

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
    constexpr std::size_t PAYLOAD_HEAD_SIZE = 12;
    constexpr std::size_t FILE_ENTRY_FIXED_SIZE = 16;   // plus the name
    constexpr std::size_t BLOCK_HEADER_SIZE = 15;       // "weight = coded_len + 15"

    constexpr std::uint32_t DEFAULT_BLOCK_SIZE = 64 * 1024;
    constexpr std::uint32_t MAX_BLOCK_SIZE = 16 * 1024 * 1024;
    constexpr std::uint32_t MAX_VOLUMES = 0xFFFF;

    enum class BlockMode : std::uint8_t
    {
        Stored = 0,      // NO_COMPRESSION: coded_len == raw_len
        Compressed = 1   // LZ77 + canonical Huffman block (sarc_codec)
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
}
