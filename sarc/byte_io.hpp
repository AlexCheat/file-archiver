#pragma once

#include <cstdint>

// Big-endian helpers (same convention as the codec).
namespace sarc
{
    inline void store_u16(std::uint8_t* p, std::uint16_t v)
    {
        p[0] = static_cast<std::uint8_t>(v >> 8);
        p[1] = static_cast<std::uint8_t>(v);
    }

    inline void store_u32(std::uint8_t* p, std::uint32_t v)
    {
        for (int i = 0; i < 4; ++i)
            p[i] = static_cast<std::uint8_t>(v >> (24 - 8 * i));
    }

    inline void store_u64(std::uint8_t* p, std::uint64_t v)
    {
        for (int i = 0; i < 8; ++i)
            p[i] = static_cast<std::uint8_t>(v >> (56 - 8 * i));
    }

    inline std::uint16_t load_u16(const std::uint8_t* p)
    {
        return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
    }

    inline std::uint32_t load_u32(const std::uint8_t* p)
    {
        return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) |
               (std::uint32_t(p[2]) << 8) | std::uint32_t(p[3]);
    }

    inline std::uint64_t load_u64(const std::uint8_t* p)
    {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
            v = (v << 8) | p[i];
        return v;
    }
}
