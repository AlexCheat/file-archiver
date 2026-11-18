#pragma once

#include <cstddef>
#include <cstdint>

namespace sarc
{
    // CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320), same as zip/zlib.
    class Crc32
    {
    public:
        void update(const std::uint8_t* data, std::size_t size);
        std::uint32_t value() const { return ~state_; }

    private:
        std::uint32_t state_ = 0xFFFFFFFFu;
    };

    std::uint32_t crc32(const std::uint8_t* data, std::size_t size);
}
