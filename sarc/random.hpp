#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace sarc
{
    // Cryptographically secure random bytes from the operating system.
    void random_bytes(std::uint8_t* out, std::size_t size);
    std::string random_hex(std::size_t byte_count);
}
