#include "random.hpp"

#include <random>

namespace sarc
{
    void random_bytes(std::uint8_t* out, std::size_t size)
    {
        static thread_local std::random_device device;

        std::size_t i = 0;

        while (i < size)
        {
            const std::uint32_t v = device();

            for (int k = 0; k < 4 && i < size; ++k, ++i)
                out[i] = static_cast<std::uint8_t>(v >> (8 * k));
        }
    }

    std::string random_hex(std::size_t byte_count)
    {
        static const char digits[] = "0123456789abcdef";

        std::string result;

        for (std::size_t i = 0; i < byte_count; ++i)
        {
            std::uint8_t b = 0;
            random_bytes(&b, 1);
            result.push_back(digits[b >> 4]);
            result.push_back(digits[b & 15]);
        }

        return result;
    }
}
