#include "crc32.hpp"

#include <array>

namespace sarc
{
    namespace
    {
        const std::array<std::uint32_t, 256>& table()
        {
            static const std::array<std::uint32_t, 256> t = []
            {
                std::array<std::uint32_t, 256> a{};

                for (std::uint32_t i = 0; i < 256; ++i)
                {
                    std::uint32_t c = i;

                    for (int k = 0; k < 8; ++k)
                        c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);

                    a[i] = c;
                }

                return a;
            }();

            return t;
        }
    }

    void Crc32::update(const std::uint8_t* data, std::size_t size)
    {
        const auto& t = table();
        std::uint32_t s = state_;

        for (std::size_t i = 0; i < size; ++i)
            s = t[(s ^ data[i]) & 0xFFu] ^ (s >> 8);

        state_ = s;
    }

    std::uint32_t crc32(const std::uint8_t* data, std::size_t size)
    {
        Crc32 c;
        c.update(data, size);
        return c.value();
    }
}
