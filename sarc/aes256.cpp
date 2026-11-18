#include "aes256.hpp"
#include "byte_io.hpp"
#include "sha256.hpp"

#include <cstring>
#include <stdexcept>

namespace sarc
{
    namespace
    {
        struct SBox
        {
            std::uint8_t table[256];

            SBox()
            {
                // Generates the AES S-box from GF(2^8) arithmetic.
                std::uint8_t p = 1, q = 1;

                do
                {
                    p = static_cast<std::uint8_t>(p ^ (p << 1) ^ ((p & 0x80) ? 0x1B : 0));

                    q = static_cast<std::uint8_t>(q ^ (q << 1));
                    q = static_cast<std::uint8_t>(q ^ (q << 2));
                    q = static_cast<std::uint8_t>(q ^ (q << 4));
                    if (q & 0x80)
                        q ^= 0x09;

                    auto rotl = [](std::uint8_t x, int s) -> std::uint8_t
                    {
                        return static_cast<std::uint8_t>((x << s) | (x >> (8 - s)));
                    };

                    table[p] = static_cast<std::uint8_t>(
                        q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4) ^ 0x63);
                }
                while (p != 1);

                table[0] = 0x63;
            }
        };

        const SBox& sbox()
        {
            static const SBox s;
            return s;
        }

        inline std::uint8_t xtime(std::uint8_t x)
        {
            return static_cast<std::uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
        }
    }

    Aes256::Aes256(const std::uint8_t key[32])
    {
        const auto& sb = sbox().table;

        std::memcpy(round_keys_, key, 32);

        std::uint8_t rcon = 1;

        for (std::size_t i = 32; i < sizeof(round_keys_); i += 4)
        {
            std::uint8_t t[4];
            std::memcpy(t, round_keys_ + i - 4, 4);

            if (i % 32 == 0)
            {
                const std::uint8_t t0 = t[0];
                t[0] = static_cast<std::uint8_t>(sb[t[1]] ^ rcon);
                t[1] = sb[t[2]];
                t[2] = sb[t[3]];
                t[3] = sb[t0];
                rcon = xtime(rcon);
            }
            else if (i % 32 == 16)
            {
                for (int j = 0; j < 4; ++j)
                    t[j] = sb[t[j]];
            }

            for (int j = 0; j < 4; ++j)
                round_keys_[i + j] = static_cast<std::uint8_t>(round_keys_[i - 32 + j] ^ t[j]);
        }
    }

    Aes256::~Aes256()
    {
        secure_zero(round_keys_, sizeof(round_keys_));
    }

    void Aes256::encrypt_block(const std::uint8_t in[16], std::uint8_t out[16]) const
    {
        const auto& sb = sbox().table;
        std::uint8_t s[16];

        for (int i = 0; i < 16; ++i)
            s[i] = static_cast<std::uint8_t>(in[i] ^ round_keys_[i]);

        for (int round = 1; round <= 14; ++round)
        {
            std::uint8_t t[16];

            // SubBytes + ShiftRows (state is column-major: s[4 * col + row]).
            for (int c = 0; c < 4; ++c)
                for (int r = 0; r < 4; ++r)
                    t[4 * c + r] = sb[s[4 * ((c + r) % 4) + r]];

            if (round < 14)
            {
                for (int c = 0; c < 4; ++c)
                {
                    const std::uint8_t a0 = t[4 * c], a1 = t[4 * c + 1];
                    const std::uint8_t a2 = t[4 * c + 2], a3 = t[4 * c + 3];
                    const std::uint8_t all = static_cast<std::uint8_t>(a0 ^ a1 ^ a2 ^ a3);

                    s[4 * c]     = static_cast<std::uint8_t>(a0 ^ all ^ xtime(static_cast<std::uint8_t>(a0 ^ a1)));
                    s[4 * c + 1] = static_cast<std::uint8_t>(a1 ^ all ^ xtime(static_cast<std::uint8_t>(a1 ^ a2)));
                    s[4 * c + 2] = static_cast<std::uint8_t>(a2 ^ all ^ xtime(static_cast<std::uint8_t>(a2 ^ a3)));
                    s[4 * c + 3] = static_cast<std::uint8_t>(a3 ^ all ^ xtime(static_cast<std::uint8_t>(a3 ^ a0)));
                }
            }
            else
            {
                std::memcpy(s, t, 16);
            }

            for (int i = 0; i < 16; ++i)
                s[i] = static_cast<std::uint8_t>(s[i] ^ round_keys_[16 * round + i]);
        }

        std::memcpy(out, s, 16);
    }

    Aes256Ctr::Aes256Ctr(const std::uint8_t key[32], const std::uint8_t nonce[12])
        : aes_(key)
    {
        std::memcpy(nonce_, nonce, 12);
        std::memset(keystream_, 0, sizeof(keystream_));
    }

    void Aes256Ctr::load_keystream(std::uint64_t block)
    {
        // Counter is a 32-bit big-endian value starting at 1.
        if (block + 1 > 0xFFFFFFFFull)
            throw std::length_error("AES-CTR counter overflow");

        std::uint8_t counter_block[16];
        std::memcpy(counter_block, nonce_, 12);
        store_u32(counter_block + 12, static_cast<std::uint32_t>(block + 1));

        aes_.encrypt_block(counter_block, keystream_);
        cached_block_ = block;
    }

    void Aes256Ctr::crypt(std::uint8_t* data, std::size_t size)
    {
        for (std::size_t i = 0; i < size; ++i)
        {
            const std::uint64_t block = position_ / 16;

            if (block != cached_block_)
                load_keystream(block);

            data[i] ^= keystream_[position_ % 16];
            ++position_;
        }
    }

    void Aes256Ctr::skip(std::uint64_t size)
    {
        position_ += size;
    }
}
