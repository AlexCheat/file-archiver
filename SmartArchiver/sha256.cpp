#include "sha256.hpp"
#include "byte_io.hpp"

#include <algorithm>
#include <cstring>

namespace sarc
{
    namespace
    {
        const std::uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        inline std::uint32_t rotr(std::uint32_t x, unsigned n)
        {
            return (x >> n) | (x << (32 - n));
        }
    }

    Sha256::Sha256()
    {
        static const std::uint32_t iv[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        std::memcpy(h_, iv, sizeof(h_));
        std::memset(buffer_, 0, sizeof(buffer_));
    }

    void Sha256::compress(const std::uint8_t* block)
    {
        std::uint32_t w[64];

        for (int i = 0; i < 16; ++i)
            w[i] = load_u32(block + 4 * i);

        for (int i = 16; i < 64; ++i)
        {
            const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
        std::uint32_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];

        for (int i = 0; i < 64; ++i)
        {
            const std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const std::uint32_t ch = (e & f) ^ (~e & g);
            const std::uint32_t t1 = h + S1 + ch + K[i] + w[i];
            const std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t t2 = S0 + maj;

            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
        h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
    }

    void Sha256::update(const std::uint8_t* data, std::size_t size)
    {
        total_ += size;

        while (size > 0)
        {
            const std::size_t take = std::min(size, BLOCK_SIZE - buffer_len_);
            std::memcpy(buffer_ + buffer_len_, data, take);
            buffer_len_ += take;
            data += take;
            size -= take;

            if (buffer_len_ == BLOCK_SIZE)
            {
                compress(buffer_);
                buffer_len_ = 0;
            }
        }
    }

    std::array<std::uint8_t, Sha256::DIGEST_SIZE> Sha256::finish()
    {
        const std::uint64_t bit_length = total_ * 8;

        std::uint8_t pad[BLOCK_SIZE * 2] = { 0x80 };
        const std::size_t pad_len =
            (buffer_len_ < 56) ? (56 - buffer_len_) : (120 - buffer_len_);

        std::uint8_t length_bytes[8];
        store_u64(length_bytes, bit_length);

        update(pad, pad_len);
        update(length_bytes, 8);

        std::array<std::uint8_t, DIGEST_SIZE> out{};

        for (int i = 0; i < 8; ++i)
            store_u32(out.data() + 4 * i, h_[i]);

        return out;
    }

    HmacSha256::HmacSha256(const std::uint8_t* key, std::size_t key_size)
    {
        std::uint8_t k[Sha256::BLOCK_SIZE] = {};

        if (key_size > Sha256::BLOCK_SIZE)
        {
            const auto digest = sha256(key, key_size);
            std::memcpy(k, digest.data(), digest.size());
        }
        else if (key_size > 0)
        {
            std::memcpy(k, key, key_size);
        }

        std::uint8_t ipad[Sha256::BLOCK_SIZE];
        std::uint8_t opad[Sha256::BLOCK_SIZE];

        for (std::size_t i = 0; i < Sha256::BLOCK_SIZE; ++i)
        {
            ipad[i] = static_cast<std::uint8_t>(k[i] ^ 0x36);
            opad[i] = static_cast<std::uint8_t>(k[i] ^ 0x5c);
        }

        inner_.update(ipad, sizeof(ipad));
        outer_.update(opad, sizeof(opad));

        secure_zero(k, sizeof(k));
        secure_zero(ipad, sizeof(ipad));
        secure_zero(opad, sizeof(opad));
    }

    std::array<std::uint8_t, Sha256::DIGEST_SIZE> HmacSha256::finish()
    {
        const auto inner_digest = inner_.finish();
        outer_.update(inner_digest.data(), inner_digest.size());
        return outer_.finish();
    }

    std::array<std::uint8_t, Sha256::DIGEST_SIZE>
    sha256(const std::uint8_t* data, std::size_t size)
    {
        Sha256 s;
        s.update(data, size);
        return s.finish();
    }

    std::vector<std::uint8_t> pbkdf2_hmac_sha256(
        const std::string& password,
        const std::uint8_t* salt, std::size_t salt_size,
        std::uint32_t iterations, std::size_t output_size)
    {
        const HmacSha256 base(
            reinterpret_cast<const std::uint8_t*>(password.data()), password.size());

        std::vector<std::uint8_t> output;
        output.reserve(output_size);

        for (std::uint32_t block = 1; output.size() < output_size; ++block)
        {
            HmacSha256 first = base;
            first.update(salt, salt_size);

            std::uint8_t counter[4];
            store_u32(counter, block);
            first.update(counter, 4);

            auto u = first.finish();
            auto t = u;

            for (std::uint32_t i = 1; i < iterations; ++i)
            {
                HmacSha256 h = base;
                h.update(u.data(), u.size());
                u = h.finish();

                for (std::size_t k = 0; k < t.size(); ++k)
                    t[k] ^= u[k];
            }

            const std::size_t take = std::min<std::size_t>(t.size(), output_size - output.size());
            output.insert(output.end(), t.begin(), t.begin() + static_cast<std::ptrdiff_t>(take));
        }

        return output;
    }

    bool ct_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t size)
    {
        std::uint8_t diff = 0;

        for (std::size_t i = 0; i < size; ++i)
            diff |= static_cast<std::uint8_t>(a[i] ^ b[i]);

        return diff == 0;
    }

    void secure_zero(void* data, std::size_t size)
    {
        volatile std::uint8_t* p = static_cast<volatile std::uint8_t*>(data);

        for (std::size_t i = 0; i < size; ++i)
            p[i] = 0;
    }
}
