#pragma once

#include <cstddef>
#include <cstdint>

namespace sarc
{
    // AES-256 block encryption (FIPS-197). Only encryption is needed for CTR.
    class Aes256
    {
    public:
        explicit Aes256(const std::uint8_t key[32]);
        ~Aes256();

        void encrypt_block(const std::uint8_t in[16], std::uint8_t out[16]) const;

    private:
        std::uint8_t round_keys_[240];
    };

    // AES-256-CTR. Counter block = nonce(12) || uint32_BE(i), i starts at 1.
    // crypt() both encrypts and decrypts; skip() moves forward without output.
    class Aes256Ctr
    {
    public:
        Aes256Ctr(const std::uint8_t key[32], const std::uint8_t nonce[12]);

        void crypt(std::uint8_t* data, std::size_t size);
        void skip(std::uint64_t size);

    private:
        void load_keystream(std::uint64_t block);

        Aes256 aes_;
        std::uint8_t nonce_[12];
        std::uint64_t position_ = 0;
        std::uint64_t cached_block_ = ~0ull;
        std::uint8_t keystream_[16];
    };
}
