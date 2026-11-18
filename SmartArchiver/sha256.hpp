#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace sarc
{
    class Sha256
    {
    public:
        static constexpr std::size_t DIGEST_SIZE = 32;
        static constexpr std::size_t BLOCK_SIZE = 64;

        Sha256();
        void update(const std::uint8_t* data, std::size_t size);
        std::array<std::uint8_t, DIGEST_SIZE> finish();

    private:
        void compress(const std::uint8_t* block);

        std::uint32_t h_[8];
        std::uint8_t buffer_[BLOCK_SIZE];
        std::size_t buffer_len_ = 0;
        std::uint64_t total_ = 0;
    };

    class HmacSha256
    {
    public:
        HmacSha256(const std::uint8_t* key, std::size_t key_size);
        void update(const std::uint8_t* data, std::size_t size) { inner_.update(data, size); }
        std::array<std::uint8_t, Sha256::DIGEST_SIZE> finish();

    private:
        Sha256 inner_;
        Sha256 outer_;
    };

    std::array<std::uint8_t, Sha256::DIGEST_SIZE>
    sha256(const std::uint8_t* data, std::size_t size);

    // PBKDF2-HMAC-SHA256 (RFC 8018).
    std::vector<std::uint8_t> pbkdf2_hmac_sha256(
        const std::string& password,
        const std::uint8_t* salt, std::size_t salt_size,
        std::uint32_t iterations, std::size_t output_size);

    // Constant-time comparison.
    bool ct_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t size);

    void secure_zero(void* data, std::size_t size);
}
