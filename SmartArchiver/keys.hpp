#pragma once

#include "archive_format.hpp"
#include "sha256.hpp"

#include <array>
#include <cstring>
#include <string>

namespace sarc
{
    // PBKDF2-HMAC-SHA256 -> 64 bytes: first 32 = K_enc, last 32 = K_mac.
    // Two different keys are mandatory; using one key for both is an error.
    struct Keys
    {
        std::array<std::uint8_t, KEY_SIZE> enc{};
        std::array<std::uint8_t, KEY_SIZE> mac{};

        Keys() = default;
        Keys(const Keys&) = default;
        Keys& operator=(const Keys&) = default;

        ~Keys()
        {
            secure_zero(enc.data(), enc.size());
            secure_zero(mac.data(), mac.size());
        }
    };

    inline Keys derive_keys(const std::string& password, const std::uint8_t* salt)
    {
        auto okm = pbkdf2_hmac_sha256(
            password, salt, SALT_SIZE, PBKDF2_ITERATIONS, 2 * KEY_SIZE);

        Keys keys;
        std::memcpy(keys.enc.data(), okm.data(), KEY_SIZE);
        std::memcpy(keys.mac.data(), okm.data() + KEY_SIZE, KEY_SIZE);

        secure_zero(okm.data(), okm.size());
        return keys;
    }
}
