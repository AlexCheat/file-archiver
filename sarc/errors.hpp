#pragma once

#include <stdexcept>
#include <string>

namespace sarc
{
    // Names follow FORMAT_SPEC_P2 section 5, plus three local ones
    // (E_INPUT, E_CONFIG, E_IO) and E_EXISTS for the no-overwrite rule.
    enum class ErrorCode
    {
        Input,    // E_INPUT   - bad input file or argument
        Config,   // E_CONFIG  - volume/block size cannot hold the data
        Io,       // E_IO      - filesystem failure
        Short,    // E_SHORT   - volume shorter than 73 bytes
        Magic,    // E_MAGIC   - wrong magic or version
        Length,   // E_LENGTH  - volume length does not match ciphertext_len
        Hmac,     // E_HMAC    - HMAC mismatch (tampering or wrong password)
        Payload,  // E_PAYLOAD - malformed, truncated or unsafe archive structure
        Code,     // E_CODE    - malformed Huffman / LZ77 stream
        Crc,      // E_CRC     - restored file does not match its CRC32
        Volumes,  // E_VOLUMES - missing, duplicate or foreign volume
        Exists    // E_EXISTS  - extraction would overwrite an existing file
    };

    inline const char* error_name(ErrorCode code)
    {
        switch (code)
        {
        case ErrorCode::Input:   return "E_INPUT";
        case ErrorCode::Config:  return "E_CONFIG";
        case ErrorCode::Io:      return "E_IO";
        case ErrorCode::Short:   return "E_SHORT";
        case ErrorCode::Magic:   return "E_MAGIC";
        case ErrorCode::Length:  return "E_LENGTH";
        case ErrorCode::Hmac:    return "E_HMAC";
        case ErrorCode::Payload: return "E_PAYLOAD";
        case ErrorCode::Code:    return "E_CODE";
        case ErrorCode::Crc:     return "E_CRC";
        case ErrorCode::Volumes: return "E_VOLUMES";
        case ErrorCode::Exists:  return "E_EXISTS";
        }
        return "E_UNKNOWN";
    }

    class Error : public std::runtime_error
    {
    public:
        Error(ErrorCode code, const std::string& message)
            : std::runtime_error(std::string(error_name(code)) + ": " + message),
              code_(code)
        {
        }

        ErrorCode code() const noexcept { return code_; }

    private:
        ErrorCode code_;
    };
}
