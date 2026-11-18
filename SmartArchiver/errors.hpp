#pragma once

#include <stdexcept>
#include <string>

namespace sarc
{
    enum class ErrorCode
    {
        Input,    // E_INPUT   - bad input file or argument
        Config,   // E_CONFIG  - volume/block size cannot hold the data
        Io,       // E_IO      - filesystem failure
        Payload,  // E_PAYLOAD - malformed, truncated or unsafe archive structure
        Code,     // E_CODE    - malformed Huffman / LZ77 stream
        Auth,     // E_AUTH    - HMAC mismatch (tampering or wrong password)
        Crc,      // E_CRC     - restored file does not match its CRC32
        Volume,   // E_VOLUME  - missing, duplicate or foreign volume
        Exists    // E_EXISTS  - extraction would overwrite an existing file
    };

    inline const char* error_name(ErrorCode code)
    {
        switch (code)
        {
        case ErrorCode::Input:   return "E_INPUT";
        case ErrorCode::Config:  return "E_CONFIG";
        case ErrorCode::Io:      return "E_IO";
        case ErrorCode::Payload: return "E_PAYLOAD";
        case ErrorCode::Code:    return "E_CODE";
        case ErrorCode::Auth:    return "E_AUTH";
        case ErrorCode::Crc:     return "E_CRC";
        case ErrorCode::Volume:  return "E_VOLUME";
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
