#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace sarc {

enum class ParseStrategy { Greedy, Lazy };

struct CodecOptions {
    ParseStrategy strategy = ParseStrategy::Lazy;
    std::size_t window_size = 32768;
    std::size_t min_match = 3;
    std::size_t max_match = 258;
    std::size_t max_chain = 256; // search bound; increase for better compression
};

struct CodecStats {
    std::size_t input_bytes = 0;
    std::size_t output_bytes = 0;
    std::size_t token_count = 0;
};

// Returns the complete encoded block from FORMAT_SPEC_P2 section 3.
std::vector<std::uint8_t> compress_block(const std::vector<std::uint8_t>& input,
                                         const CodecOptions& options = {},
                                         CodecStats* stats = nullptr);

// Decodes one complete encoded block. Throws std::runtime_error on malformed input.
std::vector<std::uint8_t> decompress_block(const std::vector<std::uint8_t>& encoded,
                                           std::size_t expected_raw_size,
                                           CodecStats* stats = nullptr);

} // namespace sarc
