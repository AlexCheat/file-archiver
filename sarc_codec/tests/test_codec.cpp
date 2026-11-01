#include "sarc_codec.hpp"

#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Bytes = std::vector<std::uint8_t>;

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

void require_throws(const std::function<void()>& fn, const std::string& message) {
    try {
        fn();
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error("Expected an exception: " + message);
}

void round_trip(const Bytes& input, sarc::ParseStrategy strategy, const std::string& label) {
    sarc::CodecOptions options;
    options.strategy = strategy;

    sarc::CodecStats enc_stats;
    const Bytes encoded = sarc::compress_block(input, options, &enc_stats);
    sarc::CodecStats dec_stats;
    const Bytes decoded = sarc::decompress_block(encoded, input.size(), &dec_stats);

    require(decoded == input, label + ": round-trip mismatch");
    require(enc_stats.input_bytes == input.size(), label + ": wrong encoder input count");
    require(enc_stats.output_bytes == encoded.size(), label + ": wrong encoder output count");
    require(dec_stats.input_bytes == encoded.size(), label + ": wrong decoder input count");
    require(dec_stats.output_bytes == input.size(), label + ": wrong decoder output count");

    std::cout << "PASS " << label << ": raw=" << input.size()
              << " encoded=" << encoded.size()
              << " tokens=" << enc_stats.token_count << '\n';
}

void test_round_trips() {
    round_trip({}, sarc::ParseStrategy::Greedy, "empty/greedy");
    round_trip({}, sarc::ParseStrategy::Lazy, "empty/lazy");
    round_trip(Bytes{0x00}, sarc::ParseStrategy::Greedy, "single-zero");
    round_trip(Bytes(5000, static_cast<std::uint8_t>('A')), sarc::ParseStrategy::Greedy, "one-symbol");
    round_trip(Bytes(5000, static_cast<std::uint8_t>('A')), sarc::ParseStrategy::Lazy, "one-symbol/lazy");

    std::string hello;
    for (int i = 0; i < 40; ++i) hello += "hello world ";
    round_trip(Bytes(hello.begin(), hello.end()), sarc::ParseStrategy::Greedy, "hello/greedy");
    round_trip(Bytes(hello.begin(), hello.end()), sarc::ParseStrategy::Lazy, "hello/lazy");

    // Every possible byte value, then the same values in reverse order.
    Bytes all_bytes;
    for (unsigned i = 0; i < 256; ++i) all_bytes.push_back(static_cast<std::uint8_t>(i));
    for (int i = 255; i >= 0; --i) all_bytes.push_back(static_cast<std::uint8_t>(i));
    round_trip(all_bytes, sarc::ParseStrategy::Greedy, "all-byte-values");

    // Exercises overlapping matches with distances 1, 2 and 3, and long matches.
    for (const std::string pattern : {"aaaaaaaaaaaaaaaa", "abababababababab", "abcabcabcabcabc"}) {
        Bytes v(pattern.begin(), pattern.end());
        v.insert(v.end(), 1000, static_cast<std::uint8_t>(pattern[0]));
        round_trip(v, sarc::ParseStrategy::Greedy, "overlap/greedy");
        round_trip(v, sarc::ParseStrategy::Lazy, "overlap/lazy");
    }

    std::mt19937 rng(2026);
    for (int n : {1, 2, 3, 15, 256, 4096, 20000, 32767, 32768, 32769}) {
        Bytes v(static_cast<std::size_t>(n));
        for (auto& b : v) b = static_cast<std::uint8_t>(rng() & 255U);
        round_trip(v, sarc::ParseStrategy::Greedy, "random/greedy/" + std::to_string(n));
        round_trip(v, sarc::ParseStrategy::Lazy, "random/lazy/" + std::to_string(n));
    }

    // Low-alphabet data makes the Huffman tables and match finder work harder.
    for (unsigned alphabet : {2U, 3U, 7U, 16U, 64U, 256U}) {
        Bytes v(12000);
        for (auto& b : v) b = static_cast<std::uint8_t>(rng() % alphabet);
        round_trip(v, sarc::ParseStrategy::Lazy, "random-alphabet/" + std::to_string(alphabet));
    }
}

void test_invalid_options() {
    const Bytes input{'a', 'b', 'c', 'a', 'b', 'c'};
    sarc::CodecOptions options;
    options.window_size = 32769;
    require_throws([&] { (void)sarc::compress_block(input, options); }, "window larger than format limit");

    options = {};
    options.min_match = 2;
    require_throws([&] { (void)sarc::compress_block(input, options); }, "min_match below format limit");

    options = {};
    options.max_match = 259;
    require_throws([&] { (void)sarc::compress_block(input, options); }, "max_match above format limit");
}

void test_malformed_blocks() {
    // A one-byte input creates a one-bit stream with seven padding bits.
    const Bytes input{'x'};
    const Bytes valid = sarc::compress_block(input);
    require(sarc::decompress_block(valid, input.size()) == input, "control block should decode");

    Bytes truncated = valid;
    truncated.pop_back();
    require_throws([&] { (void)sarc::decompress_block(truncated, input.size()); }, "truncated block");

    Bytes trailing = valid;
    trailing.push_back(0);
    require_throws([&] { (void)sarc::decompress_block(trailing, input.size()); }, "trailing byte");

    Bytes bad_padding = valid;
    bad_padding.back() |= 0x01;
    require_throws([&] { (void)sarc::decompress_block(bad_padding, input.size()); }, "nonzero padding");

    require_throws([&] { (void)sarc::decompress_block(valid, input.size() + 1); }, "wrong expected raw size");
}
} // namespace

int main() {
    try {
        test_round_trips();
        test_invalid_options();
        test_malformed_blocks();
        std::cout << "All codec tests passed.\n";
    } catch (const std::exception& e) {
        std::cerr << "TEST FAILED: " << e.what() << '\n';
        return 1;
    }
    return 0;
}
