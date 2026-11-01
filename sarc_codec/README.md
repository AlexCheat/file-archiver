# SARC block codec (C++17)

Standalone implementation of the compression block described in `FORMAT_SPEC_P2.md` section 3.

## Implemented

- LZ77 with a 32 KiB maximum history window, match lengths 3–258, bounded hash-chain search, greedy parsing and lazy parsing.
- Separate Huffman alphabets: `LIT` (0–256), `LEN` (0–255), and `DIST` (0–15).
- Canonical Huffman codes, MSB-first bit packing, and zero padding.
- Block serialization: three symbol/length tables, `token_count`, `stream_len`, and bitstream.
- Block decoder with checks for malformed tables, bad LZ77 references, wrong decoded size, non-zero padding, and extra/truncated bytes.
- Automated round-trip, edge-case, option-validation, and malformed-block tests.

## Build and test

```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

For verbose test output:

```bash
./build/sarc_codec_tests
```

## API example

```cpp
#include "sarc_codec.hpp"
#include <cstdint>
#include <vector>

std::vector<std::uint8_t> input = /* file block bytes */;
sarc::CodecOptions options;
options.strategy = sarc::ParseStrategy::Lazy; // or Greedy

sarc::CodecStats stats;
auto encoded = sarc::compress_block(input, options, &stats);
auto decoded = sarc::decompress_block(encoded, input.size());
```

`CodecStats` reports input/output byte counts and token count. The `compress_block` result is the encoded block payload expected by the outer archive code; it is not a complete `.arc` volume.

## Scope / integration

This library handles one raw block at a time. It does **not** implement the outer `SARC` volume header, AES-CTR, PBKDF2, HMAC, CRC32, file table, volume packing, or the optional dynamic-programming parser. Those belong to other project zones or the advanced level. The caller must supply the original block size to `decompress_block`, as the surrounding block table stores `raw_len`.

The local tests verify round-trip behavior and several invalid-input cases. They do not prove cross-team compatibility with the instructor's `ref_*.arc` volumes. When reference artifacts become available, test them through the complete team archiver/dearchiver; this module alone cannot validate the outer volume format or encryption.
