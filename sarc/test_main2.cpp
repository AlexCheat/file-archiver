// Self-contained test runner (no external framework). Maps to the task's
// acceptance cases C1 (1-12) and the edge-case / security items C2 / C5.

#include "aes256.hpp"
#include "archive_format.hpp"
#include "archive_reader.hpp"
#include "archive_writer.hpp"
#include "byte_io.hpp"
#include "classifier.hpp"
#include "crc32.hpp"
#include "errors.hpp"
#include "ga.hpp"
#include "keys.hpp"
#include "knapsack.hpp"
#include "random.hpp"
#include "sarc_codec.hpp"
#include "sha256.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <random>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace sarc;
using Bytes = std::vector<std::uint8_t>;

static int g_checks = 0;
static int g_failures = 0;

#define CHECK(cond) do { ++g_checks; if (!(cond)) { ++g_failures; \
    std::cerr << "    CHECK FAILED: " #cond "  (line " << __LINE__ << ")\n"; } } while (0)

template <class F>
static bool throws_code(ErrorCode code, F&& f)
{
    try { f(); }
    catch (const Error& e) { return e.code() == code; }
    catch (...) { return false; }
    return false;
}

template <class F>
static bool throws_sarc_error(F&& f)
{
    try { f(); }
    catch (const Error&) { return true; }
    catch (...) { return false; }
    return false;
}

#define CHECK_THROWS(code, expr) CHECK(throws_code(ErrorCode::code, [&] { expr; }))
#define CHECK_ERROR(expr) CHECK(throws_sarc_error([&] { expr; }))

struct TestCase { const char* name; std::function<void()> fn; };
static std::vector<TestCase>& registry() { static std::vector<TestCase> r; return r; }
struct Registrar { Registrar(const char* n, std::function<void()> f) { registry().push_back({ n, std::move(f) }); } };
#define TEST(name) static void name(); static Registrar reg_##name(#name, name); static void name()

struct TempDir
{
    fs::path path;
    TempDir() : path(fs::temp_directory_path() / ("sarc-test-" + random_hex(6))) { fs::create_directories(path); }
    ~TempDir() { std::error_code ec; fs::remove_all(path, ec); }
    std::string file(const std::string& name) const { return (path / name).string(); }
};

struct Rng
{
    std::uint32_t s;
    explicit Rng(std::uint32_t seed) : s(seed ? seed : 1) {}
    std::uint32_t next() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; }
};

static Bytes make_noise(std::size_t n, std::uint32_t seed)
{
    Rng r(seed); Bytes b(n);
    for (auto& x : b) x = static_cast<std::uint8_t>(r.next() >> 11);
    return b;
}

static Bytes make_text(std::size_t n, std::uint32_t seed)
{
    static const char* words[] = { "the", "archive", "stream", "huffman", "block", "volume", "quick", "brown",
                                   "fox", "compress", "window", "match", "literal", "distance", "length", "tree" };
    Rng r(seed); Bytes b;
    while (b.size() < n)
    {
        const std::string w = words[r.next() % 16];
        b.insert(b.end(), w.begin(), w.end());
        b.push_back((r.next() % 12 == 0) ? '\n' : ' ');
    }
    b.resize(n);
    return b;
}

static Bytes make_csv(std::size_t n, std::uint32_t seed)
{
    Rng r(seed); std::string s = "id,name,value,flag\n";
    for (int i = 0; s.size() < n; ++i)
        s += std::to_string(i) + ",item" + std::to_string(r.next() % 50) + "," + std::to_string(r.next() % 1000) + ",true\n";
    return Bytes(s.begin(), s.begin() + static_cast<std::ptrdiff_t>(n));
}

static Bytes make_raster(std::size_t n, std::uint32_t seed)
{
    Rng r(seed); Bytes b(n);
    for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<std::uint8_t>((i / 7) + (r.next() % 3));
    return b;
}

static Bytes make_exe_like(std::size_t n, std::uint32_t seed)
{
    static const std::uint8_t ops[] = { 0x55, 0x48, 0x89, 0xE5, 0x8B, 0x45, 0xFC, 0x5D, 0xC3, 0x90, 0x00, 0x00 };
    Rng r(seed); Bytes b(n);
    for (auto& x : b) x = (r.next() % 4 == 0) ? static_cast<std::uint8_t>(r.next() >> 9) : ops[r.next() % 12];
    return b;
}

static void write_file(const std::string& path, const Bytes& data)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

static Bytes read_file(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    return Bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

static PackOptions opts(const std::string& password = "correct horse")
{
    PackOptions o;
    o.password = password;
    return o;
}

static std::vector<std::string> list_dir(const fs::path& p)
{
    std::vector<std::string> names;
    if (fs::exists(p)) for (const auto& e : fs::directory_iterator(p)) names.push_back(e.path().filename().string());
    std::sort(names.begin(), names.end());
    return names;
}

// Builds a volume with arbitrary (even malicious) but correctly
// authenticated payload - used for the "structurally invalid authenticated
// payload" and unsafe-name checks.
static std::string craft_volume(const std::string& path, const std::string& password, const Bytes& payload,
                                const std::uint8_t* fixed_salt = nullptr, const std::uint8_t* fixed_nonce = nullptr)
{
    std::uint8_t salt[SALT_SIZE], nonce[NONCE_SIZE];
    if (fixed_salt) std::memcpy(salt, fixed_salt, SALT_SIZE); else random_bytes(salt, sizeof(salt));
    if (fixed_nonce) std::memcpy(nonce, fixed_nonce, NONCE_SIZE); else random_bytes(nonce, sizeof(nonce));
    const Keys keys = derive_keys(password, salt);

    std::uint8_t header[TRANSPORT_HEADER_SIZE];
    std::memcpy(header, MAGIC, 4);
    header[4] = VERSION;
    store_u16(header + 5, 0);
    store_u16(header + 7, 1);
    std::memcpy(header + 9, salt, SALT_SIZE);
    std::memcpy(header + 25, nonce, NONCE_SIZE);
    store_u32(header + 37, static_cast<std::uint32_t>(payload.size()));

    Bytes cipher = payload;
    Aes256Ctr ctr(keys.enc.data(), nonce);
    ctr.crypt(cipher.data(), cipher.size());

    HmacSha256 mac(keys.mac.data(), keys.mac.size());
    mac.update(header, sizeof(header));
    mac.update(cipher.data(), cipher.size());
    const auto tag = mac.finish();

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(header), sizeof(header));
    out.write(reinterpret_cast<const char*>(cipher.data()), static_cast<std::streamsize>(cipher.size()));
    out.write(reinterpret_cast<const char*>(tag.data()), static_cast<std::streamsize>(tag.size()));
    return path;
}

struct PayloadSpec
{
    std::string name = "ok.txt";
    Bytes data = { 'h', 'e', 'l', 'l', 'o' };
    std::uint32_t declared_size = ~0u;        // default: data.size()
    std::uint32_t crc = 0; bool crc_set = false;
    std::uint8_t flags = 0;
    std::uint8_t reserved = 0;
    std::uint8_t file_type = 0;
    std::uint8_t strategy = 1;
    std::uint16_t file_idx = 0;
    std::uint32_t block_idx = 0;
    std::uint32_t raw_len = ~0u;              // default: data.size()
    std::uint32_t coded_len = ~0u;            // default: data.size()
    std::uint8_t block_flags = 1;             // bit 0 = NO_COMPRESSION
    std::uint16_t declared_blocks = 1;        // the block_count field
    std::size_t extra_trailing = 0;
    bool duplicate_block = false;
    bool omit_blocks = false;                 // no block table entries at all
};

// FORMAT_SPEC_P2 section 2: head, file table, block_count, block table, data.
static Bytes build_payload(const PayloadSpec& s)
{
    Bytes p;
    auto u8 = [&](std::uint8_t v) { p.push_back(v); };
    auto u16 = [&](std::uint16_t v) { std::uint8_t b[2]; store_u16(b, v); p.insert(p.end(), b, b + 2); };
    auto u32 = [&](std::uint32_t v) { std::uint8_t b[4]; store_u32(b, v); p.insert(p.end(), b, b + 4); };

    u16(1); u8(s.flags); u8(s.reserved);

    u16(static_cast<std::uint16_t>(s.name.size()));
    p.insert(p.end(), s.name.begin(), s.name.end());
    u32(s.declared_size == ~0u ? static_cast<std::uint32_t>(s.data.size()) : s.declared_size);
    u32(s.crc_set ? s.crc : crc32(s.data.data(), s.data.size()));
    u8(s.file_type); u8(s.strategy);

    const int reps = s.omit_blocks ? 0 : (s.duplicate_block ? 2 : 1);
    u16(s.omit_blocks ? 0 : s.declared_blocks);

    for (int i = 0; i < reps; ++i)
    {
        u16(s.file_idx);
        u32(s.block_idx);
        u32(s.raw_len == ~0u ? static_cast<std::uint32_t>(s.data.size()) : s.raw_len);
        u32(s.coded_len == ~0u ? static_cast<std::uint32_t>(s.data.size()) : s.coded_len);
        u8(s.block_flags);
    }

    for (int i = 0; i < reps; ++i)
        p.insert(p.end(), s.data.begin(), s.data.end());

    p.insert(p.end(), s.extra_trailing, 0xAB);
    return p;
}

static Bytes from_hex(const std::string& text)
{
    Bytes b; int hi = -1;
    for (char c : text)
    {
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else continue;                       // spaces
        if (hi < 0) hi = v; else { b.push_back(static_cast<std::uint8_t>(hi * 16 + v)); hi = -1; }
    }
    return b;
}

static bool restored_equal(const fs::path& dir, const std::string& name, const Bytes& expected)
{
    return read_file((dir / name).string()) == expected;
}

// ------------------------------------------------------------------ tests

TEST(crypto_known_answers)
{
    const char* abc = "abc";
    const auto d = sha256(reinterpret_cast<const std::uint8_t*>(abc), 3);
    CHECK(d[0] == 0xba && d[1] == 0x78 && d[31] == 0xad);

    const std::uint8_t salt[4] = { 's', 'a', 'l', 't' };
    const auto k = pbkdf2_hmac_sha256("password", salt, 4, 2, 32);   // RFC 7914 / known vector
    CHECK(k[0] == 0xae && k[1] == 0x4d && k[31] == 0x43);

    std::uint8_t key[32], pt[16], ct[16];
    for (int i = 0; i < 32; ++i) key[i] = static_cast<std::uint8_t>(i);
    for (int i = 0; i < 16; ++i) pt[i] = static_cast<std::uint8_t>((i << 4) | i);
    Aes256(key).encrypt_block(pt, ct);                               // FIPS-197 C.3
    CHECK(ct[0] == 0x8e && ct[1] == 0xa2 && ct[15] == 0x89);

    CHECK(crc32(reinterpret_cast<const std::uint8_t*>("123456789"), 9) == 0xCBF43926u);

    // Different keys for encryption and MAC.
    std::uint8_t s16[16] = {};
    const Keys keys = derive_keys("pw", s16);
    CHECK(keys.enc != keys.mac);
}

TEST(case07_08_codec_edge_cases)
{
    for (std::size_t n : { std::size_t(0), std::size_t(1), std::size_t(2), std::size_t(3), std::size_t(100), std::size_t(70000) })
    {
        Bytes same(n, 'A');                       // degenerate alphabet (case 8)
        CHECK(decompress_block(compress_block(same), same.size()) == same);
    }

    const Bytes mixed = make_text(50000, 3);
    CHECK(decompress_block(compress_block(mixed), mixed.size()) == mixed);

    const Bytes noise = make_noise(5000, 9);
    CHECK(decompress_block(compress_block(noise), noise.size()) == noise);

    // Garbage and truncated blocks must produce controlled errors.
    Bytes enc = compress_block(mixed);
    for (std::size_t cut : { std::size_t(0), std::size_t(5), enc.size() / 2, enc.size() - 1 })
    {
        Bytes part(enc.begin(), enc.begin() + static_cast<std::ptrdiff_t>(cut));
        CHECK(throws_sarc_error([&] { try { decompress_block(part, mixed.size()); } catch (const std::runtime_error& e) { throw Error(ErrorCode::Code, e.what()); } }));
    }
}

TEST(case09_greedy_and_lazy_both_work)
{
    const Bytes text = make_text(200000, 5);
    CodecOptions g; g.strategy = ParseStrategy::Greedy;
    CodecOptions l; l.strategy = ParseStrategy::Lazy;

    const Bytes eg = compress_block(text, g), el = compress_block(text, l);
    CHECK(decompress_block(eg, text.size()) == text);
    CHECK(decompress_block(el, text.size()) == text);
    std::cout << "    greedy=" << eg.size() << " lazy=" << el.size() << " raw=" << text.size() << "\n";
}

TEST(case01_single_text_file)
{
    TempDir t; const Bytes data = make_text(120000, 1);
    write_file(t.file("book.txt"), data);

    const auto r = create_archive(t.file("a.sarc"), { t.file("book.txt") }, opts());
    CHECK(r.archive_bytes < data.size() / 2);

    extract_archive(r.volume_paths, t.file("out"), "correct horse");
    CHECK(restored_equal(t.path / "out", "book.txt", data));
    CHECK(list_archive(r.volume_paths, "correct horse").size() == 1);
}

TEST(case02_empty_and_one_byte_files)
{
    TempDir t;
    write_file(t.file("empty.bin"), {});
    write_file(t.file("one.bin"), { 0x42 });

    const auto r = create_archive(t.file("a.sarc"), { t.file("empty.bin"), t.file("one.bin") }, opts());
    extract_archive(r.volume_paths, t.file("out"), "correct horse");

    CHECK(fs::file_size(t.path / "out" / "empty.bin") == 0);
    CHECK(restored_equal(t.path / "out", "one.bin", { 0x42 }));
}

TEST(case03_all_seven_groups_roundtrip)
{
    TempDir t;
    const std::vector<std::pair<std::string, Bytes>> corpus = {
        { "text.txt", make_text(150000, 11) },
        { "code.py", make_text(90000, 12) },
        { "table.csv", make_csv(120000, 13) },
        { "image.pgm", make_raster(200000, 14) },
        { "prog.so", make_exe_like(100000, 15) },
        { "photo.jpg", make_noise(80000, 16) },
        { "zeros.bin", Bytes(300000, 0) },
        { "noise.bin", make_noise(70000, 17) },
    };

    std::vector<std::string> inputs;
    for (const auto& [name, data] : corpus) { write_file(t.file(name), data); inputs.push_back(t.file(name)); }

    const auto r = create_archive(t.file("a.sarc"), inputs, opts());
    extract_archive(r.volume_paths, t.file("out"), "correct horse");

    for (const auto& [name, data] : corpus)
        CHECK(restored_equal(t.path / "out", name, data));
}

TEST(case04_same_bytes_compress_many_times)
{
    TempDir t; const Bytes data(1000000, 'x');
    write_file(t.file("same.bin"), data);
    const auto r = create_archive(t.file("a.sarc"), { t.file("same.bin") }, opts());
    CHECK(r.archive_bytes * 20 < data.size());
    std::cout << "    1000000 identical bytes -> " << r.archive_bytes << " bytes\n";
}

TEST(case05_06_noise_and_precompressed_are_stored)
{
    TempDir t; const Bytes noise = make_noise(300000, 21);
    write_file(t.file("noise.bin"), noise);
    write_file(t.file("clip.mp3"), make_noise(100000, 22));

    const auto r = create_archive(t.file("a.sarc"), { t.file("noise.bin"), t.file("clip.mp3") }, opts());

    CHECK(r.blocks_stored == r.blocks_total);          // NO_COMPRESSION everywhere
    CHECK(r.coded_bytes == r.raw_bytes);               // coded_len == raw_len
    CHECK(r.overhead_bytes() < 300);                   // overhead measured separately
    std::cout << "    overhead on incompressible data: " << r.overhead_bytes() << " bytes\n";

    extract_archive(r.volume_paths, t.file("out"), "correct horse");
    CHECK(restored_equal(t.path / "out", "noise.bin", noise));
}

TEST(case10_knapsack_dp_never_worse_than_greedy)
{
    // Classic instance where greedy by ratio fails.
    std::vector<KnapsackItem> classic = { { 10, 60 }, { 20, 100 }, { 30, 120 } };
    CHECK(knapsack_greedy(classic, 50).value == 160);
    CHECK(knapsack_dp(classic, 50).value == 220);

    Rng r(99);
    for (int round = 0; round < 300; ++round)
    {
        const std::size_t n = 1 + r.next() % 13;
        std::vector<KnapsackItem> items(n);
        for (auto& it : items) { it.weight = 1 + r.next() % 60; it.value = 1 + r.next() % 200; }
        const std::uint64_t cap = r.next() % 200;

        // brute force
        std::uint64_t best = 0;
        for (std::uint32_t mask = 0; mask < (1u << n); ++mask)
        {
            std::uint64_t w = 0, v = 0;
            for (std::size_t i = 0; i < n; ++i) if (mask >> i & 1) { w += items[i].weight; v += items[i].value; }
            if (w <= cap) best = std::max(best, v);
        }

        const auto dp = knapsack_dp(items, cap);
        const auto gr = knapsack_greedy(items, cap);
        const auto pk = pack_items(items, cap, PackerKind::Knapsack);

        CHECK(dp.value == best);
        CHECK(dp.value >= gr.value);
        CHECK(pk.value >= gr.value);
        CHECK(dp.weight <= cap);
    }

    // Coarse-unit fallback must still be feasible.
    std::vector<KnapsackItem> big(50);
    for (auto& it : big) { it.weight = 1000 + r.next() % 5000; it.value = 1 + r.next() % 9000; }
    const auto coarse = knapsack_dp(big, 40000, 1000);
    CHECK(coarse.unit > 1);
    CHECK(coarse.weight <= 40000);
}

TEST(case11_tampering_wrong_password_truncation)
{
    TempDir t;
    write_file(t.file("a.txt"), make_text(500, 31));
    write_file(t.file("b.bin"), make_noise(200, 32));
    const auto r = create_archive(t.file("a.sarc"), { t.file("a.txt"), t.file("b.bin") }, opts());
    const std::string path = r.volume_paths[0];
    const Bytes original = read_file(path);

    CHECK_THROWS(Hmac, extract_archive({ path }, t.file("o1"), "wrong password"));
    CHECK_THROWS(Hmac, list_archive({ path }, "wrong password"));

    // Flip one byte in every header byte, plus samples of ciphertext and tag.
    std::vector<std::size_t> positions;
    for (std::size_t i = 0; i < TRANSPORT_HEADER_SIZE; ++i) positions.push_back(i);
    for (std::size_t i = TRANSPORT_HEADER_SIZE; i + MAC_SIZE < original.size(); i += 9) positions.push_back(i);
    for (std::size_t i = original.size() - MAC_SIZE; i < original.size(); i += 5) positions.push_back(i);

    int rejected = 0;
    for (auto pos : positions)
    {
        Bytes bad = original; bad[pos] ^= 0x01;
        write_file(t.file("bad.sarc"), bad);
        const std::string out = t.file("o_" + std::to_string(pos));
        CHECK_ERROR(extract_archive({ t.file("bad.sarc") }, out, "correct horse"));
        CHECK(!fs::exists(out) || list_dir(out).empty());     // nothing partially extracted
        ++rejected;
    }
    std::cout << "    " << rejected << " single-byte modifications, all rejected\n";

    // Truncation and trailing garbage.
    for (std::size_t cut : { std::size_t(0), std::size_t(1), std::size_t(20), std::size_t(41), std::size_t(60),
                             original.size() - MAC_SIZE, original.size() - 1 })
    {
        write_file(t.file("cut.sarc"), Bytes(original.begin(), original.begin() + static_cast<std::ptrdiff_t>(cut)));
        if (cut < TRANSPORT_HEADER_SIZE + MAC_SIZE)
            CHECK_THROWS(Short, extract_archive({ t.file("cut.sarc") }, t.file("oc"), "correct horse"));
        else
            CHECK_THROWS(Length, extract_archive({ t.file("cut.sarc") }, t.file("oc"), "correct horse"));
    }

    Bytes extra = original; extra.push_back(0);
    write_file(t.file("extra.sarc"), extra);
    CHECK_THROWS(Length, extract_archive({ t.file("extra.sarc") }, t.file("oe"), "correct horse"));

    // The untouched archive still opens.
    extract_archive({ path }, t.file("good"), "correct horse");
}

TEST(case12_volumes_order_missing_duplicate_large_file)
{
    TempDir t;
    std::vector<std::pair<std::string, Bytes>> corpus = {
        { "a.txt", make_text(30000, 41) }, { "b.txt", make_text(30000, 42) },
        { "c.csv", make_csv(30000, 43) },  { "big.bin", make_noise(100000, 44) },
        { "d.raw", make_raster(40000, 45) },
    };

    std::vector<std::string> inputs;
    for (const auto& [n, d] : corpus) { write_file(t.file(n), d); inputs.push_back(t.file(n)); }

    for (PackerKind kind : { PackerKind::Knapsack, PackerKind::Greedy })
    {
        PackOptions o = opts(); o.max_volume_bytes = 30000; o.block_size = 8192; o.packer = kind;
        const std::string base = t.file(kind == PackerKind::Knapsack ? "k.sarc" : "g.sarc");
        const auto r = create_archive(base, inputs, o);

        CHECK(r.volume_paths.size() >= 4);                       // file larger than a volume was split
        for (auto sz : r.volume_sizes) CHECK(sz <= o.max_volume_bytes);

        // any order
        auto shuffled = r.volume_paths;
        std::mt19937 gen(7);
        std::shuffle(shuffled.begin(), shuffled.end(), gen);
        const std::string out = t.file(kind == PackerKind::Knapsack ? "outk" : "outg");
        extract_archive(shuffled, out, "correct horse");
        for (const auto& [n, d] : corpus) CHECK(restored_equal(out, n, d));

        // missing volume
        auto missing = r.volume_paths; missing.pop_back();
        CHECK_THROWS(Volumes, extract_archive(missing, t.file("om"), "correct horse"));

        // duplicate volume
        auto dup = r.volume_paths; dup.push_back(dup.front());
        CHECK_THROWS(Volumes, extract_archive(dup, t.file("od"), "correct horse"));
        auto dup2 = r.volume_paths; dup2.back() = dup2.front();
        CHECK_THROWS(Volumes, extract_archive(dup2, t.file("od2"), "correct horse"));

        std::cout << "    " << (kind == PackerKind::Knapsack ? "knapsack" : "greedy  ")
                  << ": " << r.volume_paths.size() << " volumes, " << r.archive_bytes << " bytes\n";
    }

    // Volumes of two different archives must not mix.
    PackOptions o = opts(); o.max_volume_bytes = 30000; o.block_size = 8192;
    const auto r1 = create_archive(t.file("x.sarc"), inputs, o);
    const auto r2 = create_archive(t.file("y.sarc"), inputs, o);
    auto mixed = r1.volume_paths; mixed.back() = r2.volume_paths.back();
    CHECK_THROWS(Volumes, extract_archive(mixed, t.file("omix"), "correct horse"));
}

TEST(many_small_files_use_candidate_window)
{
    TempDir t; std::vector<std::string> inputs; std::vector<Bytes> data;
    for (int i = 0; i < 60; ++i)
    {
        data.push_back(make_text(80 + i, 100 + i));
        write_file(t.file("f" + std::to_string(i) + ".txt"), data.back());
        inputs.push_back(t.file("f" + std::to_string(i) + ".txt"));
    }

    PackOptions o = opts(); o.max_volume_bytes = 1500; o.candidate_window = 7;
    const auto r = create_archive(t.file("a.sarc"), inputs, o);
    CHECK(r.volume_paths.size() > 3);
    for (auto sz : r.volume_sizes) CHECK(sz <= 1500);

    extract_archive(r.volume_paths, t.file("out"), "correct horse");
    for (int i = 0; i < 60; ++i) CHECK(restored_equal(t.path / "out", "f" + std::to_string(i) + ".txt", data[i]));
}

TEST(volume_config_errors_are_controlled)
{
    TempDir t; write_file(t.file("n.bin"), make_noise(50000, 51));

    PackOptions tiny = opts(); tiny.max_volume_bytes = 50;               // smaller than the header
    CHECK_THROWS(Config, create_archive(t.file("a.sarc"), { t.file("n.bin") }, tiny));

    PackOptions small = opts(); small.max_volume_bytes = 400; small.block_size = 65536;   // block cannot fit
    CHECK_THROWS(Config, create_archive(t.file("b.sarc"), { t.file("n.bin") }, small));

    PackOptions bad_block = opts(); bad_block.block_size = 0;
    CHECK_THROWS(Config, create_archive(t.file("c.sarc"), { t.file("n.bin") }, bad_block));

    CHECK(!fs::exists(t.path / "a.sarc") && !fs::exists(t.path / "b.sarc"));      // nothing left behind
    CHECK(list_dir(t.path) == std::vector<std::string>{ "n.bin" });
}

TEST(input_validation_c2)
{
    TempDir t; write_file(t.file("ok.txt"), { 'x' });

    CHECK_THROWS(Input, create_archive(t.file("a.sarc"), { t.file("missing.txt") }, opts()));
    CHECK_THROWS(Input, create_archive(t.file("a.sarc"), { t.path.string() }, opts()));      // directory
    CHECK_THROWS(Input, create_archive(t.file("a.sarc"), { t.file("ok.txt"), t.file("ok.txt") }, opts()));
    CHECK_THROWS(Input, create_archive(t.file("ok.txt"), { t.file("ok.txt") }, opts()));     // would overwrite input
    CHECK_THROWS(Input, create_archive(t.file("a.sarc"), { t.file("ok.txt") }, opts("")));   // empty password

    write_file(t.file("bad:name.txt"), { 'x' });
    CHECK_THROWS(Input, create_archive(t.file("a.sarc"), { t.file("bad:name.txt") }, opts()));

    const std::string long_path = t.file(std::string(300, 'n'));      // very long name
    write_file(long_path, { 'x' });
    CHECK(throws_sarc_error([&] { create_archive(t.file("a.sarc"), { long_path }, opts()); }));
}

TEST(zero_files_archive)
{
    TempDir t;
    const auto r = create_archive(t.file("empty.sarc"), {}, opts());
    CHECK(r.volume_paths.size() == 1);
    CHECK(list_archive(r.volume_paths, "correct horse").empty());
    extract_archive(r.volume_paths, t.file("out"), "correct horse");
    CHECK(list_dir(t.path / "out").empty());
}

TEST(c5_authenticated_but_malicious_payloads)
{
    // Sanity: the crafting helper produces a valid archive.
    {
        TempDir t;
        craft_volume(t.file("ok.sarc"), "pw", build_payload(PayloadSpec{}));
        extract_archive({ t.file("ok.sarc") }, t.file("out"), "pw");
        CHECK(restored_equal(t.path / "out", "ok.txt", { 'h', 'e', 'l', 'l', 'o' }));
    }

    // Unsafe names: path traversal, separators, drive letters, dots, NUL.
    const std::vector<std::string> bad_names = { "../evil.txt", "..", ".", "a/b.txt", "a\\b.txt",
                                                 "c:evil.txt", "/abs.txt", std::string("nul\0x", 5) };
    for (const auto& name : bad_names)
    {
        TempDir t; fs::create_directories(t.path / "sub");
        PayloadSpec s; s.name = name;
        craft_volume(t.file("m.sarc"), "pw", build_payload(s));

        CHECK_THROWS(Payload, extract_archive({ t.file("m.sarc") }, (t.path / "sub").string(), "pw"));
        CHECK(!fs::exists(t.path / "evil.txt"));
        CHECK(list_dir(t.path / "sub").empty());
    }

    struct Case { const char* label; PayloadSpec spec; ErrorCode expected; };
    std::vector<Case> cases;
    { PayloadSpec s; s.block_idx = 5;                         cases.push_back({ "block_seq does not start at 0", s, ErrorCode::Payload }); }
    { PayloadSpec s; s.file_idx = 3;                          cases.push_back({ "unknown file index", s, ErrorCode::Payload }); }
    { PayloadSpec s; s.raw_len = 4; s.coded_len = 4;          cases.push_back({ "raw_len sum differs from orig_size", s, ErrorCode::Payload }); }
    { PayloadSpec s; s.coded_len = 3;                         cases.push_back({ "stored coded_len != raw_len", s, ErrorCode::Payload }); }
    { PayloadSpec s; s.block_flags = 7;                       cases.push_back({ "block_flags reserved bits", s, ErrorCode::Payload }); }
    { PayloadSpec s; s.block_flags = 2;                       cases.push_back({ "block_flags bit 1 set", s, ErrorCode::Payload }); }
    { PayloadSpec s; s.declared_blocks = 2;                   cases.push_back({ "block_count larger than data", s, ErrorCode::Payload }); }
    { PayloadSpec s; s.declared_blocks = 0;                   cases.push_back({ "block table shorter than declared", s, ErrorCode::Payload }); }
    { PayloadSpec s; s.extra_trailing = 9;                    cases.push_back({ "trailing bytes", s, ErrorCode::Payload }); }
    { PayloadSpec s; s.duplicate_block = true; s.declared_blocks = 2; cases.push_back({ "duplicate block", s, ErrorCode::Payload }); }
    { PayloadSpec s; s.reserved = 1;                          cases.push_back({ "reserved != 0", s, ErrorCode::Payload }); }
    { PayloadSpec s; s.flags = 2;                             cases.push_back({ "unknown payload flag", s, ErrorCode::Payload }); }
    { PayloadSpec s; s.flags = 1;                             cases.push_back({ "PREDICTION extension", s, ErrorCode::Payload }); }
    { PayloadSpec s; s.file_type = 7;                         cases.push_back({ "file_type > 6", s, ErrorCode::Payload }); }
    { PayloadSpec s; s.coded_len = 1u << 30;                  cases.push_back({ "coded_len beyond volume", s, ErrorCode::Payload }); }
    { PayloadSpec s; s.declared_size = 0xFFFFFFFEu;           cases.push_back({ "huge declared size", s, ErrorCode::Payload }); }
    { PayloadSpec s; s.block_flags = 0; s.coded_len = 5;      cases.push_back({ "garbage Huffman block", s, ErrorCode::Code }); }
    { PayloadSpec s; s.crc_set = true; s.crc = 0xDEADBEEF;    cases.push_back({ "wrong CRC32", s, ErrorCode::Crc }); }

    for (const auto& c : cases)
    {
        TempDir t;
        craft_volume(t.file("m.sarc"), "pw", build_payload(c.spec));
        const bool ok = throws_code(c.expected, [&] { extract_archive({ t.file("m.sarc") }, t.file("out"), "pw"); });

        if (!ok) std::cerr << "    case failed: " << c.label << "\n";
        CHECK(ok);
        const bool clean = list_dir(t.path / "out").empty();   // no partial output, staging removed
        if (!clean) std::cerr << "    left behind after failure: " << c.label << "\n";
        CHECK(clean);
    }
}

TEST(atomic_extraction_never_overwrites)
{
    TempDir t;
    write_file(t.file("a.txt"), make_text(2000, 61));
    write_file(t.file("b.txt"), make_text(2000, 62));
    const auto r = create_archive(t.file("a.sarc"), { t.file("a.txt"), t.file("b.txt") }, opts());

    fs::create_directories(t.path / "out");
    const Bytes precious = { 'k', 'e', 'e', 'p' };
    write_file(t.file("out/b.txt"), precious);

    CHECK_THROWS(Exists, extract_archive(r.volume_paths, t.file("out"), "correct horse"));
    CHECK(restored_equal(t.path / "out", "b.txt", precious));              // untouched
    CHECK(list_dir(t.path / "out") == std::vector<std::string>{ "b.txt" }); // no a.txt, no staging dir
}

TEST(classifier_and_features)
{
    const Bytes noise = make_noise(65536, 71), text = make_text(65536, 72), zeros(65536, 0);

    CHECK(shannon_entropy(noise.data(), noise.size()) > 7.9);
    CHECK(shannon_entropy(zeros.data(), zeros.size()) < 0.001);
    CHECK(extract_features(text.data(), text.size()).size() == FEATURE_COUNT);

    EntropyClassifier c;
    CHECK(c.classify(noise.data(), noise.size()).strategy == Strategy::Store);
    CHECK(c.classify(text.data(), text.size()).strategy == Strategy::Compress);
    CHECK(c.classify(zeros.data(), zeros.size()).strategy == Strategy::Compress);
    CHECK(c.classify(nullptr, 0).strategy == Strategy::Store);
    for (const Bytes* b : { &noise, &text, &zeros })
        CHECK(static_cast<int>(c.classify(b->data(), b->size()).type) <= MAX_FILE_TYPE);
}

TEST(spec_section8_reference_example)
{
    // FORMAT_SPEC_P2 section 8, rebuilt byte by byte (ref_01_single_file.arc).
    TempDir t;
    const std::string block_hex =
        "0009 002003 006404 006504 006804 006C02 006F03 007204 007703 010003"   // LIT
        "0002 00CF01 00FF01"                                                    // LEN
        "0001 000401"                                                           // DIST
        "0000000E 00000007 ED06A3F3159D18";                                     // tokens, stream
    const Bytes block = from_hex(block_hex);
    CHECK(block.size() == 57);

    const Bytes payload = from_hex(
        "0001 00 00  0009 68656C6C6F2E747874  000001E0 70208846 00 01  0001"
        "  0000 00000000 000001E0 00000039 00 " + block_hex);
    CHECK(payload.size() == 99);

    const Bytes salt = from_hex("000102030405060708090A0B0C0D0E0F");
    const Bytes nonce = from_hex("010203040506070800000000");
    craft_volume(t.file("ref_01.arc"), "algo2026", payload, salt.data(), nonce.data());

    const Bytes arc = read_file(t.file("ref_01.arc"));
    CHECK(arc.size() == 172);
    CHECK(Bytes(arc.begin(), arc.begin() + 41) ==
          from_hex("53415243 01 0000 0001 000102030405060708090A0B0C0D0E0F 010203040506070800000000 00000063"));

    const auto entries = list_archive({ t.file("ref_01.arc") }, "algo2026");
    CHECK(entries.size() == 1);
    CHECK(entries[0].name == "hello.txt" && entries[0].size == 480 && entries[0].crc32 == 0x70208846u);

    extract_archive({ t.file("ref_01.arc") }, t.file("out"), "algo2026");
    Bytes expected; for (int i = 0; i < 40; ++i) for (char ch : std::string("hello world ")) expected.push_back(static_cast<std::uint8_t>(ch));
    CHECK(restored_equal(t.path / "out", "hello.txt", expected));

    // Our encoder reproduces the 57-byte block of the example exactly.
    CHECK(compress_block(expected) == block);
}

TEST(spec_error_codes)
{
    TempDir t;
    write_file(t.file("a.txt"), make_text(3000, 81));
    const auto r = create_archive(t.file("a.sarc"), { t.file("a.txt") }, opts());
    const Bytes good = read_file(r.volume_paths[0]);

    auto expect = [&](const char* label, ErrorCode code, Bytes bad)
    {
        write_file(t.file("bad.sarc"), bad);
        const bool ok = throws_code(code, [&] { list_archive({ t.file("bad.sarc") }, "correct horse"); });
        if (!ok) std::cerr << "    wrong error code: " << label << "\n";
        CHECK(ok);
    };

    { Bytes b = good; b[0] ^= 1;                    expect("magic", ErrorCode::Magic, b); }
    { Bytes b = good; b[4] = 2;                     expect("version", ErrorCode::Magic, b); }
    { Bytes b = good; b.resize(72);                 expect("shorter than 73", ErrorCode::Short, b); }
    { Bytes b = good; b.pop_back();                 expect("truncated", ErrorCode::Length, b); }
    { Bytes b = good; b.push_back(0);               expect("extra byte", ErrorCode::Length, b); }
    { Bytes b = good; b[41] ^= 1;                   expect("ciphertext byte", ErrorCode::Hmac, b); }
    { Bytes b = good; b.back() ^= 1;                expect("tag byte", ErrorCode::Hmac, b); }
    { Bytes b = good; b[10] ^= 1;                   expect("salt byte", ErrorCode::Hmac, b); }
    { Bytes b = good; store_u16(b.data() + 5, 5);   expect("volume_index >= volume_count", ErrorCode::Volumes, b); }

    CHECK_THROWS(Hmac, list_archive({ r.volume_paths[0] }, "wrong"));
}

TEST(foreign_layout_empty_file_variants)
{
    // The spec does not say how an empty file is stored: accept both
    // "no blocks" and "one empty NO_COMPRESSION block".
    {
        TempDir t; PayloadSpec s; s.name = "empty.bin"; s.data = {}; s.omit_blocks = true;
        craft_volume(t.file("z.sarc"), "pw", build_payload(s));
        extract_archive({ t.file("z.sarc") }, t.file("out"), "pw");
        CHECK(fs::file_size(t.path / "out" / "empty.bin") == 0);
    }
    {
        TempDir t; PayloadSpec s; s.name = "empty.bin"; s.data = {};
        craft_volume(t.file("z.sarc"), "pw", build_payload(s));
        extract_archive({ t.file("z.sarc") }, t.file("out"), "pw");
        CHECK(fs::file_size(t.path / "out" / "empty.bin") == 0);
    }
}

TEST(file_larger_than_4gib_is_rejected)
{
    TempDir t;
    { std::ofstream f(t.file("big.bin"), std::ios::binary); f << 'x'; }
    std::error_code ec;
    fs::resize_file(t.path / "big.bin", 0x100000001ull, ec);     // sparse file
    if (ec) { std::cout << "    skipped: cannot create a sparse file here\n"; return; }
    CHECK_THROWS(Input, create_archive(t.file("a.sarc"), { t.file("big.bin") }, opts()));
}

// Smooth synthetic landscape in (0, 1] with its optimum inside the gene ranges.
static double synthetic_fitness(const Genome& g)
{
    const double a = std::log2(static_cast<double>(g.window)) - 12.0;
    const double b = static_cast<double>(g.min_match) - 4.0;
    const double c = g.store_threshold - 7.2;
    return std::exp(-(a * a / 8.0 + b * b / 8.0 + c * c / 0.5));
}

TEST(ga_elitism_bounds_and_determinism)
{
    GaConfig cfg; cfg.population = 10; cfg.generations = 15; cfg.elites = 2;

    double ga_sum = 0, rnd_sum = 0;

    for (std::uint64_t seed = 1; seed <= 6; ++seed)
    {
        cfg.seed = seed;
        const GaResult r = run_ga(cfg, synthetic_fitness);

        CHECK(r.history.size() == cfg.generations + 1);
        CHECK(r.history.back().best >= r.history.front().best);       // the task's correctness check
        for (std::size_t i = 1; i < r.history.size(); ++i)
            CHECK(r.history[i].best >= r.history[i - 1].best);        // monotone because of elitism
        CHECK(r.evaluations <= cfg.population + cfg.generations * (cfg.population - cfg.elites));
        CHECK(r.history.back().evaluations == r.evaluations);

        const Genome& b = r.best;
        CHECK(b.window >= GENE_WINDOW_MIN && b.window <= GENE_WINDOW_MAX);
        CHECK(b.min_match >= GENE_MIN_MATCH_MIN && b.min_match <= GENE_MIN_MATCH_MAX);
        CHECK(b.store_threshold >= GENE_THRESHOLD_MIN && b.store_threshold <= GENE_THRESHOLD_MAX);
        CHECK(r.best_fitness == synthetic_fitness(r.best));

        const RandomSearchResult rs = run_random_search(cfg, synthetic_fitness, r.evaluations);
        CHECK(rs.best_so_far.size() == r.evaluations);
        for (std::size_t i = 1; i < rs.best_so_far.size(); ++i)
            CHECK(rs.best_so_far[i] >= rs.best_so_far[i - 1]);

        ga_sum += r.best_fitness; rnd_sum += rs.best_fitness;
    }

    std::cout << "    synthetic landscape, mean best of 6 seeds: GA " << ga_sum / 6
              << ", random search " << rnd_sum / 6 << " (same number of evaluations)\n";

    // Same seed, same run.
    cfg.seed = 42;
    const GaResult x = run_ga(cfg, synthetic_fitness), y = run_ga(cfg, synthetic_fitness);
    CHECK(x.best == y.best && x.evaluations == y.evaluations && x.history.size() == y.history.size());

    // Invalid configurations are rejected.
    GaConfig bad = cfg; bad.elites = bad.population;
    CHECK(throws_sarc_error([&] { try { run_ga(bad, synthetic_fitness); } catch (const std::invalid_argument& e) { throw Error(ErrorCode::Config, e.what()); } }));
}

TEST(ga_on_real_archive)
{
    TempDir t;
    write_file(t.file("a.txt"), make_text(40000, 91));
    write_file(t.file("b.csv"), make_csv(30000, 92));
    write_file(t.file("n.bin"), make_noise(20000, 93));

    ArchiveEvaluator evaluator({ t.file("a.txt"), t.file("b.csv"), t.file("n.bin") }, opts(), MetricParams{});

    const Evaluation e = evaluator.measure(Genome{});
    CHECK(e.exact && e.q > 0.0 && e.q <= 1.0 && e.s > 0.0 && e.t > 0.0);

    // A genome that cannot compress text at all (huge min match) must lose on S.
    Genome weak; weak.min_match = 12; weak.window = 256;
    const Evaluation w = evaluator.measure(weak);
    CHECK(w.exact && w.archive_bytes >= e.archive_bytes);

    GaConfig cfg; cfg.population = 4; cfg.generations = 2; cfg.elites = 1; cfg.seed = 7;
    const FitnessFn fitness = [&](const Genome& g) { return evaluator.measure(g).q; };
    const GaResult r = run_ga(cfg, fitness);
    CHECK(r.history.back().best >= r.history.front().best);
    CHECK(r.best_fitness > 0.0);
}

int main(int argc, char** argv)
{
    const std::string filter = argc > 1 ? argv[1] : "";
    int failed_tests = 0;

    for (const auto& t : registry())
    {
        if (!filter.empty() && std::string(t.name).find(filter) == std::string::npos)
            continue;

        const int before = g_failures;
        const auto start = std::chrono::steady_clock::now();
        std::cout << "[ RUN  ] " << t.name << "\n";

        try { t.fn(); }
        catch (const std::exception& e) { ++g_failures; std::cerr << "    UNEXPECTED EXCEPTION: " << e.what() << "\n"; }

        const double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        const bool ok = g_failures == before;
        if (!ok) ++failed_tests;
        std::cout << (ok ? "[  OK  ] " : "[ FAIL ] ") << t.name << "  (" << sec << " s)\n";
    }

    std::cout << "\n" << g_checks << " checks, " << g_failures << " failed, " << failed_tests << " test(s) failed\n";
    return g_failures == 0 ? 0 : 1;
}
