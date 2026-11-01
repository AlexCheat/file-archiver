#include "sarc_codec.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <queue>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace sarc {
namespace {
constexpr unsigned MAX_BITS = 15;
constexpr unsigned LIT_MARKER = 256;
struct Token { bool match = false; std::uint16_t literal = 0; std::uint16_t length = 0; std::uint16_t distance = 0; };

struct BitWriter {
    std::vector<std::uint8_t> bytes;
    std::uint8_t current = 0; unsigned used = 0;
    void put_bit(unsigned bit) { current = static_cast<std::uint8_t>((current << 1) | (bit & 1U)); if (++used == 8) { bytes.push_back(current); current = 0; used = 0; } }
    void put_bits(std::uint32_t value, unsigned count) { for (unsigned i = count; i > 0; --i) put_bit((value >> (i - 1)) & 1U); }
    void finish() { if (used) { current = static_cast<std::uint8_t>(current << (8 - used)); bytes.push_back(current); current = 0; used = 0; } }
};
struct BitReader {
    const std::vector<std::uint8_t>& bytes; std::size_t pos = 0;
    explicit BitReader(const std::vector<std::uint8_t>& b) : bytes(b) {}
    unsigned get_bit() { if (pos >= bytes.size() * 8) throw std::runtime_error("E_CODE: unexpected end of bitstream"); unsigned b = (bytes[pos / 8] >> (7 - (pos % 8))) & 1U; ++pos; return b; }
    std::uint32_t get_bits(unsigned count) { std::uint32_t v = 0; for (unsigned i = 0; i < count; ++i) v = (v << 1) | get_bit(); return v; }
    void validate_zero_padding() const { for (std::size_t p = pos; p < bytes.size() * 8; ++p) if ((bytes[p / 8] >> (7 - (p % 8))) & 1U) throw std::runtime_error("E_CODE: nonzero padding"); }
};
struct ByteWriter {
    std::vector<std::uint8_t> b;
    void u8(std::uint8_t x) { b.push_back(x); }
    void u16(std::uint16_t x) { b.push_back(static_cast<std::uint8_t>(x >> 8)); b.push_back(static_cast<std::uint8_t>(x)); }
    void u32(std::uint32_t x) { b.push_back(static_cast<std::uint8_t>(x >> 24)); b.push_back(static_cast<std::uint8_t>(x >> 16)); b.push_back(static_cast<std::uint8_t>(x >> 8)); b.push_back(static_cast<std::uint8_t>(x)); }
};
struct ByteReader {
    const std::vector<std::uint8_t>& b; std::size_t p = 0;
    explicit ByteReader(const std::vector<std::uint8_t>& v) : b(v) {}
    void need(std::size_t n) { if (n > b.size() - std::min(p, b.size())) throw std::runtime_error("E_PAYLOAD: truncated block"); }
    std::uint8_t u8() { need(1); return b[p++]; }
    std::uint16_t u16() { need(2); auto x = static_cast<std::uint16_t>((b[p] << 8) | b[p + 1]); p += 2; return x; }
    std::uint32_t u32() { need(4); std::uint32_t x = (std::uint32_t(b[p]) << 24) | (std::uint32_t(b[p+1]) << 16) | (std::uint32_t(b[p+2]) << 8) | b[p+3]; p += 4; return x; }
};

unsigned bit_length(std::uint32_t x) { unsigned n = 0; while (x) { ++n; x >>= 1; } return n; }

// Bounded hash-chain LZ77 matcher. Distances are in [1, 32768], lengths [3, 258].
std::vector<Token> tokenize(const std::vector<std::uint8_t>& in, const CodecOptions& opt) {
    if (opt.window_size == 0 || opt.window_size > 32768 || opt.min_match < 3 || opt.max_match > 258 || opt.min_match > opt.max_match)
        throw std::invalid_argument("Invalid LZ77 options");
    const std::size_t n = in.size();
    std::vector<std::ptrdiff_t> head(1u << 16, -1), prev(n, -1);
    auto hash3 = [&](std::size_t p) -> unsigned { return ((unsigned(in[p]) * 251u + unsigned(in[p+1])) * 251u + unsigned(in[p+2])) & 0xffffu; };
    auto insert = [&](std::size_t p) { if (p + 2 >= n) return; unsigned h = hash3(p); prev[p] = head[h]; head[h] = static_cast<int>(p); };
    auto find = [&](std::size_t p) -> std::pair<std::size_t,std::size_t> {
        if (p + 2 >= n) return {0,0};
        std::ptrdiff_t candidate = head[hash3(p)]; std::size_t best_len = 0, best_dist = 0, searched = 0;
        const std::size_t max_len = std::min(opt.max_match, n - p);
        while (candidate >= 0 && searched++ < opt.max_chain) {
            std::size_t c = static_cast<std::size_t>(candidate);
            std::size_t dist = p - c;
            if (dist > opt.window_size) break; // chain is newest-first
            if (dist && in[c] == in[p] && in[c+1] == in[p+1] && in[c+2] == in[p+2]) {
                std::size_t len = 3;
                while (len < max_len && in[c + (len % dist)] == in[p + len]) ++len;
                if (len > best_len) { best_len = len; best_dist = dist; if (len == max_len) break; }
            }
            candidate = prev[c];
        }
        return best_len >= opt.min_match ? std::make_pair(best_len,best_dist) : std::make_pair(std::size_t(0),std::size_t(0));
    };
    std::vector<Token> out; std::size_t p = 0;
    while (p < n) {
        auto [len, dist] = find(p);
        bool inserted_current = false;
        if (opt.strategy == ParseStrategy::Lazy && len >= opt.min_match && p + 1 < n) {
            insert(p); inserted_current = true;
            auto [next_len, next_dist] = find(p + 1);
            if (next_len > len + 1) { out.push_back(Token{false, in[p], 0, 0}); ++p; continue; }
            // p has already been inserted, and find() may see it only at next position (distance 1).
            (void)next_dist;
        } else {
            // Insert current position below; find() must happen before insertion.
        }
        if (len >= opt.min_match) {
            out.push_back(Token{true, 0, static_cast<std::uint16_t>(len), static_cast<std::uint16_t>(dist)});
            for (std::size_t j = inserted_current ? 1 : 0; j < len; ++j) insert(p + j);
            p += len;
        } else {
            out.push_back(Token{false, in[p], 0, 0}); insert(p); ++p;
        }
    }
    return out;
}

struct Huffman {
    std::vector<std::uint8_t> lengths;
    std::vector<std::uint32_t> codes;
    std::vector<int> decode_symbol;
    std::vector<std::vector<std::pair<std::uint32_t,unsigned>>> by_length;
};
struct HNode { std::uint64_t freq; int left; int right; int symbol; std::uint64_t order; };
Huffman make_huffman(const std::vector<std::uint64_t>& freq) {
    Huffman h; h.lengths.assign(freq.size(), 0); h.codes.assign(freq.size(), 0);
    std::vector<HNode> nodes; nodes.reserve(freq.size() * 2);
    using QItem = std::tuple<std::uint64_t,std::uint64_t,int>;
    std::priority_queue<QItem,std::vector<QItem>,std::greater<QItem>> q;
    std::uint64_t order = 0;
    for (std::size_t s = 0; s < freq.size(); ++s) if (freq[s]) { int id = static_cast<int>(nodes.size()); nodes.push_back({freq[s],-1,-1,static_cast<int>(s),order}); q.emplace(freq[s],order++,id); }
    if (q.empty()) { h.by_length.resize(MAX_BITS + 1); return h; }
    if (q.size() == 1) { h.lengths[nodes[std::get<2>(q.top())].symbol] = 1; }
    else {
        while (q.size() > 1) { auto [fa,oa,a] = q.top(); q.pop(); auto [fb,ob,b] = q.top(); q.pop(); int id = static_cast<int>(nodes.size()); nodes.push_back({fa+fb,a,b,-1,order}); q.emplace(fa+fb,order++,id); }
        std::vector<std::pair<int,unsigned>> st{{std::get<2>(q.top()),0}};
        while (!st.empty()) { auto [id,d] = st.back(); st.pop_back(); const auto& nd = nodes[id]; if (nd.symbol >= 0) h.lengths[nd.symbol] = static_cast<std::uint8_t>(std::max(1u,d)); else { st.emplace_back(nd.left,d+1); st.emplace_back(nd.right,d+1); } }
        unsigned max_len = 0; for (auto l : h.lengths) max_len = std::max(max_len,unsigned(l));
        if (max_len > MAX_BITS) {
            std::array<int, MAX_BITS + 1> count{}; int overflow = 0;
            for (auto& l : h.lengths) if (l) { if (l > MAX_BITS) { l = MAX_BITS; ++overflow; } ++count[l]; }
            while (overflow > 0) {
                int bits = MAX_BITS - 1; while (bits > 0 && count[bits] == 0) --bits;
                if (bits == 0 || count[MAX_BITS] == 0) throw std::runtime_error("Unable to limit Huffman code lengths");
                --count[bits]; count[bits+1] += 2; --count[MAX_BITS]; overflow -= 2;
            }
            std::vector<std::size_t> symbols;
            for (std::size_t s = 0; s < freq.size(); ++s) if (freq[s]) symbols.push_back(s);
            std::sort(symbols.begin(), symbols.end(), [&](std::size_t a, std::size_t b) { if (freq[a] != freq[b]) return freq[a] < freq[b]; return a > b; });
            std::size_t k = 0;
            for (int bits = MAX_BITS; bits >= 1; --bits) for (int j = 0; j < count[bits]; ++j) { if (k >= symbols.size()) throw std::runtime_error("Invalid length-limited Huffman tree"); h.lengths[symbols[k++]] = static_cast<std::uint8_t>(bits); }
            if (k != symbols.size()) throw std::runtime_error("Invalid length-limited Huffman tree");
        }
    }
    std::array<std::uint32_t, MAX_BITS + 1> count{}, next{};
    for (auto l : h.lengths) if (l) { if (l > MAX_BITS) throw std::runtime_error("Huffman code too long"); ++count[l]; }
    std::uint32_t code = 0;
    for (unsigned bits = 1; bits <= MAX_BITS; ++bits) { code = (code + count[bits-1]) << 1; next[bits] = code; }
    for (std::size_t s = 0; s < h.lengths.size(); ++s) if (h.lengths[s]) h.codes[s] = next[h.lengths[s]]++;
    h.by_length.resize(MAX_BITS + 1);
    for (std::size_t s = 0; s < h.lengths.size(); ++s) if (h.lengths[s]) h.by_length[h.lengths[s]].emplace_back(h.codes[s], static_cast<unsigned>(s));
    for (auto& v : h.by_length) std::sort(v.begin(), v.end());
    return h;
}

void write_tree(ByteWriter& out, const Huffman& h) {
    std::uint16_t n = 0; for (auto l : h.lengths) if (l) ++n; out.u16(n);
    for (std::size_t s = 0; s < h.lengths.size(); ++s) if (h.lengths[s]) { out.u16(static_cast<std::uint16_t>(s)); out.u8(h.lengths[s]); }
}
Huffman read_tree(ByteReader& in, std::size_t alphabet_size) {
    std::uint16_t n = in.u16(); if (n > alphabet_size) throw std::runtime_error("E_CODE: too many Huffman symbols");
    Huffman h; h.lengths.assign(alphabet_size,0); h.codes.assign(alphabet_size,0); std::uint16_t previous = 0; bool first = true;
    for (unsigned i = 0; i < n; ++i) { auto s = in.u16(); auto l = in.u8(); if (s >= alphabet_size || l == 0 || l > MAX_BITS || (!first && s <= previous)) throw std::runtime_error("E_CODE: invalid Huffman table"); first = false; previous = s; h.lengths[s] = l; }
    if (n == 1 && h.lengths[std::distance(h.lengths.begin(), std::find_if(h.lengths.begin(), h.lengths.end(), [](auto l){return l != 0;}))] != 1) throw std::runtime_error("E_CODE: one-symbol tree must have length 1");
    std::array<unsigned, MAX_BITS+1> count{}; for (auto l : h.lengths) if (l) ++count[l];
    if (n > 1) { int left = 1; for (unsigned bits=1; bits<=MAX_BITS; ++bits) { left = left*2 - static_cast<int>(count[bits]); if (left < 0) throw std::runtime_error("E_CODE: oversubscribed Huffman tree"); } if (left != 0) throw std::runtime_error("E_CODE: incomplete Huffman tree"); }
    std::array<std::uint32_t, MAX_BITS+1> next{}; std::uint32_t code = 0;
    for (unsigned bits=1; bits<=MAX_BITS; ++bits) { code = (code + count[bits-1]) << 1; next[bits] = code; }
    for (std::size_t s=0;s<alphabet_size;++s) if (h.lengths[s]) h.codes[s]=next[h.lengths[s]]++;
    h.by_length.resize(MAX_BITS+1); for (std::size_t s=0;s<alphabet_size;++s) if (h.lengths[s]) h.by_length[h.lengths[s]].emplace_back(h.codes[s],static_cast<unsigned>(s));
    for (auto& v : h.by_length) std::sort(v.begin(),v.end());
    return h;
}
void write_symbol(BitWriter& bw, const Huffman& h, unsigned sym) { if (sym >= h.lengths.size() || !h.lengths[sym]) throw std::runtime_error("Missing Huffman symbol"); bw.put_bits(h.codes[sym], h.lengths[sym]); }
unsigned read_symbol(BitReader& br, const Huffman& h) {
    std::uint32_t code = 0;
    for (unsigned len=1;len<=MAX_BITS;++len) { code=(code<<1)|br.get_bit(); for (const auto& p : h.by_length[len]) if (p.first==code) return p.second; }
    throw std::runtime_error("E_CODE: invalid Huffman code");
}
} // namespace

std::vector<std::uint8_t> compress_block(const std::vector<std::uint8_t>& input, const CodecOptions& options, CodecStats* stats) {
    auto tokens = tokenize(input, options);
    std::vector<std::uint64_t> f_lit(257), f_len(256), f_dist(16);
    for (const auto& t : tokens) {
        if (!t.match) ++f_lit[t.literal];
        else { ++f_lit[LIT_MARKER]; ++f_len[t.length - 3]; unsigned d = t.distance - 1; ++f_dist[bit_length(d)]; }
    }
    auto lit = make_huffman(f_lit), len = make_huffman(f_len), dist = make_huffman(f_dist);
    BitWriter bw;
    for (const auto& t : tokens) {
        if (!t.match) write_symbol(bw, lit, t.literal);
        else {
            write_symbol(bw, lit, LIT_MARKER); write_symbol(bw, len, t.length - 3);
            unsigned d = t.distance - 1, c = bit_length(d), extra = c ? c - 1 : 0;
            write_symbol(bw, dist, c); if (extra) bw.put_bits(d & ((1u << extra)-1u), extra);
        }
    }
    bw.finish();
    if (tokens.size() > std::numeric_limits<std::uint32_t>::max() || bw.bytes.size() > std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("Block too large");
    ByteWriter out; write_tree(out,lit); write_tree(out,len); write_tree(out,dist); out.u32(static_cast<std::uint32_t>(tokens.size())); out.u32(static_cast<std::uint32_t>(bw.bytes.size())); out.b.insert(out.b.end(),bw.bytes.begin(),bw.bytes.end());
    if (stats) { stats->input_bytes=input.size(); stats->output_bytes=out.b.size(); stats->token_count=tokens.size(); }
    return out.b;
}

std::vector<std::uint8_t> decompress_block(const std::vector<std::uint8_t>& encoded, std::size_t expected_raw_size, CodecStats* stats) {
    ByteReader br(encoded); auto lit=read_tree(br,257); auto len=read_tree(br,256); auto dist=read_tree(br,16);
    auto token_count=br.u32(); auto stream_len=br.u32(); br.need(stream_len); if (br.p + stream_len != encoded.size()) throw std::runtime_error("E_PAYLOAD: trailing or missing bytes");
    std::vector<std::uint8_t> stream(encoded.begin()+static_cast<std::ptrdiff_t>(br.p),encoded.end()); BitReader bits(stream); std::vector<std::uint8_t> out; out.reserve(expected_raw_size);
    for (std::uint32_t i=0;i<token_count;++i) {
        unsigned s=read_symbol(bits,lit);
        if (s < 256) { out.push_back(static_cast<std::uint8_t>(s)); }
        else if (s == LIT_MARKER) {
            unsigned ls=read_symbol(bits,len); std::size_t match_len=ls+3;
            unsigned dc=read_symbol(bits,dist); if (dc>15) throw std::runtime_error("E_CODE: invalid distance code");
            unsigned extra=dc ? dc-1 : 0; std::uint32_t low=extra ? bits.get_bits(extra) : 0;
            std::uint32_t dminus = dc==0 ? 0 : ((1u << (dc-1)) | low); std::size_t distance=std::size_t(dminus)+1;
            if (distance > out.size() || distance > 32768 || match_len > expected_raw_size - std::min(expected_raw_size,out.size())) throw std::runtime_error("E_CODE: invalid LZ77 reference");
            for (std::size_t j=0;j<match_len;++j) out.push_back(out[out.size()-distance]);
        } else throw std::runtime_error("E_CODE: invalid LIT symbol");
        if (out.size() > expected_raw_size) throw std::runtime_error("E_CODE: decoded block exceeds expected size");
    }
    bits.validate_zero_padding(); if (out.size()!=expected_raw_size) throw std::runtime_error("E_CODE: decoded size mismatch");
    if (stats) { stats->input_bytes=encoded.size(); stats->output_bytes=out.size(); stats->token_count=token_count; }
    return out;
}
} // namespace sarc
