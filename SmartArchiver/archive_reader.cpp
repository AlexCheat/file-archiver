#include "archive_reader.hpp"
#include "aes256.hpp"
#include "archive_format.hpp"
#include "byte_io.hpp"
#include "crc32.hpp"
#include "errors.hpp"
#include "keys.hpp"
#include "random.hpp"
#include "sarc_codec.hpp"
#include "sha256.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

namespace fs = std::filesystem;

namespace sarc
{
    namespace
    {
        struct VolumeInfo
        {
            std::string path;
            std::array<std::uint8_t, TRANSPORT_HEADER_SIZE> raw{};
            std::uint16_t index = 0;
            std::uint16_t count = 0;
            std::uint32_t ciphertext_len = 0;

            const std::uint8_t* salt() const { return raw.data() + 9; }
            const std::uint8_t* nonce() const { return raw.data() + 25; }
        };

        // Validates the plaintext transport header and the file length
        // BEFORE anything is decrypted.
        VolumeInfo read_volume_header(const std::string& path)
        {
            std::ifstream in(path, std::ios::binary);

            if (!in)
                throw Error(ErrorCode::Io, "Cannot open volume: " + path);

            in.seekg(0, std::ios::end);
            const auto end = in.tellg();
            in.seekg(0, std::ios::beg);

            if (end < 0)
                throw Error(ErrorCode::Io, "Cannot determine volume size: " + path);

            const std::uint64_t file_size = static_cast<std::uint64_t>(end);

            if (file_size < TRANSPORT_HEADER_SIZE + MAC_SIZE)
                throw Error(ErrorCode::Payload, "Volume is too short: " + path);

            VolumeInfo v;
            v.path = path;

            in.read(reinterpret_cast<char*>(v.raw.data()), static_cast<std::streamsize>(v.raw.size()));

            if (!in)
                throw Error(ErrorCode::Io, "Cannot read volume header: " + path);

            if (std::memcmp(v.raw.data(), MAGIC, 4) != 0)
                throw Error(ErrorCode::Payload, "Invalid archive signature: " + path);

            if (v.raw[4] != VERSION)
                throw Error(ErrorCode::Payload, "Unsupported archive version: " + path);

            v.index = load_u16(v.raw.data() + 5);
            v.count = load_u16(v.raw.data() + 7);

            if (v.count == 0 || v.index >= v.count)
                throw Error(ErrorCode::Payload, "Invalid volume numbering: " + path);

            v.ciphertext_len = load_u32(v.raw.data() + 37);

            if (file_size != TRANSPORT_HEADER_SIZE + static_cast<std::uint64_t>(v.ciphertext_len) + MAC_SIZE)
                throw Error(ErrorCode::Payload,
                    "Volume length does not match its header (truncated or extra data): " + path);

            return v;
        }

        // HMAC over header || ciphertext, checked before any decryption.
        void verify_mac(const VolumeInfo& v, const Keys& keys)
        {
            std::ifstream in(v.path, std::ios::binary);

            if (!in)
                throw Error(ErrorCode::Io, "Cannot open volume: " + v.path);

            HmacSha256 mac(keys.mac.data(), keys.mac.size());
            mac.update(v.raw.data(), v.raw.size());

            in.seekg(static_cast<std::streamoff>(TRANSPORT_HEADER_SIZE));

            std::vector<std::uint8_t> buffer(BUFFER_SIZE);
            std::uint64_t remaining = v.ciphertext_len;

            while (remaining > 0)
            {
                const std::size_t take = static_cast<std::size_t>(
                    std::min<std::uint64_t>(remaining, buffer.size()));

                in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(take));

                if (static_cast<std::size_t>(in.gcount()) != take)
                    throw Error(ErrorCode::Payload, "Unexpected end of volume: " + v.path);

                mac.update(buffer.data(), take);
                remaining -= take;
            }

            std::uint8_t stored[MAC_SIZE];
            in.read(reinterpret_cast<char*>(stored), MAC_SIZE);

            if (static_cast<std::size_t>(in.gcount()) != MAC_SIZE)
                throw Error(ErrorCode::Payload, "Unexpected end of volume: " + v.path);

            const auto computed = mac.finish();

            if (!ct_equal(computed.data(), stored, MAC_SIZE))
                throw Error(ErrorCode::Auth,
                    "Authentication failed (wrong password or modified archive): " + v.path);
        }

        // Decrypting reader that can never read past the authenticated payload.
        class CipherStream
        {
        public:
            CipherStream(const VolumeInfo& v, const Keys& keys)
                : in_(v.path, std::ios::binary),
                  ctr_(keys.enc.data(), v.nonce()),
                  remaining_(v.ciphertext_len)
            {
                if (!in_)
                    throw Error(ErrorCode::Io, "Cannot open volume: " + v.path);

                in_.seekg(static_cast<std::streamoff>(TRANSPORT_HEADER_SIZE));
            }

            std::uint64_t remaining() const { return remaining_; }

            void read(std::uint8_t* out, std::size_t size)
            {
                if (size > remaining_)
                    throw Error(ErrorCode::Payload, "Payload structure exceeds the volume");

                in_.read(reinterpret_cast<char*>(out), static_cast<std::streamsize>(size));

                if (static_cast<std::size_t>(in_.gcount()) != size)
                    throw Error(ErrorCode::Payload, "Unexpected end of volume");

                ctr_.crypt(out, size);
                remaining_ -= size;
            }

            void skip(std::uint64_t size)
            {
                if (size > remaining_)
                    throw Error(ErrorCode::Payload, "Payload structure exceeds the volume");

                in_.seekg(static_cast<std::streamoff>(size), std::ios::cur);

                if (!in_)
                    throw Error(ErrorCode::Payload, "Unexpected end of volume");

                ctr_.skip(size);
                remaining_ -= size;
            }

            std::uint8_t u8() { std::uint8_t b[1]; read(b, 1); return b[0]; }
            std::uint16_t u16() { std::uint8_t b[2]; read(b, 2); return load_u16(b); }
            std::uint32_t u32() { std::uint8_t b[4]; read(b, 4); return load_u32(b); }
            std::uint64_t u64() { std::uint8_t b[8]; read(b, 8); return load_u64(b); }

        private:
            std::ifstream in_;
            Aes256Ctr ctr_;
            std::uint64_t remaining_;
        };

        struct FileState
        {
            std::string name;
            std::uint64_t size = 0;
            std::uint32_t crc = 0;
            std::uint8_t type = 0;
            std::uint8_t strategy = 0;
            std::uint64_t block_count = 0;
            std::unordered_set<std::uint32_t> received;
            fs::path staged;
        };

        std::uint64_t blocks_for(std::uint64_t size, std::uint32_t block_size)
        {
            return size == 0 ? 1 : (size + block_size - 1) / block_size;
        }

        class StagingGuard
        {
        public:
            void set(const fs::path& p) { path_ = p; }
            void release() { path_.clear(); }

            ~StagingGuard()
            {
                if (path_.empty())
                    return;

                std::error_code ec;
                fs::remove_all(path_, ec);
            }

        private:
            fs::path path_;
        };

        [[noreturn]] void rethrow_codec(const std::exception& e)
        {
            std::string message = e.what();

            if (message.compare(0, 11, "E_PAYLOAD: ") == 0)
                throw Error(ErrorCode::Payload, message.substr(11));

            if (message.compare(0, 8, "E_CODE: ") == 0)
                message.erase(0, 8);

            throw Error(ErrorCode::Code, message);
        }

        class ArchiveParser
        {
        public:
            ArchiveParser(const std::vector<std::string>& paths,
                          const std::string& password,
                          const fs::path* output)
                : paths_(paths), password_(password), output_(output)
            {
            }

            void run()
            {
                if (paths_.empty())
                    throw Error(ErrorCode::Input, "No archive volumes given");

                // 1. Validate all transport headers and the volume set.
                std::vector<VolumeInfo> volumes;

                for (const auto& p : paths_)
                    volumes.push_back(read_volume_header(p));

                check_volume_set(volumes);
                std::sort(volumes.begin(), volumes.end(),
                    [](const VolumeInfo& a, const VolumeInfo& b) { return a.index < b.index; });

                // 2. Key derivation: once per archive (same salt in every volume).
                const Keys keys = derive_keys(password_, volumes.front().salt());

                // 3. Authenticate every volume BEFORE any content is processed.
                for (const auto& v : volumes)
                    verify_mac(v, keys);

                StagingGuard guard;

                if (output_)
                {
                    fs::create_directories(*output_);
                    staging_ = *output_ / (".sarc-staging-" + random_hex(8));
                    fs::create_directory(staging_);
                    guard.set(staging_);
                }

                // 4. Parse payloads (and decode blocks when extracting).
                try
                {
                    for (const auto& v : volumes)
                        parse_volume(v, keys);

                    close_current();
                    check_complete();

                    if (output_)
                    {
                        verify_crc();
                        commit();
                        guard.release();
                        std::error_code ec;
                        fs::remove_all(staging_, ec);
                    }
                }
                catch (...)
                {
                    // Windows cannot delete a file that is still open, so the
                    // staging file must be closed before the guard cleans up.
                    if (out_.is_open())
                        out_.close();

                    throw;
                }
            }

            std::vector<ListEntry> entries() const
            {
                std::vector<ListEntry> result;

                for (const auto& f : files_)
                    result.push_back({ f.name, f.size, f.crc, f.type, f.strategy });

                return result;
            }

        private:
            void check_volume_set(const std::vector<VolumeInfo>& volumes) const
            {
                const VolumeInfo& first = volumes.front();
                std::set<std::uint16_t> indices;
                std::set<std::array<std::uint8_t, NONCE_SIZE>> nonces;

                for (const auto& v : volumes)
                {
                    if (v.count != first.count ||
                        std::memcmp(v.salt(), first.salt(), SALT_SIZE) != 0)
                        throw Error(ErrorCode::Volume,
                            "Volumes belong to different archives: " + v.path);

                    if (!indices.insert(v.index).second)
                        throw Error(ErrorCode::Volume,
                            "Duplicate volume " + std::to_string(v.index + 1) + ": " + v.path);

                    std::array<std::uint8_t, NONCE_SIZE> n{};
                    std::memcpy(n.data(), v.nonce(), NONCE_SIZE);

                    if (!nonces.insert(n).second)
                        throw Error(ErrorCode::Volume, "Nonce reused between volumes: " + v.path);
                }

                if (volumes.size() != first.count)
                    throw Error(ErrorCode::Volume,
                        "Missing volume: expected " + std::to_string(first.count) +
                        ", got " + std::to_string(volumes.size()));
            }

            void parse_volume(const VolumeInfo& v, const Keys& keys)
            {
                CipherStream cs(v, keys);

                const std::uint32_t file_count = cs.u32();
                const std::uint32_t block_count = cs.u32();
                const std::uint32_t block_size = cs.u32();

                if (file_count > 0xFFFF || file_count > MAX_FILES)
                    throw Error(ErrorCode::Payload, "Invalid file count");

                if (block_size == 0 || block_size > MAX_BLOCK_SIZE)
                    throw Error(ErrorCode::Payload, "Invalid block size");

                if (block_size_ != 0 && block_size_ != block_size)
                    throw Error(ErrorCode::Payload, "Block size differs between volumes");

                block_size_ = block_size;

                if (static_cast<std::uint64_t>(block_count) * BLOCK_HEADER_SIZE > cs.remaining())
                    throw Error(ErrorCode::Payload, "Invalid block count");

                // ---- file table ----
                std::vector<std::size_t> local;
                std::unordered_set<std::string> local_names;

                for (std::uint32_t i = 0; i < file_count; ++i)
                {
                    const std::uint16_t name_len = cs.u16();

                    if (name_len == 0 || name_len > MAX_FILENAME_SIZE)
                        throw Error(ErrorCode::Payload, "Invalid filename length");

                    std::string name(name_len, '\0');
                    cs.read(reinterpret_cast<std::uint8_t*>(name.data()), name_len);

                    if (!is_safe_filename(name))
                        throw Error(ErrorCode::Payload, "Unsafe filename in archive");

                    if (!local_names.insert(name).second)
                        throw Error(ErrorCode::Payload, "Duplicate filename in archive");

                    const std::uint64_t size = cs.u64();
                    const std::uint32_t crc = cs.u32();
                    const std::uint8_t type = cs.u8();
                    const std::uint8_t strategy = cs.u8();

                    const auto found = index_.find(name);

                    if (found != index_.end())
                    {
                        const FileState& f = files_[found->second];

                        if (f.size != size || f.crc != crc || f.type != type || f.strategy != strategy)
                            throw Error(ErrorCode::Payload, "File table differs between volumes");

                        local.push_back(found->second);
                        continue;
                    }

                    if (files_.size() >= MAX_FILES)
                        throw Error(ErrorCode::Payload, "Too many files in archive");

                    FileState f;
                    f.name = name;
                    f.size = size;
                    f.crc = crc;
                    f.type = type;
                    f.strategy = strategy;
                    f.block_count = blocks_for(size, block_size);

                    if (output_)
                    {
                        f.staged = staging_ / ("f" + std::to_string(files_.size()));
                        std::ofstream create(f.staged, std::ios::binary | std::ios::trunc);

                        if (!create)
                            throw Error(ErrorCode::Io, "Cannot create staging file");
                    }

                    index_[name] = files_.size();
                    local.push_back(files_.size());
                    files_.push_back(std::move(f));
                }

                // ---- blocks ----
                for (std::uint32_t i = 0; i < block_count; ++i)
                {
                    const std::uint16_t file_idx = cs.u16();
                    const std::uint32_t block_idx = cs.u32();
                    const std::uint32_t raw_len = cs.u32();
                    const std::uint32_t coded_len = cs.u32();
                    const std::uint8_t mode = cs.u8();

                    if (file_idx >= local.size())
                        throw Error(ErrorCode::Payload, "Block refers to an unknown file");

                    const std::size_t fi = local[file_idx];
                    FileState& f = files_[fi];

                    if (block_idx >= f.block_count)
                        throw Error(ErrorCode::Payload, "Block index out of range");

                    const std::uint64_t offset = static_cast<std::uint64_t>(block_idx) * block_size;
                    const std::uint64_t expected_raw = f.size == 0 ? 0
                        : std::min<std::uint64_t>(block_size, f.size - offset);

                    if (raw_len != expected_raw)
                        throw Error(ErrorCode::Payload, "Block length does not match the file table");

                    if (mode == static_cast<std::uint8_t>(BlockMode::Stored))
                    {
                        if (coded_len != raw_len)
                            throw Error(ErrorCode::Payload, "Stored block must have coded_len == raw_len");
                    }
                    else if (mode == static_cast<std::uint8_t>(BlockMode::Compressed))
                    {
                        if (raw_len == 0 || coded_len == 0 ||
                            coded_len > static_cast<std::uint64_t>(raw_len) * 2 + 16384)
                            throw Error(ErrorCode::Payload, "Invalid coded block length");
                    }
                    else
                    {
                        throw Error(ErrorCode::Payload, "Unknown block mode");
                    }

                    if (coded_len > cs.remaining())
                        throw Error(ErrorCode::Payload, "Block exceeds the volume");

                    if (!f.received.insert(block_idx).second)
                        throw Error(ErrorCode::Payload, "Duplicate block in archive");

                    if (!output_)
                    {
                        cs.skip(coded_len);
                        continue;
                    }

                    std::vector<std::uint8_t> coded(coded_len);
                    cs.read(coded.data(), coded.size());

                    if (mode == static_cast<std::uint8_t>(BlockMode::Compressed))
                    {
                        try
                        {
                            coded = decompress_block(coded, raw_len);
                        }
                        catch (const Error&)
                        {
                            throw;
                        }
                        catch (const std::exception& e)
                        {
                            rethrow_codec(e);
                        }
                    }

                    write_block(fi, offset, coded);
                }

                if (cs.remaining() != 0)
                    throw Error(ErrorCode::Payload, "Unexpected extra data in payload");
            }

            void write_block(std::size_t file, std::uint64_t offset, const std::vector<std::uint8_t>& data)
            {
                if (data.empty())
                    return;

                if (current_ != file)
                {
                    close_current();
                    out_.open(files_[file].staged, std::ios::in | std::ios::out | std::ios::binary);

                    if (!out_)
                        throw Error(ErrorCode::Io, "Cannot open staging file");

                    current_ = file;
                }

                out_.seekp(static_cast<std::streamoff>(offset));
                out_.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));

                if (!out_)
                    throw Error(ErrorCode::Io, "Cannot write extracted data");
            }

            void close_current()
            {
                if (out_.is_open())
                {
                    out_.close();

                    if (out_.fail())
                        throw Error(ErrorCode::Io, "Cannot finish writing extracted data");
                }

                current_ = static_cast<std::size_t>(-1);
            }

            void check_complete() const
            {
                for (const auto& f : files_)
                {
                    if (f.received.size() != f.block_count)
                        throw Error(ErrorCode::Payload, "Archive is incomplete: " + f.name);
                }
            }

            void verify_crc() const
            {
                std::vector<std::uint8_t> buffer(BUFFER_SIZE);

                for (const auto& f : files_)
                {
                    std::error_code ec;

                    if (fs::file_size(f.staged, ec) != f.size || ec)
                        throw Error(ErrorCode::Crc, "Restored size mismatch: " + f.name);

                    std::ifstream in(f.staged, std::ios::binary);
                    Crc32 crc;

                    while (in)
                    {
                        in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
                        crc.update(buffer.data(), static_cast<std::size_t>(in.gcount()));
                    }

                    if (crc.value() != f.crc)
                        throw Error(ErrorCode::Crc, "CRC32 mismatch: " + f.name);
                }
            }

            void commit()
            {
                // Never overwrite: check every destination first.
                for (const auto& f : files_)
                {
                    if (fs::exists(*output_ / f.name))
                        throw Error(ErrorCode::Exists, "File already exists: " + f.name);
                }

                std::vector<fs::path> moved;

                try
                {
                    for (const auto& f : files_)
                    {
                        const fs::path destination = *output_ / f.name;
                        fs::rename(f.staged, destination);
                        moved.push_back(destination);
                    }
                }
                catch (...)
                {
                    std::error_code ec;

                    for (const auto& p : moved)
                        fs::remove(p, ec);

                    throw;
                }
            }

            const std::vector<std::string>& paths_;
            const std::string& password_;
            const fs::path* output_;

            fs::path staging_;
            std::uint32_t block_size_ = 0;
            std::vector<FileState> files_;
            std::unordered_map<std::string, std::size_t> index_;

            std::fstream out_;
            std::size_t current_ = static_cast<std::size_t>(-1);
        };
    }

    std::vector<ListEntry> list_archive(
        const std::vector<std::string>& volume_paths,
        const std::string& password)
    {
        try
        {
            ArchiveParser parser(volume_paths, password, nullptr);
            parser.run();
            return parser.entries();
        }
        catch (const fs::filesystem_error& e)
        {
            throw Error(ErrorCode::Io, e.what());
        }
        catch (const std::bad_alloc&)
        {
            throw Error(ErrorCode::Io, "Out of memory");
        }
    }

    void extract_archive(
        const std::vector<std::string>& volume_paths,
        const std::string& output_folder,
        const std::string& password)
    {
        try
        {
            const fs::path output = fs::absolute(output_folder);
            ArchiveParser parser(volume_paths, password, &output);
            parser.run();
        }
        catch (const fs::filesystem_error& e)
        {
            throw Error(ErrorCode::Io, e.what());
        }
        catch (const std::bad_alloc&)
        {
            throw Error(ErrorCode::Io, "Out of memory");
        }
    }
}
