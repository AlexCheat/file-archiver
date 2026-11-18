#include "archive_writer.hpp"
#include "aes256.hpp"
#include "archive_format.hpp"
#include "byte_io.hpp"
#include "crc32.hpp"
#include "errors.hpp"
#include "keys.hpp"
#include "random.hpp"
#include "sha256.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace fs = std::filesystem;

namespace sarc
{
    namespace
    {
        struct FileInfo
        {
            std::string name;
            fs::path path;
            std::uint64_t size = 0;
            std::uint32_t crc = 0;
            std::uint32_t block_count = 0;
            Classification cls;
        };

        struct BlockInfo
        {
            std::uint32_t file = 0;
            std::uint32_t index = 0;
            std::uint32_t raw_len = 0;
            std::uint32_t coded_len = 0;
            BlockMode mode = BlockMode::Stored;
            std::uint64_t spool_offset = 0;
        };

        struct VolumePlan
        {
            std::vector<std::uint32_t> table_files;   // global file ids, local order
            std::vector<std::size_t> blocks;          // indices into the block list
            std::uint64_t payload_len = 0;
        };

        std::uint64_t entry_size(const FileInfo& f)
        {
            return FILE_ENTRY_FIXED_SIZE + f.name.size();
        }

        // Temporary store for coded blocks, so that volume layout can be
        // decided after every coded_len is known without holding data in RAM.
        class Spool
        {
        public:
            explicit Spool(fs::path path) : path_(std::move(path))
            {
                file_.open(path_, std::ios::in | std::ios::out | std::ios::binary | std::ios::trunc);

                if (!file_)
                    throw Error(ErrorCode::Io, "Cannot create temporary file: " + path_.string());
            }

            ~Spool()
            {
                file_.close();
                std::error_code ec;
                fs::remove(path_, ec);
            }

            Spool(const Spool&) = delete;
            Spool& operator=(const Spool&) = delete;

            std::uint64_t append(const std::uint8_t* data, std::size_t size)
            {
                const std::uint64_t offset = end_;

                file_.seekp(static_cast<std::streamoff>(end_));
                file_.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));

                if (!file_)
                    throw Error(ErrorCode::Io, "Cannot write temporary file");

                end_ += size;
                return offset;
            }

            void read(std::uint64_t offset, std::uint8_t* out, std::size_t size)
            {
                file_.seekg(static_cast<std::streamoff>(offset));
                file_.read(reinterpret_cast<char*>(out), static_cast<std::streamsize>(size));

                if (static_cast<std::size_t>(file_.gcount()) != size)
                    throw Error(ErrorCode::Io, "Cannot read temporary file");
            }

        private:
            fs::path path_;
            std::fstream file_;
            std::uint64_t end_ = 0;
        };

        // Encrypts (AES-256-CTR) and authenticates (HMAC-SHA256) on the fly.
        class VolumeSink
        {
        public:
            VolumeSink(const fs::path& path, const Keys& keys,
                       const std::uint8_t header[TRANSPORT_HEADER_SIZE])
                : out_(path, std::ios::binary | std::ios::trunc),
                  ctr_(keys.enc.data(), header + 25),
                  mac_(keys.mac.data(), keys.mac.size())
            {
                if (!out_)
                    throw Error(ErrorCode::Io, "Cannot create volume: " + path.string());

                expected_ = load_u32(header + 37);
                mac_.update(header, TRANSPORT_HEADER_SIZE);
                out_.write(reinterpret_cast<const char*>(header), TRANSPORT_HEADER_SIZE);
            }

            void put(const std::uint8_t* data, std::size_t size)
            {
                std::uint8_t chunk[4096];

                while (size > 0)
                {
                    const std::size_t take = std::min(size, sizeof(chunk));
                    std::memcpy(chunk, data, take);

                    ctr_.crypt(chunk, take);
                    mac_.update(chunk, take);
                    out_.write(reinterpret_cast<const char*>(chunk), static_cast<std::streamsize>(take));

                    written_ += take;
                    data += take;
                    size -= take;
                }
            }

            void put_u16(std::uint16_t v) { std::uint8_t b[2]; store_u16(b, v); put(b, 2); }
            void put_u32(std::uint32_t v) { std::uint8_t b[4]; store_u32(b, v); put(b, 4); }
            void put_u64(std::uint64_t v) { std::uint8_t b[8]; store_u64(b, v); put(b, 8); }
            void put_u8(std::uint8_t v) { put(&v, 1); }

            void finish()
            {
                if (written_ != expected_)
                    throw Error(ErrorCode::Io, "Internal error: volume length mismatch");

                const auto tag = mac_.finish();
                out_.write(reinterpret_cast<const char*>(tag.data()), static_cast<std::streamsize>(tag.size()));
                out_.close();

                if (!out_)
                    throw Error(ErrorCode::Io, "Volume write failed");
            }

        private:
            std::ofstream out_;
            Aes256Ctr ctr_;
            HmacSha256 mac_;
            std::uint64_t expected_ = 0;
            std::uint64_t written_ = 0;
        };

        // Removes partially written files unless released.
        class PartGuard
        {
        public:
            void add(const fs::path& p) { paths_.push_back(p); }
            void release() { paths_.clear(); }

            ~PartGuard()
            {
                std::error_code ec;

                for (const auto& p : paths_)
                    fs::remove(p, ec);
            }

        private:
            std::vector<fs::path> paths_;
        };

        std::uint64_t payload_size(const std::vector<FileInfo>& files,
                                   const std::vector<BlockInfo>& blocks,
                                   const VolumePlan& plan)
        {
            std::uint64_t total = PAYLOAD_HEAD_SIZE;

            for (auto id : plan.table_files)
                total += entry_size(files[id]);

            for (auto b : plan.blocks)
                total += BLOCK_HEADER_SIZE + blocks[b].coded_len;

            return total;
        }

        std::vector<VolumePlan> plan_volumes(const std::vector<FileInfo>& files,
                                             const std::vector<BlockInfo>& blocks,
                                             const PackOptions& opt)
        {
            const std::uint64_t fixed = TRANSPORT_HEADER_SIZE + MAC_SIZE + PAYLOAD_HEAD_SIZE;
            std::vector<VolumePlan> plans;

            if (opt.max_volume_bytes == 0)
            {
                VolumePlan p;
                p.table_files.resize(files.size());
                std::iota(p.table_files.begin(), p.table_files.end(), std::uint32_t{ 0 });
                p.blocks.resize(blocks.size());
                std::iota(p.blocks.begin(), p.blocks.end(), std::size_t{ 0 });
                p.payload_len = payload_size(files, blocks, p);

                if (p.table_files.size() > 0xFFFF || p.payload_len > 0xFFFFFFFFull)
                    throw Error(ErrorCode::Config,
                        "Archive is too large for one volume; set a volume size");

                plans.push_back(std::move(p));
                return plans;
            }

            if (opt.max_volume_bytes <= fixed)
                throw Error(ErrorCode::Config, "Volume size is smaller than the volume header");

            const std::uint64_t volume_limit = std::min<std::uint64_t>(opt.max_volume_bytes, 0xFFFFFFFFull);

            std::vector<std::size_t> pending(blocks.size());
            std::iota(pending.begin(), pending.end(), std::size_t{ 0 });

            const std::size_t window_cap = std::max<std::size_t>(1, std::min<std::size_t>(opt.candidate_window, 0xFFFF));

            while (!pending.empty())
            {
                std::size_t n = std::min(window_cap, pending.size());

                for (;;)
                {
                    // Fix the candidate set and reserve its whole file table.
                    std::vector<std::uint32_t> table_files;
                    std::unordered_set<std::uint32_t> seen;
                    std::uint64_t table_bytes = 0;

                    for (std::size_t k = 0; k < n; ++k)
                    {
                        const std::uint32_t f = blocks[pending[k]].file;

                        if (seen.insert(f).second)
                        {
                            table_files.push_back(f);
                            table_bytes += entry_size(files[f]);
                        }
                    }

                    if (fixed + table_bytes > volume_limit)
                    {
                        if (n > 1)
                        {
                            n = std::max<std::size_t>(1, n / 2);
                            continue;
                        }

                        throw Error(ErrorCode::Config,
                            "File table does not fit into an empty volume; "
                            "increase the volume size");
                    }

                    const std::uint64_t capacity = volume_limit - fixed - table_bytes;

                    std::vector<KnapsackItem> items(n);

                    for (std::size_t k = 0; k < n; ++k)
                    {
                        const BlockInfo& b = blocks[pending[k]];
                        const auto type = static_cast<std::size_t>(files[b.file].cls.type);

                        items[k].weight = BLOCK_HEADER_SIZE + b.coded_len;
                        items[k].value = (static_cast<std::uint64_t>(b.raw_len) + 1) * opt.type_priority[type];
                    }

                    const KnapsackResult chosen = pack_items(items, capacity, opt.packer);

                    if (chosen.chosen.empty())
                    {
                        if (n > 1)
                        {
                            n = std::max<std::size_t>(1, n / 2);
                            continue;
                        }

                        throw Error(ErrorCode::Config,
                            "A coded block does not fit into a volume; reduce the "
                            "block size or increase the volume size");
                    }

                    VolumePlan plan;
                    plan.table_files = std::move(table_files);

                    std::vector<char> taken(n, 0);

                    for (auto k : chosen.chosen)
                    {
                        taken[k] = 1;
                        plan.blocks.push_back(pending[k]);
                    }

                    plan.payload_len = payload_size(files, blocks, plan);

                    std::vector<std::size_t> rest;
                    rest.reserve(pending.size());

                    for (std::size_t k = 0; k < pending.size(); ++k)
                    {
                        if (k >= n || !taken[k])
                            rest.push_back(pending[k]);
                    }

                    pending = std::move(rest);
                    plans.push_back(std::move(plan));
                    break;
                }

                if (plans.size() > MAX_VOLUMES)
                    throw Error(ErrorCode::Config, "Too many volumes; increase the volume size");
            }

            if (plans.empty())
            {
                // No blocks at all (an archive of zero files).
                VolumePlan p;
                p.payload_len = PAYLOAD_HEAD_SIZE;
                plans.push_back(std::move(p));
            }

            return plans;
        }

        std::string volume_name(const std::string& base, std::size_t index, std::size_t count)
        {
            if (count == 1)
                return base;

            std::string number = std::to_string(index + 1);

            while (number.size() < 3)
                number.insert(number.begin(), '0');

            return base + "." + number;
        }

        [[noreturn]] void rethrow_codec(const std::exception& e)
        {
            std::string message = e.what();

            for (const char* prefix : { "E_CODE: ", "E_PAYLOAD: " })
            {
                const std::size_t len = std::strlen(prefix);

                if (message.compare(0, len, prefix) == 0)
                {
                    message.erase(0, len);
                    break;
                }
            }

            throw Error(ErrorCode::Code, message);
        }
    }

    PackReport create_archive(
        const std::string& archive_path,
        const std::vector<std::string>& input_files,
        const PackOptions& options)
    {
        try
        {
            if (options.password.empty())
                throw Error(ErrorCode::Input, "A password is required");

            if (options.block_size == 0 || options.block_size > MAX_BLOCK_SIZE)
                throw Error(ErrorCode::Config, "Block size must be in 1..16777216");

            if (input_files.size() > MAX_FILES)
                throw Error(ErrorCode::Input, "Too many input files");

            const std::string base = fs::absolute(archive_path).lexically_normal().string();

            // ---- Validate every input before touching the disk ----
            std::vector<FileInfo> files;
            std::unordered_set<std::string> names;

            for (const auto& file : input_files)
            {
                FileInfo info;
                info.path = fs::absolute(file).lexically_normal();

                std::error_code ec;

                if (!fs::is_regular_file(info.path, ec))
                    throw Error(ErrorCode::Input, "Not a regular file: " + file);

                info.name = info.path.filename().string();

                if (!is_safe_filename(info.name))
                    throw Error(ErrorCode::Input, "Unsafe or invalid file name: " + info.name);

                if (!names.insert(info.name).second)
                    throw Error(ErrorCode::Input, "Duplicate filename: " + info.name);

                // Archive (and its volumes / temp files) must not clobber an input.
                if (info.path.string().compare(0, base.size(), base) == 0 &&
                    (info.path.string().size() == base.size() ||
                     info.path.string()[base.size()] == '.'))
                    throw Error(ErrorCode::Input, "Archive cannot overwrite an input file");

                info.size = fs::file_size(info.path, ec);

                if (ec)
                    throw Error(ErrorCode::Input, "Cannot read file size: " + file);

                std::ifstream probe(info.path, std::ios::binary);

                if (!probe)
                    throw Error(ErrorCode::Input, "Cannot open input file (permissions?): " + file);

                const std::uint64_t blocks = info.size == 0
                    ? 1 : (info.size + options.block_size - 1) / options.block_size;

                if (blocks > 0xFFFFFFFFull)
                    throw Error(ErrorCode::Config, "File has too many blocks; increase block size");

                info.block_count = static_cast<std::uint32_t>(blocks);
                files.push_back(std::move(info));
            }

            const EntropyClassifier fallback;
            const FileClassifier& classifier = options.classifier ? *options.classifier : fallback;

            // ---- Pass 1: classify, split into blocks, compress, spool ----
            Spool spool(base + ".spool");

            std::vector<BlockInfo> blocks;
            std::vector<std::uint8_t> raw;

            PackReport report;

            for (std::uint32_t fi = 0; fi < files.size(); ++fi)
            {
                FileInfo& f = files[fi];
                std::ifstream in(f.path, std::ios::binary);

                if (!in)
                    throw Error(ErrorCode::Input, "Cannot open input file: " + f.name);

                Crc32 crc;

                for (std::uint32_t b = 0; b < f.block_count; ++b)
                {
                    const std::uint64_t offset = static_cast<std::uint64_t>(b) * options.block_size;
                    const std::uint32_t len = f.size == 0 ? 0
                        : static_cast<std::uint32_t>(std::min<std::uint64_t>(options.block_size, f.size - offset));

                    raw.resize(len);
                    in.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(len));

                    if (static_cast<std::uint32_t>(in.gcount()) != len)
                        throw Error(ErrorCode::Input, "Input file changed or could not be read: " + f.name);

                    crc.update(raw.data(), raw.size());

                    if (b == 0)
                        f.cls = classifier.classify(raw.data(), std::min<std::size_t>(raw.size(), 64 * 1024));

                    BlockInfo info;
                    info.file = fi;
                    info.index = b;
                    info.raw_len = len;

                    std::vector<std::uint8_t> coded;
                    bool use_compressed = false;

                    if (f.cls.strategy == Strategy::Compress && len > 0)
                    {
                        try
                        {
                            coded = compress_block(raw, options.codec);
                        }
                        catch (const std::invalid_argument& e)
                        {
                            throw Error(ErrorCode::Config, e.what());
                        }
                        catch (const std::runtime_error& e)
                        {
                            rethrow_codec(e);
                        }

                        use_compressed = coded.size() < len;
                    }

                    if (use_compressed)
                    {
                        info.mode = BlockMode::Compressed;
                        info.coded_len = static_cast<std::uint32_t>(coded.size());
                        info.spool_offset = spool.append(coded.data(), coded.size());
                    }
                    else
                    {
                        info.mode = BlockMode::Stored;   // NO_COMPRESSION: coded_len == raw_len
                        info.coded_len = len;
                        info.spool_offset = spool.append(raw.data(), raw.size());
                        ++report.blocks_stored;
                    }

                    report.coded_bytes += info.coded_len;
                    ++report.blocks_total;
                    blocks.push_back(info);
                }

                f.crc = crc.value();
                report.raw_bytes += f.size;
            }

            report.files = files.size();

            // ---- Pass 2: pack blocks into volumes (knapsack) ----
            const std::vector<VolumePlan> plans = plan_volumes(files, blocks, options);

            std::uint8_t salt[SALT_SIZE];
            random_bytes(salt, sizeof(salt));
            const Keys keys = derive_keys(options.password, salt);   // once per archive

            std::set<std::array<std::uint8_t, NONCE_SIZE>> used_nonces;
            std::vector<fs::path> parts, finals;
            PartGuard guard;

            for (std::size_t v = 0; v < plans.size(); ++v)
            {
                const VolumePlan& plan = plans[v];

                std::array<std::uint8_t, NONCE_SIZE> nonce{};

                do
                {
                    random_bytes(nonce.data(), nonce.size());
                }
                while (!used_nonces.insert(nonce).second);   // nonce unique per volume

                std::uint8_t header[TRANSPORT_HEADER_SIZE];
                std::memcpy(header, MAGIC, 4);
                header[4] = VERSION;
                store_u16(header + 5, static_cast<std::uint16_t>(v));
                store_u16(header + 7, static_cast<std::uint16_t>(plans.size()));
                std::memcpy(header + 9, salt, SALT_SIZE);
                std::memcpy(header + 25, nonce.data(), NONCE_SIZE);
                store_u32(header + 37, static_cast<std::uint32_t>(plan.payload_len));

                const fs::path final_path = volume_name(base, v, plans.size());
                const fs::path part_path = final_path.string() + ".part";

                guard.add(part_path);
                parts.push_back(part_path);
                finals.push_back(final_path);

                VolumeSink sink(part_path, keys, header);

                sink.put_u32(static_cast<std::uint32_t>(plan.table_files.size()));
                sink.put_u32(static_cast<std::uint32_t>(plan.blocks.size()));
                sink.put_u32(options.block_size);

                std::unordered_map<std::uint32_t, std::uint16_t> local;

                for (std::size_t k = 0; k < plan.table_files.size(); ++k)
                {
                    const FileInfo& f = files[plan.table_files[k]];
                    local[plan.table_files[k]] = static_cast<std::uint16_t>(k);

                    sink.put_u16(static_cast<std::uint16_t>(f.name.size()));
                    sink.put(reinterpret_cast<const std::uint8_t*>(f.name.data()), f.name.size());
                    sink.put_u64(f.size);
                    sink.put_u32(f.crc);
                    sink.put_u8(static_cast<std::uint8_t>(f.cls.type));
                    sink.put_u8(static_cast<std::uint8_t>(f.cls.strategy));
                }

                std::vector<std::uint8_t> chunk(BUFFER_SIZE);

                for (std::size_t bi : plan.blocks)
                {
                    const BlockInfo& b = blocks[bi];

                    sink.put_u16(local.at(b.file));
                    sink.put_u32(b.index);
                    sink.put_u32(b.raw_len);
                    sink.put_u32(b.coded_len);
                    sink.put_u8(static_cast<std::uint8_t>(b.mode));

                    std::uint64_t remaining = b.coded_len;
                    std::uint64_t offset = b.spool_offset;

                    while (remaining > 0)
                    {
                        const std::size_t take = static_cast<std::size_t>(
                            std::min<std::uint64_t>(remaining, chunk.size()));

                        spool.read(offset, chunk.data(), take);
                        sink.put(chunk.data(), take);

                        offset += take;
                        remaining -= take;
                    }
                }

                sink.finish();
            }

            // Publish only after every volume was written successfully.
            for (std::size_t v = 0; v < parts.size(); ++v)
            {
                std::error_code ec;
                fs::remove(finals[v], ec);
                fs::rename(parts[v], finals[v]);

                const auto size = fs::file_size(finals[v]);
                report.volume_paths.push_back(finals[v].string());
                report.volume_sizes.push_back(size);
                report.archive_bytes += size;
            }

            guard.release();
            return report;
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
