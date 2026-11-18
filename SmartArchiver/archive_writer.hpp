#pragma once

#include "classifier.hpp"
#include "knapsack.hpp"
#include "sarc_codec.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace sarc
{
    struct PackOptions
    {
        std::string password;                       // required
        std::uint64_t max_volume_bytes = 0;         // 0 = one volume, no limit
        std::uint32_t block_size = 64 * 1024;       // from team_config.json
        CodecOptions codec;                         // LZ77 parameters (GA genes)
        PackerKind packer = PackerKind::Knapsack;
        std::size_t candidate_window = 256;         // blocks considered per volume

        // Value of a block = (raw_len + 1) * type_priority[file type].
        std::array<std::uint32_t, FILE_TYPE_COUNT> type_priority{ 1, 1, 1, 1, 1, 1, 1, 1 };

        // Analysis zone plug-in point. nullptr = EntropyClassifier.
        std::shared_ptr<const FileClassifier> classifier;
    };

    struct PackReport
    {
        std::vector<std::string> volume_paths;
        std::vector<std::uint64_t> volume_sizes;
        std::uint64_t files = 0;
        std::uint64_t raw_bytes = 0;        // sum of input sizes
        std::uint64_t coded_bytes = 0;      // sum of coded_len over all blocks
        std::uint64_t archive_bytes = 0;    // sum of volume file sizes
        std::uint64_t blocks_total = 0;
        std::uint64_t blocks_stored = 0;    // NO_COMPRESSION blocks

        // Everything that is not block data: headers, tables, MACs.
        std::uint64_t overhead_bytes() const { return archive_bytes - coded_bytes; }
    };

    // Writes <archive_path> (one volume) or <archive_path>.001, .002, ...
    PackReport create_archive(
        const std::string& archive_path,
        const std::vector<std::string>& files,
        const PackOptions& options);
}
