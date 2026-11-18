#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace sarc
{
    // The seven corpus groups from the task (+ Unknown).
    enum class FileType : std::uint8_t
    {
        Unknown = 0,
        Text,        // natural text
        Code,        // source code
        Structured,  // CSV / JSON / logs
        Raster,      // BMP / PGM
        Executable,  // .exe / .so
        Compressed,  // JPEG / MP3 / ZIP
        Artificial   // zeros, noise
    };

    constexpr std::size_t FILE_TYPE_COUNT = 8;

    enum class Strategy : std::uint8_t
    {
        Compress = 0,
        Store = 1    // deliberate refusal to compress (NO_COMPRESSION)
    };

    struct Classification
    {
        FileType type = FileType::Unknown;
        Strategy strategy = Strategy::Compress;
    };

    // Feature vector from section 3.1, roughly scaled to [-1, 1]:
    //   [0]       Shannon entropy / 8
    //   [1..32]   byte histogram folded to 32 bins (fractions)
    //   [33]      share of printable ASCII
    //   [34]      mean distance between '\n' (capped at 1024, / 1024)
    //   [35..50]  autocorrelation, lags 1..16
    //   [51]      bigram entropy / 16
    constexpr std::size_t FEATURE_COUNT = 52;
    using FeatureVector = std::array<double, FEATURE_COUNT>;

    double shannon_entropy(const std::uint8_t* data, std::size_t size);
    FeatureVector extract_features(const std::uint8_t* data, std::size_t size);

    // Seam for the analysis zone: the perceptron replaces EntropyClassifier by
    // implementing this interface on top of extract_features().
    class FileClassifier
    {
    public:
        virtual ~FileClassifier() = default;
        virtual Classification classify(const std::uint8_t* data, std::size_t size) const = 0;
    };

    // Baseline stand-in until the perceptron is trained: refuses to compress
    // high-entropy data, labels the rest by a few simple rules.
    class EntropyClassifier : public FileClassifier
    {
    public:
        explicit EntropyClassifier(double store_threshold_bits = 7.5)
            : threshold_(store_threshold_bits) {}

        Classification classify(const std::uint8_t* data, std::size_t size) const override;

    private:
        double threshold_;
    };
}
