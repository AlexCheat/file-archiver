#pragma once

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <cstddef>
#include <cstdint>

namespace sarc
{
    // file_type values of FORMAT_SPEC_P2 section 2.2 (0..6).
    enum class FileType : std::uint8_t
    {
        Text = 0,        // natural text
        Code = 1,        // source code
        Structured = 2,  // CSV / JSON / logs
        Raster = 3,      // BMP / PGM
        Executable = 4,  // .exe / .so
        Compressed = 5,  // JPEG / MP3 / ZIP
        Artificial = 6   // zeros, noise
    };

    constexpr std::size_t FILE_TYPE_COUNT = 7;

    enum class Strategy : std::uint8_t
    {
        Store = 0,    // deliberate refusal to compress (NO_COMPRESSION)
        Compress = 1
    };

    struct Classification
    {
        FileType type = FileType::Text;
        Strategy strategy = Strategy::Compress;
    };

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

    class PerceptronClassifier : public FileClassifier
    {
    public:
        struct TrainingSample
        {
            FeatureVector features;
            FileType label;
        };

        explicit PerceptronClassifier(std::size_t hidden_size = 32, std::uint64_t seed = 42);

        // Класифікація (використовує extract_features
        Classification classify(const std::uint8_t* data, std::size_t size) const override;

        // Прямий прохід по вже готовому вектору ознак (повертає ймовірності по 7 класах)
        std::array<double, FILE_TYPE_COUNT> predict_proba(const FeatureVector& x) const;

        // Навчання мережі (SGD + Cross-Entropy Loss)
        void train(const std::vector<TrainingSample>& dataset,
                   std::size_t epochs = 150,
                   double learning_rate = 0.05);

        // Збереження та завантаження навчених ваг у бінарний файл
        void save_weights(const std::string& path) const;
        void load_weights(const std::string& path);

    private:
        std::size_t hidden_size_;
        std::vector<double> w1_;
        std::vector<double> b1_;
        std::vector<double> w2_;
        std::vector<double> b2_;

        static Strategy decide_strategy(FileType type, double entropy_norm);
    };
}
