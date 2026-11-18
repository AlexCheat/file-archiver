#include "classifier.hpp"
#include "errors.hpp"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <random>

namespace sarc
{
    PerceptronClassifier::PerceptronClassifier(std::size_t hidden_size, std::uint64_t seed)
        : hidden_size_(hidden_size),
          w1_(hidden_size * FEATURE_COUNT),
          b1_(hidden_size, 0.0),
          w2_(FILE_TYPE_COUNT * hidden_size),
          b2_(FILE_TYPE_COUNT, 0.0)
    {
        std::mt19937_64 rng(seed);
        const double std1 = std::sqrt(2.0 / static_cast<double>(FEATURE_COUNT + hidden_size_));
        const double std2 = std::sqrt(2.0 / static_cast<double>(hidden_size_ + FILE_TYPE_COUNT));

        std::normal_distribution<double> dist1(0.0, std1);
        std::normal_distribution<double> dist2(0.0, std2);

        for (double& w : w1_) w = dist1(rng);
        for (double& w : w2_) w = dist2(rng);
    }

    std::array<double, FILE_TYPE_COUNT> PerceptronClassifier::predict_proba(const FeatureVector& x) const
    {
        std::vector<double> h(hidden_size_, 0.0);
        for (std::size_t i = 0; i < hidden_size_; ++i)
        {
            double sum = b1_[i];
            const std::size_t row = i * FEATURE_COUNT;
            for (std::size_t j = 0; j < FEATURE_COUNT; ++j)
                sum += w1_[row + j] * x[j];
            h[i] = std::tanh(sum);
        }

        std::array<double, FILE_TYPE_COUNT> logits{};
        double max_logit = -1e30;
        for (std::size_t c = 0; c < FILE_TYPE_COUNT; ++c)
        {
            double sum = b2_[c];
            const std::size_t row = c * hidden_size_;
            for (std::size_t i = 0; i < hidden_size_; ++i)
                sum += w2_[row + i] * h[i];
            logits[c] = sum;
            max_logit = std::max(max_logit, sum);
        }

        // Чисельно стабільний Softmax
        std::array<double, FILE_TYPE_COUNT> probs{};
        double exp_sum = 0.0;
        for (std::size_t c = 0; c < FILE_TYPE_COUNT; ++c)
        {
            probs[c] = std::exp(logits[c] - max_logit);
            exp_sum += probs[c];
        }
        for (double& p : probs) p /= exp_sum;

        return probs;
    }

    Strategy PerceptronClassifier::decide_strategy(FileType type, double entropy_norm)
    {
        // Вже стиснуті формати (JPEG, MP3, ZIP) не стискаємо повторно[cite: 62]
        if (type == FileType::Compressed)
            return Strategy::Store;

        // Штучні дані (нулі — стискаємо; чистий білий шум з ентропією ~8 біт — зберігаємо)[cite: 62]
        if (type == FileType::Artificial)
            return (entropy_norm * 8.0 > 7.5) ? Strategy::Store : Strategy::Compress;

        return Strategy::Compress;
    }

    Classification PerceptronClassifier::classify(const std::uint8_t* data, std::size_t size) const
    {
        if (!data || size == 0)
            return { FileType::Artificial, Strategy::Store };

        const FeatureVector features = extract_features(data, size);
        const auto probs = predict_proba(features);

        std::size_t best_idx = 0;
        for (std::size_t c = 1; c < FILE_TYPE_COUNT; ++c)
        {
            if (probs[c] > probs[best_idx])
                best_idx = c;
        }

        const auto detected_type = static_cast<FileType>(best_idx);
        // features[0] — це Shannon entropy / 8[cite: 62]
        const Strategy strat = decide_strategy(detected_type, features[0]);

        return { detected_type, strat };
    }

    void PerceptronClassifier::train(const std::vector<TrainingSample>& dataset,
                                     std::size_t epochs,
                                     double learning_rate)
    {
        if (dataset.empty()) return;

        std::vector<std::size_t> indices(dataset.size());
        for (std::size_t i = 0; i < indices.size(); ++i) indices[i] = i;
        std::mt19937_64 rng(1337);

        std::vector<double> h(hidden_size_);
        std::vector<double> dh(hidden_size_);

        for (std::size_t epoch = 0; epoch < epochs; ++epoch)
        {
            std::shuffle(indices.begin(), indices.end(), rng);

            for (std::size_t idx : indices)
            {
                const auto& sample = dataset[idx];
                const auto& x = sample.features;
                const std::size_t target = static_cast<std::size_t>(sample.label);

                // 1. Forward pass
                for (std::size_t i = 0; i < hidden_size_; ++i)
                {
                    double sum = b1_[i];
                    const std::size_t row = i * FEATURE_COUNT;
                    for (std::size_t j = 0; j < FEATURE_COUNT; ++j)
                        sum += w1_[row + j] * x[j];
                    h[i] = std::tanh(sum);
                }

                std::array<double, FILE_TYPE_COUNT> probs{};
                double max_l = -1e30;
                for (std::size_t c = 0; c < FILE_TYPE_COUNT; ++c)
                {
                    double sum = b2_[c];
                    const std::size_t row = c * hidden_size_;
                    for (std::size_t i = 0; i < hidden_size_; ++i)
                        sum += w2_[row + i] * h[i];
                    probs[c] = sum;
                    max_l = std::max(max_l, sum);
                }

                double exp_sum = 0.0;
                for (std::size_t c = 0; c < FILE_TYPE_COUNT; ++c)
                {
                    probs[c] = std::exp(probs[c] - max_l);
                    exp_sum += probs[c];
                }
                for (double& p : probs) p /= exp_sum;

                // 2. Backward pass (градієнт Cross-Entropy + Softmax)
                std::array<double, FILE_TYPE_COUNT> dlogits = probs;
                dlogits[target] -= 1.0;

                std::fill(dh.begin(), dh.end(), 0.0);

                for (std::size_t c = 0; c < FILE_TYPE_COUNT; ++c)
                {
                    const double dl = dlogits[c];
                    const std::size_t row = c * hidden_size_;
                    for (std::size_t i = 0; i < hidden_size_; ++i)
                    {
                        dh[i] += dl * w2_[row + i];
                        w2_[row + i] -= learning_rate * dl * h[i];
                    }
                    b2_[c] -= learning_rate * dl;
                }

                for (std::size_t i = 0; i < hidden_size_; ++i)
                {
                    const double d_raw = dh[i] * (1.0 - h[i] * h[i]); // похідна tanh
                    const std::size_t row = i * FEATURE_COUNT;
                    for (std::size_t j = 0; j < FEATURE_COUNT; ++j)
                        w1_[row + j] -= learning_rate * d_raw * x[j];
                    b1_[i] -= learning_rate * d_raw;
                }
            }
        }
    }

    void PerceptronClassifier::save_weights(const std::string& path) const
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) throw Error(ErrorCode::Io, "Cannot save perceptron weights: " + path);

        const std::uint32_t magic = 0x50435031u; // "PCP1"
        const std::uint32_t h_sz = static_cast<std::uint32_t>(hidden_size_);
        out.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
        out.write(reinterpret_cast<const char*>(&h_sz), sizeof(h_sz));

        auto write_vec = [&](const std::vector<double>& v) {
            out.write(reinterpret_cast<const char*>(v.data()),
                      static_cast<std::streamsize>(v.size() * sizeof(double)));
        };
        write_vec(w1_);
        write_vec(b1_);
        write_vec(w2_);
        write_vec(b2_);
    }

    void PerceptronClassifier::load_weights(const std::string& path)
    {
        std::ifstream in(path, std::ios::binary);
        if (!in) throw Error(ErrorCode::Io, "Cannot load perceptron weights: " + path);

        std::uint32_t magic = 0, h_sz = 0;
        in.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        in.read(reinterpret_cast<char*>(&h_sz), sizeof(h_sz));
        if (!in || magic != 0x50435031u || h_sz == 0)
            throw Error(ErrorCode::Payload, "Invalid perceptron weights file");

        hidden_size_ = h_sz;
        w1_.resize(hidden_size_ * FEATURE_COUNT);
        b1_.resize(hidden_size_);
        w2_.resize(FILE_TYPE_COUNT * hidden_size_);
        b2_.resize(FILE_TYPE_COUNT);

        auto read_vec = [&](std::vector<double>& v) {
            in.read(reinterpret_cast<char*>(v.data()),
                    static_cast<std::streamsize>(v.size() * sizeof(double)));
        };
        read_vec(w1_);
        read_vec(b1_);
        read_vec(w2_);
        read_vec(b2_);
        if (!in) throw Error(ErrorCode::Payload, "Truncated perceptron weights file");
    }
}