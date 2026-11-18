#include "classifier.hpp"

#include <algorithm>
#include <cmath>
#include <vector>

namespace sarc
{
    double shannon_entropy(const std::uint8_t* data, std::size_t size)
    {
        if (size == 0)
            return 0.0;

        std::array<std::uint64_t, 256> counts{};

        for (std::size_t i = 0; i < size; ++i)
            ++counts[data[i]];

        double h = 0.0;

        for (auto c : counts)
        {
            if (c == 0)
                continue;

            const double p = static_cast<double>(c) / static_cast<double>(size);
            h -= p * std::log2(p);
        }

        return h;
    }

    FeatureVector extract_features(const std::uint8_t* data, std::size_t size)
    {
        FeatureVector f{};

        if (size == 0)
            return f;

        const double n = static_cast<double>(size);

        f[0] = shannon_entropy(data, size) / 8.0;

        std::array<std::uint64_t, 32> bins{};
        std::uint64_t printable = 0;

        for (std::size_t i = 0; i < size; ++i)
        {
            ++bins[data[i] >> 3];

            if ((data[i] >= 0x20 && data[i] <= 0x7E) ||
                data[i] == '\t' || data[i] == '\n' || data[i] == '\r')
                ++printable;
        }

        for (std::size_t b = 0; b < 32; ++b)
            f[1 + b] = static_cast<double>(bins[b]) / n;

        f[33] = static_cast<double>(printable) / n;

        // Mean distance between end-of-line characters.
        std::size_t last = 0, gaps = 0;
        double gap_sum = 0.0;
        bool seen = false;

        for (std::size_t i = 0; i < size; ++i)
        {
            if (data[i] != '\n')
                continue;

            if (seen)
            {
                gap_sum += static_cast<double>(i - last);
                ++gaps;
            }

            last = i;
            seen = true;
        }

        f[34] = gaps ? std::min(gap_sum / static_cast<double>(gaps), 1024.0) / 1024.0 : 0.0;

        // Autocorrelation (Pearson) on lags 1..16.
        double mean = 0.0;

        for (std::size_t i = 0; i < size; ++i)
            mean += data[i];

        mean /= n;

        double variance = 0.0;

        for (std::size_t i = 0; i < size; ++i)
        {
            const double d = data[i] - mean;
            variance += d * d;
        }

        for (std::size_t lag = 1; lag <= 16; ++lag)
        {
            double value = 0.0;

            if (variance <= 0.0)
            {
                value = 1.0;   // constant data is perfectly self-correlated
            }
            else if (size > lag)
            {
                double acc = 0.0;

                for (std::size_t i = 0; i + lag < size; ++i)
                    acc += (data[i] - mean) * (data[i + lag] - mean);

                value = acc / variance;
            }

            f[34 + lag] = value;
        }

        // Bigram entropy.
        if (size >= 2)
        {
            std::vector<std::uint32_t> pairs(65536, 0);

            for (std::size_t i = 0; i + 1 < size; ++i)
                ++pairs[(static_cast<std::size_t>(data[i]) << 8) | data[i + 1]];

            const double total = n - 1.0;
            double h = 0.0;

            for (auto c : pairs)
            {
                if (c == 0)
                    continue;

                const double p = c / total;
                h -= p * std::log2(p);
            }

            f[51] = h / 16.0;
        }

        return f;
    }

    Classification EntropyClassifier::classify(const std::uint8_t* data, std::size_t size) const
    {
        Classification c;

        if (size == 0)
        {
            c.type = FileType::Artificial;
            c.strategy = Strategy::Store;
            return c;
        }

        const double entropy = shannon_entropy(data, size);

        if (entropy < 0.01)
        {
            c.type = FileType::Artificial;   // constant data
            return c;
        }

        // Small samples under-estimate entropy, so only trust it on >= 512 bytes.
        if (size >= 512 && entropy >= threshold_)
        {
            c.type = FileType::Compressed;
            c.strategy = Strategy::Store;
            return c;
        }

        std::uint64_t printable = 0;

        for (std::size_t i = 0; i < size; ++i)
        {
            if ((data[i] >= 0x20 && data[i] <= 0x7E) ||
                data[i] == '\t' || data[i] == '\n' || data[i] == '\r')
                ++printable;
        }

        c.type = (static_cast<double>(printable) / static_cast<double>(size) >= 0.95)
            ? FileType::Text
            : FileType::Unknown;

        return c;
    }
}
