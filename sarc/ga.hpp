#pragma once

#include "archive_writer.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <tuple>
#include <vector>

// Genetic algorithm of the "Optimisation" zone (base level):
//   chromosome of three genes, tournament selection, one crossover type
//   (uniform), mutation, elitism, comparison with random search under the
//   same number of fitness evaluations.
// The core knows nothing about archives: it only needs a fitness function.

namespace sarc
{
    // ---- gene ranges ------------------------------------------------------
    constexpr std::uint32_t GENE_WINDOW_MIN = 256;
    constexpr std::uint32_t GENE_WINDOW_MAX = 32768;
    constexpr std::uint32_t GENE_MIN_MATCH_MIN = 3;
    constexpr std::uint32_t GENE_MIN_MATCH_MAX = 12;
    constexpr double GENE_THRESHOLD_MIN = 6.0;
    constexpr double GENE_THRESHOLD_MAX = 8.0;

    struct Genome
    {
        std::uint32_t window = 32768;     // LZ77 search window, bytes
        std::uint32_t min_match = 3;      // shortest match that becomes a reference
        double store_threshold = 7.5;     // entropy (bits/byte) above which a file is stored

        bool operator<(const Genome& o) const
        {
            return std::tie(window, min_match, store_threshold)
                 < std::tie(o.window, o.min_match, o.store_threshold);
        }

        bool operator==(const Genome& o) const
        {
            return window == o.window && min_match == o.min_match &&
                   store_threshold == o.store_threshold;
        }
    };

    struct GaConfig
    {
        std::size_t population = 12;
        std::size_t generations = 8;
        std::size_t elites = 2;           // copied unchanged into the next generation
        std::size_t tournament = 3;       // tournament size
        double crossover_rate = 0.9;
        double mutation_rate = 0.25;      // per gene
        std::uint64_t seed = 1;
    };

    struct GenerationStats
    {
        std::size_t generation = 0;
        std::size_t evaluations = 0;      // fitness calls so far (cache hits are free)
        double best = 0.0;
        double mean = 0.0;
        double worst = 0.0;
        Genome best_genome;
    };

    struct GaResult
    {
        std::vector<GenerationStats> history;   // history[0] is the initial population
        Genome best;                            // best genome ever evaluated
        double best_fitness = 0.0;
        std::size_t evaluations = 0;
    };

    struct RandomSearchResult
    {
        std::vector<double> best_so_far;        // after evaluation 1, 2, ...
        Genome best;
        double best_fitness = 0.0;
    };

    using FitnessFn = std::function<double(const Genome&)>;

    // Forces every gene into its range (the threshold is rounded to 0.01).
    Genome clamp_genome(Genome g);

    // Maximises `fitness`. With elites >= 1 the best value of every generation
    // is at least the best value of the previous one, so history.back().best
    // >= history.front().best (the correctness check required by the task).
    GaResult run_ga(const GaConfig& config, const FitnessFn& fitness);

    // Baseline: `evaluations` independent random genomes.
    RandomSearchResult run_random_search(const GaConfig& config, const FitnessFn& fitness,
                                         std::size_t evaluations);

    // ---- fitness on a real corpus: Q = alpha * S + beta * T ---------------
    struct MetricParams
    {
        double alpha = 0.5;
        double beta = 0.5;
        double t_ref = 1.0;
    };

    struct Evaluation
    {
        double q = 0.0;
        double s = 0.0;
        double t = 0.0;
        double seconds = 0.0;             // pack + unpack
        std::uint64_t archive_bytes = 0;
        bool exact = false;               // every file restored byte for byte
    };

    PackOptions genome_to_options(const Genome& genome, const PackOptions& base);

    // Packs and unpacks the corpus with the genome's parameters and returns
    // the metric. Q is 0 when anything fails or differs.
    class ArchiveEvaluator
    {
    public:
        ArchiveEvaluator(std::vector<std::string> files, PackOptions base, MetricParams metric);
        ~ArchiveEvaluator();

        ArchiveEvaluator(const ArchiveEvaluator&) = delete;
        ArchiveEvaluator& operator=(const ArchiveEvaluator&) = delete;

        Evaluation measure(const Genome& genome);

    private:
        std::vector<std::string> files_;
        PackOptions base_;
        MetricParams metric_;
        std::filesystem::path dir_;
        std::size_t counter_ = 0;
    };
}
