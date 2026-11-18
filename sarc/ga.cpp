#include "ga.hpp"
#include "archive_reader.hpp"
#include "random.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <map>
#include <memory>
#include <random>
#include <stdexcept>

namespace fs = std::filesystem;

namespace sarc
{
    namespace
    {
        using Rng = std::mt19937_64;

        double quantize(double x)
        {
            return std::round(x * 100.0) / 100.0;   // keeps logs readable, raises cache hits
        }

        double unit(Rng& rng)
        {
            return std::uniform_real_distribution<double>(0.0, 1.0)(rng);
        }

        Genome random_genome(Rng& rng)
        {
            const double lo = std::log2(static_cast<double>(GENE_WINDOW_MIN));
            const double hi = std::log2(static_cast<double>(GENE_WINDOW_MAX));

            Genome g;
            g.window = static_cast<std::uint32_t>(std::llround(std::exp2(lo + unit(rng) * (hi - lo))));
            g.min_match = GENE_MIN_MATCH_MIN +
                static_cast<std::uint32_t>(rng() % (GENE_MIN_MATCH_MAX - GENE_MIN_MATCH_MIN + 1));
            g.store_threshold = GENE_THRESHOLD_MIN + unit(rng) * (GENE_THRESHOLD_MAX - GENE_THRESHOLD_MIN);
            return clamp_genome(g);
        }

        // Uniform crossover: every gene comes from one of the two parents.
        Genome crossover(const Genome& a, const Genome& b, double rate, Rng& rng)
        {
            Genome child = a;

            if (unit(rng) < rate)
            {
                if (unit(rng) < 0.5) child.window = b.window;
                if (unit(rng) < 0.5) child.min_match = b.min_match;
                if (unit(rng) < 0.5) child.store_threshold = b.store_threshold;
            }

            return child;
        }

        void mutate(Genome& g, double rate, Rng& rng)
        {
            std::normal_distribution<double> gauss(0.0, 1.0);

            if (unit(rng) < rate)   // multiplicative step: the window is a scale-like gene
                g.window = static_cast<std::uint32_t>(
                    std::llround(static_cast<double>(g.window) * std::exp2(gauss(rng))));

            if (unit(rng) < rate)
            {
                const int step = (rng() & 1) ? 1 : -1;
                const int m = static_cast<int>(g.min_match) + step;
                g.min_match = static_cast<std::uint32_t>(std::max(m, 0));
            }

            if (unit(rng) < rate)
                g.store_threshold += 0.25 * gauss(rng);

            g = clamp_genome(g);
        }

        struct Individual
        {
            Genome genome;
            double fitness = 0.0;
        };

        std::size_t tournament(const std::vector<Individual>& pop, std::size_t size, Rng& rng)
        {
            std::size_t best = rng() % pop.size();

            for (std::size_t i = 1; i < size; ++i)
            {
                const std::size_t c = rng() % pop.size();

                if (pop[c].fitness > pop[best].fitness)
                    best = c;
            }

            return best;
        }

        bool same_content(const fs::path& a, const fs::path& b)
        {
            std::ifstream fa(a, std::ios::binary), fb(b, std::ios::binary);

            if (!fa || !fb)
                return false;

            std::vector<char> ba(64 * 1024), bb(64 * 1024);

            for (;;)
            {
                fa.read(ba.data(), static_cast<std::streamsize>(ba.size()));
                fb.read(bb.data(), static_cast<std::streamsize>(bb.size()));

                if (fa.gcount() != fb.gcount())
                    return false;

                if (fa.gcount() == 0)
                    return true;

                if (!std::equal(ba.begin(), ba.begin() + fa.gcount(), bb.begin()))
                    return false;
            }
        }
    }

    Genome clamp_genome(Genome g)
    {
        g.window = std::clamp(g.window, GENE_WINDOW_MIN, GENE_WINDOW_MAX);
        g.min_match = std::clamp(g.min_match, GENE_MIN_MATCH_MIN, GENE_MIN_MATCH_MAX);
        g.store_threshold = quantize(std::clamp(g.store_threshold, GENE_THRESHOLD_MIN, GENE_THRESHOLD_MAX));
        return g;
    }

    GaResult run_ga(const GaConfig& config, const FitnessFn& fitness)
    {
        if (config.population < 2)
            throw std::invalid_argument("GA: population must be at least 2");

        if (config.elites >= config.population)
            throw std::invalid_argument("GA: elites must be smaller than the population");

        if (config.tournament < 1)
            throw std::invalid_argument("GA: tournament size must be at least 1");

        Rng rng(config.seed);

        // A genome is measured once; elites and repeated children reuse the value.
        // This is also what keeps the elitism guarantee exact with a noisy
        // (timing based) fitness.
        std::map<Genome, double> cache;
        std::size_t evaluations = 0;

        auto evaluate = [&](const Genome& g)
        {
            const auto it = cache.find(g);

            if (it != cache.end())
                return it->second;

            const double f = fitness(g);
            ++evaluations;
            cache.emplace(g, f);
            return f;
        };

        GaResult result;
        std::vector<Individual> pop;

        for (std::size_t i = 0; i < config.population; ++i)
        {
            const Genome g = random_genome(rng);
            pop.push_back({ g, evaluate(g) });
        }

        bool have_best = false;

        auto record = [&](std::size_t generation)
        {
            GenerationStats st;
            st.generation = generation;
            st.evaluations = evaluations;
            st.best = pop.front().fitness;
            st.worst = pop.front().fitness;
            st.best_genome = pop.front().genome;
            double sum = 0.0;

            for (const auto& ind : pop)
            {
                sum += ind.fitness;
                st.worst = std::min(st.worst, ind.fitness);

                if (ind.fitness > st.best)
                {
                    st.best = ind.fitness;
                    st.best_genome = ind.genome;
                }
            }

            st.mean = sum / static_cast<double>(pop.size());

            if (!have_best || st.best > result.best_fitness)
            {
                result.best = st.best_genome;
                result.best_fitness = st.best;
                have_best = true;
            }

            result.history.push_back(st);
        };

        record(0);

        for (std::size_t gen = 1; gen <= config.generations; ++gen)
        {
            std::stable_sort(pop.begin(), pop.end(),
                [](const Individual& a, const Individual& b) { return a.fitness > b.fitness; });

            std::vector<Individual> next(pop.begin(), pop.begin() + static_cast<std::ptrdiff_t>(config.elites));

            while (next.size() < config.population)
            {
                const Genome& a = pop[tournament(pop, config.tournament, rng)].genome;
                const Genome& b = pop[tournament(pop, config.tournament, rng)].genome;

                Genome child = crossover(a, b, config.crossover_rate, rng);
                mutate(child, config.mutation_rate, rng);
                next.push_back({ child, evaluate(child) });
            }

            pop = std::move(next);
            record(gen);
        }

        result.evaluations = evaluations;
        return result;
    }

    RandomSearchResult run_random_search(const GaConfig& config, const FitnessFn& fitness,
                                         std::size_t evaluations)
    {
        Rng rng(config.seed ^ 0x9E3779B97F4A7C15ull);

        RandomSearchResult result;
        result.best_so_far.reserve(evaluations);

        for (std::size_t i = 0; i < evaluations; ++i)
        {
            const Genome g = random_genome(rng);
            const double f = fitness(g);

            if (i == 0 || f > result.best_fitness)
            {
                result.best = g;
                result.best_fitness = f;
            }

            result.best_so_far.push_back(result.best_fitness);
        }

        return result;
    }

    PackOptions genome_to_options(const Genome& genome, const PackOptions& base)
    {
        const Genome g = clamp_genome(genome);

        PackOptions o = base;
        o.codec.window_size = g.window;
        o.codec.min_match = g.min_match;
        o.classifier = std::make_shared<EntropyClassifier>(g.store_threshold);
        return o;
    }

    ArchiveEvaluator::ArchiveEvaluator(std::vector<std::string> files, PackOptions base, MetricParams metric)
        : files_(std::move(files)), base_(std::move(base)), metric_(metric),
          dir_(fs::temp_directory_path() / ("sarc-ga-" + random_hex(6)))
    {
        fs::create_directories(dir_);
    }

    ArchiveEvaluator::~ArchiveEvaluator()
    {
        std::error_code ec;
        fs::remove_all(dir_, ec);
    }

    Evaluation ArchiveEvaluator::measure(const Genome& genome)
    {
        using clock = std::chrono::steady_clock;

        const PackOptions options = genome_to_options(genome, base_);
        const std::string archive = (dir_ / ("a" + std::to_string(counter_) + ".sarc")).string();
        const fs::path out = dir_ / ("o" + std::to_string(counter_));
        ++counter_;

        Evaluation e;
        PackReport report;
        bool exact = true;
        double seconds = 0.0;

        try
        {
            const auto t0 = clock::now();
            report = create_archive(archive, files_, options);
            extract_archive(report.volume_paths, out.string(), options.password);
            seconds = std::chrono::duration<double>(clock::now() - t0).count();

            for (const auto& f : files_)
            {
                if (!same_content(f, out / fs::path(f).filename()))
                    exact = false;
            }
        }
        catch (const std::exception&)
        {
            exact = false;
        }

        std::error_code ec;
        fs::remove_all(out, ec);

        for (const auto& p : report.volume_paths)
            fs::remove(p, ec);

        const double raw = static_cast<double>(report.raw_bytes);
        const double arc = static_cast<double>(report.archive_bytes);

        e.exact = exact;
        e.seconds = seconds;
        e.archive_bytes = report.archive_bytes;
        e.s = (raw + arc) > 0.0 ? raw / (raw + arc) : 0.0;
        e.t = metric_.t_ref / (metric_.t_ref + seconds);
        e.q = exact ? metric_.alpha * e.s + metric_.beta * e.t : 0.0;
        return e;
    }
}
