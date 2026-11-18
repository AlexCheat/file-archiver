#include "aes256.hpp"
#include "archive_format.hpp"
#include "archive_reader.hpp"
#include "archive_writer.hpp"
#include "errors.hpp"
#include "ga.hpp"
#include "random.hpp"
#include "sarc_codec.hpp"
#include "classifier.hpp" // Підключення класифікатора та перцептрона

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace
{
    struct Args
    {
        std::vector<std::string> positional;
        std::string password;
        bool has_password = false;
        std::string password_env;
        std::uint64_t volume_size = 0;
        std::uint32_t block_size = sarc::DEFAULT_BLOCK_SIZE;
        std::string strategy = "lazy";
        std::size_t max_chain = 256;
        bool greedy_pack = false;
        bool no_classifier = false;   // ablation: always try to compress
        bool store_only = false;      // ablation: never compress
        double alpha = 0.5;           // real values come from team_config.json
        double beta = 0.5;
        double t_ref = 1.0;
        // MLP параметри
        std::string mlp_weights;
        std::size_t epochs = 100;
        double learning_rate = 0.05;
        // genetic algorithm ('ga' command)
        std::size_t pop = 12;
        std::size_t gens = 8;
        std::size_t elites = 2;
        std::size_t tournament = 3;
        double crossover = 0.9;
        double mutation = 0.25;
        std::uint64_t seed = 1;
        std::size_t repeats = 1;
        std::string log_path = "ga_log.csv";
    };

    // Ablation helper for the "impact of each block" table.
    class FixedClassifier : public sarc::FileClassifier
    {
    public:
        explicit FixedClassifier(sarc::Strategy strategy) : strategy_(strategy) {}

        sarc::Classification classify(const std::uint8_t*, std::size_t) const override
        {
            sarc::Classification c;
            c.type = sarc::FileType::Text;
            c.strategy = strategy_;
            return c;
        }

    private:
        sarc::Strategy strategy_;
    };

    void print_usage()
    {
        std::cout
            << "Smart Archiver\n\n"
            << "Commands:\n"
            << "  sarc pack <archive.sarc> [files...] [options]\n"
            << "  sarc list <volume...> [options]\n"
            << "  sarc extract <output-folder> <volume...> [options]\n"
            << "  sarc bench <files-or-folders...> [options]\n"
            << "  sarc order <files-or-folders...> [options]   compress->encrypt vs encrypt->compress\n"
            << "  sarc ga <files-or-folders...> [options]      genetic algorithm vs random search\n"
            << "  sarc train <files-or-folders...> --weights <file.bin> [options]  train Perceptron classifier\n\n"
            << "Options:\n"
            << "  -p <password>            password (visible in the process list!)\n"
            << "  --password-env <NAME>    read the password from an environment variable\n"
            << "                           (if neither is given, it is asked on stdin)\n"
            << "  --volume-size <bytes>    split into volumes of at most this size\n"
            << "  --block-size <bytes>     block size (default 65536)\n"
            << "  --strategy greedy|lazy   LZ77 parsing (default lazy)\n"
            << "  --max-chain <n>          LZ77 match search depth (default 256)\n"
            << "  --greedy-pack            greedy volume packing instead of knapsack DP\n"
            << "  --no-classifier          ablation: skip the classifier, always try to compress\n"
            << "  --store-only             ablation: no compression at all\n"
            << "  --mlp-weights <path>     path to perceptron weights binary file\n"
            << "  --epochs <n>             training epochs for 'train' (default 100)\n"
            << "  --lr <val>               learning rate for 'train' (default 0.05)\n"
            << "  --alpha --beta --tref    metric Q parameters for 'bench' and 'ga'\n"
            << "  GA: --pop N --gens N --elites N --tournament N --crossover P --mutation P\n"
            << "      --seed N --repeats N --log <file.csv>   (the GA tunes window, min match, store threshold)\n";
    }

    std::uint64_t parse_number(const std::string& text, const char* what)
    {
        try
        {
            std::size_t used = 0;
            const unsigned long long v = std::stoull(text, &used);

            if (used != text.size())
                throw std::invalid_argument("trailing characters");

            return v;
        }
        catch (const std::exception&)
        {
            throw std::runtime_error(std::string("Invalid value for ") + what + ": " + text);
        }
    }

    double parse_double(const std::string& text, const char* what)
    {
        try
        {
            std::size_t used = 0;
            const double v = std::stod(text, &used);

            if (used != text.size())
                throw std::invalid_argument("trailing characters");

            return v;
        }
        catch (const std::exception&)
        {
            throw std::runtime_error(std::string("Invalid value for ") + what + ": " + text);
        }
    }

    Args parse_args(int argc, char* argv[], int first)
    {
        Args a;

        auto need = [&](int& i, const char* name) -> std::string
        {
            if (i + 1 >= argc)
                throw std::runtime_error(std::string("Missing value for ") + name);

            return argv[++i];
        };

        for (int i = first; i < argc; ++i)
        {
            const std::string arg = argv[i];

            if (arg == "-p")
            {
                a.password = need(i, "-p");
                a.has_password = true;
            }
            else if (arg == "--password-env") a.password_env = need(i, arg.c_str());
            else if (arg == "--volume-size")  a.volume_size = parse_number(need(i, arg.c_str()), "--volume-size");
            else if (arg == "--block-size")   a.block_size = static_cast<std::uint32_t>(parse_number(need(i, arg.c_str()), "--block-size"));
            else if (arg == "--strategy")     a.strategy = need(i, arg.c_str());
            else if (arg == "--max-chain")    a.max_chain = static_cast<std::size_t>(parse_number(need(i, arg.c_str()), "--max-chain"));
            else if (arg == "--greedy-pack")  a.greedy_pack = true;
            else if (arg == "--no-classifier") a.no_classifier = true;
            else if (arg == "--store-only")   a.store_only = true;
            else if (arg == "--mlp-weights")  a.mlp_weights = need(i, arg.c_str());
            else if (arg == "--epochs")       a.epochs = static_cast<std::size_t>(parse_number(need(i, arg.c_str()), "--epochs"));
            else if (arg == "--lr")           a.learning_rate = parse_double(need(i, arg.c_str()), "--lr");
            else if (arg == "--pop")          a.pop = static_cast<std::size_t>(parse_number(need(i, arg.c_str()), "--pop"));
            else if (arg == "--gens")         a.gens = static_cast<std::size_t>(parse_number(need(i, arg.c_str()), "--gens"));
            else if (arg == "--elites")       a.elites = static_cast<std::size_t>(parse_number(need(i, arg.c_str()), "--elites"));
            else if (arg == "--tournament")   a.tournament = static_cast<std::size_t>(parse_number(need(i, arg.c_str()), "--tournament"));
            else if (arg == "--crossover")    a.crossover = parse_double(need(i, arg.c_str()), "--crossover");
            else if (arg == "--mutation")     a.mutation = parse_double(need(i, arg.c_str()), "--mutation");
            else if (arg == "--seed")         a.seed = parse_number(need(i, arg.c_str()), "--seed");
            else if (arg == "--repeats")      a.repeats = static_cast<std::size_t>(parse_number(need(i, arg.c_str()), "--repeats"));
            else if (arg == "--log")          a.log_path = need(i, arg.c_str());
            else if (arg == "--alpha")        a.alpha = parse_double(need(i, arg.c_str()), "--alpha");
            else if (arg == "--beta")         a.beta = parse_double(need(i, arg.c_str()), "--beta");
            else if (arg == "--tref")         a.t_ref = parse_double(need(i, arg.c_str()), "--tref");
            else if (arg.size() > 1 && arg[0] == '-' && arg != "-")
                throw std::runtime_error("Unknown option: " + arg);
            else
                a.positional.push_back(arg);
        }

        return a;
    }

    std::string get_password(const Args& a)
    {
        std::string password;

        if (a.has_password)
        {
            password = a.password;
        }
        else if (!a.password_env.empty())
        {
            const char* value = std::getenv(a.password_env.c_str());

            if (!value)
                throw std::runtime_error("Environment variable is not set: " + a.password_env);

            password = value;
        }
        else
        {
            std::cerr << "Password: ";
            std::getline(std::cin, password);
        }

        if (password.empty())
            throw std::runtime_error("Password must not be empty");

        return password;
    }

    sarc::CodecOptions make_codec(const Args& a)
    {
        sarc::CodecOptions c;
        c.max_chain = a.max_chain;

        if (a.strategy == "greedy")
            c.strategy = sarc::ParseStrategy::Greedy;
        else if (a.strategy == "lazy")
            c.strategy = sarc::ParseStrategy::Lazy;
        else
            throw std::runtime_error("Unknown strategy: " + a.strategy);

        return c;
    }

    sarc::PackOptions make_options(const Args& a, const std::string& password)
    {
        sarc::PackOptions o;
        o.password = password;
        o.max_volume_bytes = a.volume_size;
        o.block_size = a.block_size;
        o.codec = make_codec(a);

        if (a.greedy_pack)
            o.packer = sarc::PackerKind::Greedy;

        // Підключення перцептрона та завантаження ваг, якщо вказано файл
        auto mlp = std::make_shared<sarc::PerceptronClassifier>(32);
        if (!a.mlp_weights.empty() && fs::exists(a.mlp_weights)) {
            mlp->load_weights(a.mlp_weights);
        }
        o.classifier = mlp;

        if (a.store_only)
            o.classifier = std::make_shared<FixedClassifier>(sarc::Strategy::Store);
        else if (a.no_classifier)
            o.classifier = std::make_shared<FixedClassifier>(sarc::Strategy::Compress);

        return o;
    }

    std::vector<std::string> collect_files(const std::vector<std::string>& inputs)
    {
        std::vector<std::string> files;

        for (const auto& p : inputs)
        {
            if (fs::is_directory(p))
            {
                for (const auto& e : fs::recursive_directory_iterator(p))
                    if (e.is_regular_file())
                        files.push_back(e.path().string());
            }
            else
            {
                files.push_back(p);
            }
        }

        std::sort(files.begin(), files.end());
        return files;
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

    // Автовизначення типу файлу за розширенням для навчання перцептрона
    sarc::FileType guess_file_type(const fs::path& path)
    {
        std::string ext = path.extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

        if (ext == ".txt" || ext == ".md" || ext == ".log") return sarc::FileType::Text;
        if (ext == ".cpp" || ext == ".hpp" || ext == ".h" || ext == ".c" || ext == ".py" || ext == ".js") return sarc::FileType::Code;
        if (ext == ".csv" || ext == ".json") return sarc::FileType::Structured;
        if (ext == ".bmp" || ext == ".pgm" || ext == ".png") return sarc::FileType::Raster;
        if (ext == ".exe" || ext == ".so" || ext == ".dll") return sarc::FileType::Executable;
        if (ext == ".jpg" || ext == ".mp3" || ext == ".zip" || ext == ".gz") return sarc::FileType::Compressed;
        return sarc::FileType::Artificial;
    }

    // Реалізація команди навчання перцептрона: sarc train <files...> --weights weights.bin
    void run_train(const Args& a)
    {
        if (a.mlp_weights.empty())
            throw std::runtime_error("train: --weights <path> is required");

        const std::vector<std::string> files = collect_files(a.positional);
        if (files.empty())
            throw std::runtime_error("train: no input files provided for training");

        std::vector<sarc::PerceptronClassifier::TrainingSample> dataset;
        dataset.reserve(files.size());

        std::cout << "Extracting features from " << files.size() << " file(s)...\n";
        for (const auto& filepath : files)
        {
            std::ifstream f(filepath, std::ios::binary);
            if (!f) continue;
            std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            if (data.empty()) continue;

            sarc::FeatureVector features = sarc::extract_features(data.data(), data.size());
            sarc::FileType label = guess_file_type(filepath);

            dataset.push_back({features, label});
        }

        if (dataset.empty())
            throw std::runtime_error("train: dataset is empty (no valid readable files)");

        std::cout << "Training Perceptron (epochs: " << a.epochs << ", lr: " << a.learning_rate << ")...\n";
        sarc::PerceptronClassifier mlp(32);
        mlp.train(dataset, a.epochs, a.learning_rate);

        mlp.save_weights(a.mlp_weights);
        std::cout << "Training completed successfully! Weights saved to " << a.mlp_weights << '\n';
    }

    // Q = alpha * S + beta * T, S = B_orig / (B_orig + B_arc),
    // T = t_ref / (t_ref + t); Q = 0 if any file is not restored byte-exact.
    void run_bench(const Args& a)
    {
        const std::vector<std::string> files = collect_files(a.positional);

        if (files.empty())
            throw std::runtime_error("bench: no input files");

        struct Cleanup
        {
            fs::path dir;
            ~Cleanup() { std::error_code ec; fs::remove_all(dir, ec); }
        } cleanup{ fs::temp_directory_path() / ("sarc-bench-" + sarc::random_hex(6)) };

        fs::create_directories(cleanup.dir);

        const sarc::PackOptions options = make_options(a, get_password(a));
        const std::string archive = (cleanup.dir / "bench.sarc").string();
        const fs::path out = cleanup.dir / "out";

        using clock = std::chrono::steady_clock;

        bool exact = true;
        sarc::PackReport report;
        const auto t0 = clock::now();
        auto t1 = t0, t2 = t0;

        // An archiver that fails to restore its own data scores Q = 0.
        try
        {
            report = sarc::create_archive(archive, files, options);
            t1 = clock::now();
            sarc::extract_archive(report.volume_paths, out.string(), options.password);
            t2 = clock::now();

            for (const auto& f : files)
            {
                if (!same_content(f, out / fs::path(f).filename()))
                {
                    std::cerr << "MISMATCH: " << f << '\n';
                    exact = false;
                }
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << "bench failed: " << e.what() << '\n';
            exact = false;
            t2 = clock::now();

            if (t1 == t0)
                t1 = t2;
        }

        const double seconds = std::chrono::duration<double>(t2 - t0).count();
        const double raw = static_cast<double>(report.raw_bytes);
        const double arc = static_cast<double>(report.archive_bytes);
        const double S = (raw + arc) > 0 ? raw / (raw + arc) : 0.0;
        const double T = a.t_ref / (a.t_ref + seconds);
        const double Q = exact ? a.alpha * S + a.beta * T : 0.0;

        std::cout << std::fixed << std::setprecision(4)
            << "files            : " << report.files << '\n'
            << "original bytes   : " << report.raw_bytes << '\n'
            << "archive bytes    : " << report.archive_bytes
            << "  (volumes: " << report.volume_paths.size() << ")\n"
            << "ratio arc/orig   : " << (raw > 0 ? arc / raw : 0.0) << '\n'
            << "blocks stored    : " << report.blocks_stored << " / " << report.blocks_total << '\n'
            << "overhead bytes   : " << report.overhead_bytes() << '\n'
            << "pack time, s     : " << std::chrono::duration<double>(t1 - t0).count() << '\n'
            << "unpack time, s   : " << std::chrono::duration<double>(t2 - t1).count() << '\n'
            << "byte-exact       : " << (exact ? "yes" : "NO") << '\n'
            << "S = " << S << "  T = " << T << "  Q = " << Q
            << "  (alpha=" << a.alpha << ", beta=" << a.beta << ", t_ref=" << a.t_ref << ")\n";
    }

    // Report table 5: fitness (= Q on the corpus) by generation against random
    // search that gets exactly the same number of fitness evaluations.
    void run_ga_command(const Args& a)
    {
        const std::vector<std::string> files = collect_files(a.positional);

        if (files.empty())
            throw std::runtime_error("ga: no input files");

        if (a.repeats == 0)
            throw std::runtime_error("ga: --repeats must be at least 1");

        const sarc::PackOptions base = make_options(a, get_password(a));
        const sarc::MetricParams metric{ a.alpha, a.beta, a.t_ref };
        const auto evaluator = std::make_shared<sarc::ArchiveEvaluator>(files, base, metric);
        const sarc::FitnessFn fitness = [evaluator](const sarc::Genome& g) { return evaluator->measure(g).q; };

        sarc::GaConfig cfg;
        cfg.population = a.pop;
        cfg.generations = a.gens;
        cfg.elites = a.elites;
        cfg.tournament = a.tournament;
        cfg.crossover_rate = a.crossover;
        cfg.mutation_rate = a.mutation;

        std::ofstream log(a.log_path, std::ios::trunc);

        if (!log)
            throw std::runtime_error("Cannot write the GA log: " + a.log_path);

        log << "run,method,generation,evaluations,best,mean,worst,window,min_match,store_threshold\n";

        const sarc::Evaluation def = evaluator->measure(sarc::Genome{});

        std::cout << std::fixed << std::setprecision(4)
            << "corpus: " << files.size() << " file(s); metric alpha=" << a.alpha << " beta=" << a.beta
            << " t_ref=" << a.t_ref << "\n"
            << "default genes (window 32768, min match 3, threshold 7.50): Q = " << def.q
            << "  (S = " << def.s << ", T = " << def.t << ", " << def.archive_bytes << " bytes)\n"
            << "population " << a.pop << ", generations " << a.gens << ", elites " << a.elites
            << ", tournament " << a.tournament << ", crossover " << a.crossover
            << ", mutation " << a.mutation << " per gene\n";

        double ga_final = 0.0, random_final = 0.0;
        bool elitism_ok = true;

        for (std::size_t run = 0; run < a.repeats; ++run)
        {
            cfg.seed = a.seed + run;

            const sarc::GaResult ga = sarc::run_ga(cfg, fitness);
            const sarc::RandomSearchResult rnd = sarc::run_random_search(cfg, fitness, ga.evaluations);

            std::cout << "\nrun " << run + 1 << " (seed " << cfg.seed << "), "
                      << ga.evaluations << " fitness evaluations for each method\n"
                      << "gen  evals  GA best  GA mean  GA worst  random best  best genes (window, min match, threshold)\n";

            for (const auto& st : ga.history)
            {
                const std::size_t at = std::min<std::size_t>(st.evaluations, rnd.best_so_far.size());
                const double random_best = at ? rnd.best_so_far[at - 1] : 0.0;

                std::cout << std::setw(3) << st.generation << std::setw(7) << st.evaluations
                          << std::setw(10) << st.best << std::setw(9) << st.mean << std::setw(10) << st.worst
                          << std::setw(13) << random_best << "  "
                          << st.best_genome.window << ", " << st.best_genome.min_match << ", "
                          << std::setprecision(2) << st.best_genome.store_threshold << std::setprecision(4) << '\n';

                log << run + 1 << ",ga," << st.generation << ',' << st.evaluations << ','
                    << st.best << ',' << st.mean << ',' << st.worst << ','
                    << st.best_genome.window << ',' << st.best_genome.min_match << ','
                    << st.best_genome.store_threshold << '\n';
                log << run + 1 << ",random," << st.generation << ',' << at << ',' << random_best
                    << ",,,,,\n";
            }

            const bool ok = ga.history.back().best >= ga.history.front().best;
            elitism_ok = elitism_ok && ok;

            std::cout << "elitism check: best of the last generation " << ga.history.back().best
                      << (ok ? " >= " : " < ") << "best of generation 0 " << ga.history.front().best
                      << (ok ? "  OK\n" : "  FAILED\n")
                      << "GA best " << ga.best_fitness << " at (" << ga.best.window << ", "
                      << ga.best.min_match << ", " << std::setprecision(2) << ga.best.store_threshold
                      << std::setprecision(4) << "); random best " << rnd.best_fitness
                      << " at (" << rnd.best.window << ", " << rnd.best.min_match << ", "
                      << std::setprecision(2) << rnd.best.store_threshold << std::setprecision(4) << ")\n";

            ga_final += ga.best_fitness;
            random_final += rnd.best_fitness;
        }

        const double n = static_cast<double>(a.repeats);

        std::cout << "\nmean over " << a.repeats << " run(s): GA " << ga_final / n
                  << ", random search " << random_final / n
                  << ", default genes " << def.q << "\n"
                  << "log written to " << a.log_path << '\n';

        if (!elitism_ok)
            throw std::runtime_error("elitism check failed: the GA implementation is incorrect");
    }

    // Report table 4: "compress, then encrypt" (what the archiver does) against
    // "encrypt, then compress". AES-CTR keeps the length, so the first scheme
    // costs the compressed size, the second compresses ciphertext (noise).
    void run_order(const Args& a)
    {
        const std::vector<std::string> files = collect_files(a.positional);

        if (files.empty())
            throw std::runtime_error("order: no input files");

        const sarc::CodecOptions codec = make_codec(a);

        std::uint8_t key[sarc::KEY_SIZE], nonce[sarc::NONCE_SIZE];
        sarc::random_bytes(key, sizeof(key));
        sarc::random_bytes(nonce, sizeof(nonce));

        std::uint64_t raw = 0, compress_first = 0, encrypt_first = 0;
        std::vector<std::uint8_t> buffer;

        for (const auto& path : files)
        {
            std::ifstream in(path, std::ios::binary);

            if (!in)
                throw std::runtime_error("Cannot open input file: " + path);

            sarc::Aes256Ctr ctr(key, nonce);

            for (;;)
            {
                buffer.resize(a.block_size);
                in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
                const std::size_t got = static_cast<std::size_t>(in.gcount());

                if (got == 0)
                    break;

                buffer.resize(got);
                raw += got;

                // compress -> encrypt: the block keeps its coded size.
                compress_first += std::min(sarc::compress_block(buffer, codec).size(), got);

                // encrypt -> compress: the codec only sees ciphertext.
                ctr.crypt(buffer.data(), got);
                encrypt_first += std::min(sarc::compress_block(buffer, codec).size(), got);
            }
        }

        const double r = static_cast<double>(raw);

        std::cout << std::fixed << std::setprecision(4)
            << "original bytes            : " << raw << '\n'
            << "compress -> encrypt, bytes: " << compress_first
            << "  ratio " << (raw ? compress_first / r : 0.0) << '\n'
            << "encrypt -> compress, bytes: " << encrypt_first
            << "  ratio " << (raw ? encrypt_first / r : 0.0) << '\n'
            << "(coded sizes only, per block, never above the raw size; headers excluded)\n";
    }
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        print_usage();
        return 0;
    }

    const std::string command = argv[1];

    try
    {
        const Args args = parse_args(argc, argv, 2);

        if (command == "pack")
        {
            if (args.positional.empty())
                throw std::runtime_error("Usage: sarc pack <archive> [files...]");

            const std::vector<std::string> files(args.positional.begin() + 1, args.positional.end());
            const sarc::PackReport r = sarc::create_archive(
                args.positional[0], files, make_options(args, get_password(args)));

            std::cout << "Archive created: " << r.volume_paths.size() << " volume(s), "
                      << r.archive_bytes << " bytes from " << r.raw_bytes << " bytes\n";
        }
        else if (command == "list")
        {
            if (args.positional.empty())
                throw std::runtime_error("Usage: sarc list <volume...>");

            const auto entries = sarc::list_archive(args.positional, get_password(args));

            std::cout << "Archive contents:\n\n";

            for (const auto& e : entries)
                std::cout << e.name << " (" << e.size << " bytes)\n";
        }
        else if (command == "extract")
        {
            if (args.positional.size() < 2)
                throw std::runtime_error("Usage: sarc extract <output-folder> <volume...>");

            const std::vector<std::string> volumes(args.positional.begin() + 1, args.positional.end());
            sarc::extract_archive(volumes, args.positional[0], get_password(args));

            std::cout << "Extraction completed!\n";
        }
        else if (command == "bench")
        {
            run_bench(args);
        }
        else if (command == "order")
        {
            run_order(args);
        }
        else if (command == "ga")
        {
            run_ga_command(args);
        }
        else if (command == "train") // Додано обробку команди train
        {
            run_train(args);
        }
        else
        {
            throw std::runtime_error("Unknown command: " + command);
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}