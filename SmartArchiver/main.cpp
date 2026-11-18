#include "archive_format.hpp"
#include "archive_reader.hpp"
#include "archive_writer.hpp"
#include "errors.hpp"
#include "random.hpp"

#include <chrono>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
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
        double alpha = 0.5;   // real values come from team_config.json
        double beta = 0.5;
        double t_ref = 1.0;
    };

    void print_usage()
    {
        std::cout
            << "Smart Archiver\n\n"
            << "Commands:\n"
            << "  sarc pack <archive.sarc> [files...] [options]\n"
            << "  sarc list <volume...> [options]\n"
            << "  sarc extract <output-folder> <volume...> [options]\n"
            << "  sarc bench <files-or-folders...> [options]\n\n"
            << "Options:\n"
            << "  -p <password>            password (visible in the process list!)\n"
            << "  --password-env <NAME>    read the password from an environment variable\n"
            << "                           (if neither is given, it is asked on stdin)\n"
            << "  --volume-size <bytes>    split into volumes of at most this size\n"
            << "  --block-size <bytes>     block size (default 65536)\n"
            << "  --strategy greedy|lazy   LZ77 parsing (default lazy)\n"
            << "  --max-chain <n>          LZ77 match search depth (default 256)\n"
            << "  --greedy-pack            greedy volume packing instead of knapsack DP\n"
            << "  --alpha --beta --tref    metric Q parameters for 'bench'\n";
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
            else if (arg == "--alpha")        a.alpha = std::stod(need(i, arg.c_str()));
            else if (arg == "--beta")         a.beta = std::stod(need(i, arg.c_str()));
            else if (arg == "--tref")         a.t_ref = std::stod(need(i, arg.c_str()));
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

    sarc::PackOptions make_options(const Args& a)
    {
        sarc::PackOptions o;
        o.password = get_password(a);
        o.max_volume_bytes = a.volume_size;
        o.block_size = a.block_size;
        o.codec.max_chain = a.max_chain;

        if (a.strategy == "greedy")
            o.codec.strategy = sarc::ParseStrategy::Greedy;
        else if (a.strategy == "lazy")
            o.codec.strategy = sarc::ParseStrategy::Lazy;
        else
            throw std::runtime_error("Unknown strategy: " + a.strategy);

        if (a.greedy_pack)
            o.packer = sarc::PackerKind::Greedy;

        return o;
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

    // Q = alpha * S + beta * T, S = B_orig / (B_orig + B_arc),
    // T = t_ref / (t_ref + t); Q = 0 if any file is not restored byte-exact.
    void run_bench(const Args& a)
    {
        std::vector<std::string> files;

        for (const auto& p : a.positional)
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

        if (files.empty())
            throw std::runtime_error("bench: no input files");

        struct Cleanup
        {
            fs::path dir;
            ~Cleanup() { std::error_code ec; fs::remove_all(dir, ec); }
        } cleanup{ fs::temp_directory_path() / ("sarc-bench-" + sarc::random_hex(6)) };

        fs::create_directories(cleanup.dir);

        sarc::PackOptions options = make_options(a);
        const std::string archive = (cleanup.dir / "bench.sarc").string();
        const fs::path out = cleanup.dir / "out";

        using clock = std::chrono::steady_clock;

        const auto t0 = clock::now();
        const sarc::PackReport report = sarc::create_archive(archive, files, options);
        const auto t1 = clock::now();
        sarc::extract_archive(report.volume_paths, out.string(), options.password);
        const auto t2 = clock::now();

        bool exact = true;

        for (const auto& f : files)
        {
            if (!same_content(f, out / fs::path(f).filename()))
            {
                std::cerr << "MISMATCH: " << f << '\n';
                exact = false;
            }
        }

        const double seconds = std::chrono::duration<double>(t2 - t0).count();
        const double raw = static_cast<double>(report.raw_bytes);
        const double arc = static_cast<double>(report.archive_bytes);
        const double S = raw / (raw + arc);
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
            const sarc::PackReport r = sarc::create_archive(args.positional[0], files, make_options(args));

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
