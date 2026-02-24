#include <sodium.h>
#include <stdexcept>
#include <vector>
#include <string>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <cmath>
#include <cstdlib>
#include <thread>
#include <sstream>
#include "logger.hpp"
#include "protoss_protocol.hpp"

static double calc_mean(const std::vector<double> &values)
{
    double sum = 0.0;
    for (double v : values)
        sum += v;
    return sum / values.size();
}

static double calc_stddev(const std::vector<double> &values)
{
    if (values.size() < 2)
        return 0.0;
    double m = calc_mean(values);
    double sum_sq = 0.0;
    for (double v : values)
    {
        double diff = v - m;
        sum_sq += diff * diff;
    }
    return std::sqrt(sum_sq / (values.size() - 1));
}

// Returns true on success, storing per-run averages in out parameters.
bool run_benchmark(int iterations, int run_id, bool is_warmup,
                   double &out_init_ms, double &out_rspder_ms, double &out_der_ms)
{
    if (is_warmup)
        std::cout << "Warmup: Running Protoss protocol benchmark with " << iterations << " iterations..." << std::endl;
    else
        std::cout << "Run " << run_id << ": Running Protoss protocol benchmark with " << iterations << " iterations..." << std::endl;

    // Configure test params
    std::string password = "SharedPassword";
    std::vector<unsigned char> P_i = {0x00};
    std::vector<unsigned char> P_j = {0x01};

    // Initialize timing variables
    auto init_time = std::chrono::duration<double>::zero();
    auto rspder_time = std::chrono::duration<double>::zero();
    auto der_time = std::chrono::duration<double>::zero();

    // Run the test multiple times to calculate average times
    for (int i = 0; i < iterations; i++)
    {
        try
        {
            // Time Init step
            auto start = std::chrono::high_resolution_clock::now();
            ReturnTypeInit res_init = Init(password, P_i, P_j);
            auto end = std::chrono::high_resolution_clock::now();
            init_time += end - start;

            std::vector<unsigned char> I = res_init.I;
            ProtossState protoss_state = res_init.protoss_state;

            // Time RspDer step
            start = std::chrono::high_resolution_clock::now();
            ReturnTypeRspDer res_rspDer = RspDer(password, P_i, P_j, I);
            end = std::chrono::high_resolution_clock::now();
            rspder_time += end - start;

            std::vector<unsigned char> R = res_rspDer.R;
            std::vector<unsigned char> session_key_j = res_rspDer.getSessionKey();

            // Time Der step
            start = std::chrono::high_resolution_clock::now();
            std::vector<unsigned char> session_key_i = Der(password, protoss_state, R);
            end = std::chrono::high_resolution_clock::now();
            der_time += end - start;

            // We only verify keys match in the first iteration of the first run
            if (i == 0 && run_id == 1 && !is_warmup)
            {
                bool match = (session_key_i == session_key_j);
                if (!match)
                {
                    std::cerr << "ERROR: Session keys don't match!" << std::endl;
                }
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "Exception: " << e.what() << std::endl;
            return false;
        }
    }

    // Calculate average times
    out_init_ms = std::chrono::duration<double, std::milli>(init_time).count() / iterations;
    out_rspder_ms = std::chrono::duration<double, std::milli>(rspder_time).count() / iterations;
    out_der_ms = std::chrono::duration<double, std::milli>(der_time).count() / iterations;

    return true;
}

int main(int argc, char *argv[])
{
    Logger::get_instance().log(LoggingKeyword::BENCHMARK, "See the benchmark_results/sodium folder for the info of this run.");
    if (sodium_init() < 0)
    {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    // Default parameters
    int iterations = 10000;
    int num_runs = 10;

    // Parse optional CLI arguments: [iterations] [num_runs]
    if (argc >= 2)
        iterations = std::atoi(argv[1]);
    if (argc >= 3)
        num_runs = std::atoi(argv[2]);

    std::cout << "Protoss Protocol Timing Benchmark" << std::endl;
    std::cout << "=================================" << std::endl;

    // First run a warmup to avoid cold-start effects
    std::cout << "Performing warmup runs..." << std::endl;
    double dummy_init, dummy_rspder, dummy_der;
    run_benchmark(100, 0, true, dummy_init, dummy_rspder, dummy_der);

    // Run the benchmark multiple times to average out external variability
    std::cout << "\nRunning main benchmark (" << num_runs << " runs x " << iterations << " iterations)..." << std::endl;
    std::vector<double> run_init, run_rspder, run_der, run_total;

    for (int r = 1; r <= num_runs; r++)
    {
        double avg_init, avg_rspder, avg_der;
        if (!run_benchmark(iterations, r, false, avg_init, avg_rspder, avg_der))
        {
            std::cerr << "ERROR: Run " << r << " failed, aborting." << std::endl;
            return 1;
        }
        run_init.push_back(avg_init);
        run_rspder.push_back(avg_rspder);
        run_der.push_back(avg_der);
        run_total.push_back(avg_init + avg_rspder + avg_der);
    }

    // Calculate mean and standard deviation across runs
    double mean_init = calc_mean(run_init);
    double mean_rspder = calc_mean(run_rspder);
    double mean_der = calc_mean(run_der);
    double mean_total = calc_mean(run_total);

    double std_init = calc_stddev(run_init);
    double std_rspder = calc_stddev(run_rspder);
    double std_der = calc_stddev(run_der);
    double std_total = calc_stddev(run_total);

    // Save results to file
    Logger &logger = Logger::get_instance();
    std::stringstream ss;
    ss << std::fixed << std::setprecision(3);
    ss << "Benchmark Results with " << iterations << " iterations x " << num_runs << " runs\n";
    ss << "Hash Lengths: " << INPUT_LEN_RISTRETTO_HASH_TO_POINT << " bytes input for Ristretto hash-to-point fn, " << SESSION_KEY_LEN << " bytes of session key\n";
    ss << "-------------------------\n";
    ss << "Avg. Init phase:     " << mean_init << " +/- " << std_init << " ms\n";
    ss << "Avg. RspDer phase:   " << mean_rspder << " +/- " << std_rspder << " ms\n";
    ss << "Avg. Der phase:      " << mean_der << " +/- " << std_der << " ms\n";
    ss << "-------------------------\n";
    ss << "Avg. Total time:     " << mean_total << " +/- " << std_total << " ms\n";
    ss << "\nRelative Cost:\n";
    ss << "Init phase:     " << (mean_init / mean_total * 100) << "%\n";
    ss << "RspDer phase:   " << (mean_rspder / mean_total * 100) << "%\n";
    ss << "Der phase:      " << (mean_der / mean_total * 100) << "%\n";

    // Get current timestamp for the filename
    auto now = std::time(nullptr);
    std::stringstream filename;
    filename << "benchmark_results_it" << iterations << "_" << std::put_time(std::localtime(&now), "%Y-%m-%d_%H-%M-%S") << ".txt";

    // Save to file in benchmark_results folder
    logger.log_to_file(filename.str(), ss.str());
    std::cout << "\nBenchmark results saved to benchmark_results/sodium/" << filename.str() << std::endl;

    system("pause");
    return 0;
}
