#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include <cstring>
#include <cmath>
#include <cstdlib>
#include <random>
#include <iomanip>
#include <sstream>
#include "protoss_protocol.hpp"
#include "logger.hpp"
extern "C"
{
#include "crypto_cpace.h "
}

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

// Helper function to generate random password
std::string generate_random_password(size_t length)
{
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);

    std::string password;
    password.reserve(length);
    for (size_t i = 0; i < length; ++i)
    {
        password += charset[dis(gen)];
    }
    return password;
}

// Helper function to generate random bytes
std::vector<unsigned char> generate_random_bytes(size_t length)
{
    std::vector<unsigned char> bytes(length);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < length; ++i)
    {
        bytes[i] = static_cast<unsigned char>(dis(gen));
    }
    return bytes;
}

void warmup_protoss(size_t warmup_iterations)
{
    Logger &logger = Logger::get_instance();
    logger.log(LoggingKeyword::BENCHMARK, "Warming up Protoss PAKE with " + std::to_string(warmup_iterations) + " iterations");

    for (size_t i = 0; i < warmup_iterations; ++i)
    {
        std::string password = generate_random_password(16);
        auto P_i = generate_random_bytes(32);
        auto P_j = generate_random_bytes(32);

        auto [I, state] = Init(password, P_i, P_j);
        auto rspder_result = RspDer(password, P_i, P_j, I);
        auto K_der = Der(password, state, rspder_result.R);
    }
}

void warmup_cpace(size_t warmup_iterations)
{
    Logger &logger = Logger::get_instance();
    logger.log(LoggingKeyword::BENCHMARK, "Warming up CPACE with " + std::to_string(warmup_iterations) + " iterations");

    for (size_t i = 0; i < warmup_iterations; ++i)
    {
        std::string password = generate_random_password(16);
        std::string id_a = "client";
        std::string id_b = "server";

        crypto_cpace_state ctx;
        unsigned char public_data[crypto_cpace_PUBLICDATABYTES];
        unsigned char response[crypto_cpace_RESPONSEBYTES];
        crypto_cpace_shared_keys shared_keys;

        crypto_cpace_step1(&ctx, public_data, password.c_str(), password.length(),
                           id_a.c_str(), id_a.length(), id_b.c_str(), id_b.length(),
                           nullptr, 0);
        crypto_cpace_step2(response, public_data, &shared_keys, password.c_str(),
                           password.length(), id_a.c_str(), id_a.length(),
                           id_b.c_str(), id_b.length(), nullptr, 0);
        crypto_cpace_step3(&ctx, &shared_keys, response);
    }
}

// Returns per-run averages in microseconds via out parameters
void benchmark_protoss(size_t iterations, size_t run_id,
                       double &out_init, double &out_rspder, double &out_der)
{
    Logger &logger = Logger::get_instance();
    logger.log(LoggingKeyword::BENCHMARK, "Run " + std::to_string(run_id) + ": Starting Protoss PAKE benchmark with " + std::to_string(iterations) + " iterations");

    auto total_init_time = std::chrono::nanoseconds(0);
    auto total_rspder_time = std::chrono::nanoseconds(0);
    auto total_der_time = std::chrono::nanoseconds(0);

    for (size_t i = 0; i < iterations; ++i)
    {
        std::string password = generate_random_password(16);
        auto P_i = generate_random_bytes(32);
        auto P_j = generate_random_bytes(32);

        // Measure Init
        auto start = std::chrono::high_resolution_clock::now();
        auto [I, state] = Init(password, P_i, P_j);
        auto end = std::chrono::high_resolution_clock::now();
        total_init_time += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);

        // Measure RspDer
        start = std::chrono::high_resolution_clock::now();
        auto rspder_result = RspDer(password, P_i, P_j, I);
        auto K_rspder = rspder_result.getSessionKey();
        end = std::chrono::high_resolution_clock::now();
        total_rspder_time += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);

        // Measure Der
        start = std::chrono::high_resolution_clock::now();
        auto K_der = Der(password, state, rspder_result.R);
        end = std::chrono::high_resolution_clock::now();
        total_der_time += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    }

    // Calculate averages in microseconds
    out_init = (total_init_time.count() / iterations) / 1000.0;
    out_rspder = (total_rspder_time.count() / iterations) / 1000.0;
    out_der = (total_der_time.count() / iterations) / 1000.0;
}

// Returns per-run averages in microseconds via out parameters
void benchmark_cpace(size_t iterations, size_t run_id,
                     double &out_step1, double &out_step2, double &out_step3)
{
    Logger &logger = Logger::get_instance();
    logger.log(LoggingKeyword::BENCHMARK, "Run " + std::to_string(run_id) + ": Starting CPACE benchmark with " + std::to_string(iterations) + " iterations");

    auto total_step1_time = std::chrono::nanoseconds(0);
    auto total_step2_time = std::chrono::nanoseconds(0);
    auto total_step3_time = std::chrono::nanoseconds(0);

    for (size_t i = 0; i < iterations; ++i)
    {
        std::string password = generate_random_password(16);
        std::string id_a = "client";
        std::string id_b = "server";

        crypto_cpace_state ctx;
        unsigned char public_data[crypto_cpace_PUBLICDATABYTES];
        unsigned char response[crypto_cpace_RESPONSEBYTES];
        crypto_cpace_shared_keys shared_keys;

        // Measure Step 1
        auto start = std::chrono::high_resolution_clock::now();
        crypto_cpace_step1(&ctx, public_data, password.c_str(), password.length(),
                           id_a.c_str(), id_a.length(), id_b.c_str(), id_b.length(),
                           nullptr, 0);
        auto end = std::chrono::high_resolution_clock::now();
        total_step1_time += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);

        // Measure Step 2
        start = std::chrono::high_resolution_clock::now();
        crypto_cpace_step2(response, public_data, &shared_keys, password.c_str(),
                           password.length(), id_a.c_str(), id_a.length(),
                           id_b.c_str(), id_b.length(), nullptr, 0);
        end = std::chrono::high_resolution_clock::now();
        total_step2_time += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);

        // Measure Step 3
        start = std::chrono::high_resolution_clock::now();
        crypto_cpace_step3(&ctx, &shared_keys, response);
        end = std::chrono::high_resolution_clock::now();
        total_step3_time += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    }

    // Calculate averages in microseconds
    out_step1 = (total_step1_time.count() / iterations) / 1000.0;
    out_step2 = (total_step2_time.count() / iterations) / 1000.0;
    out_step3 = (total_step3_time.count() / iterations) / 1000.0;
}

int main(int argc, char *argv[])
{
    size_t warmup_iterations = 5000;
    size_t benchmark_iterations = 50000;
    size_t num_runs = 10;
    Logger &logger = Logger::get_instance();

    // Parse optional CLI arguments: [iterations] [num_runs] [warmup_iterations]
    if (argc >= 2)
        benchmark_iterations = std::atoi(argv[1]);
    if (argc >= 3)
        num_runs = std::atoi(argv[2]);
    if (argc >= 4)
        warmup_iterations = std::atoi(argv[3]);

    logger.log(LoggingKeyword::BENCHMARK, "Starting PAKE Protocol Comparison Benchmark");
    std::cout << "Starting PAKE Protocol Benchmarking\n";
    std::cout << "==================================\n";

    // Warm-up runs
    std::cout << "Performing warm-up runs (" << warmup_iterations << " iterations)...\n";
    warmup_protoss(warmup_iterations);
    warmup_cpace(warmup_iterations);

    // Run the benchmark multiple times to average out external variability
    std::cout << "\nStarting main benchmark runs (" << num_runs << " runs x " << benchmark_iterations << " iterations)...\n";

    std::vector<double> protoss_init_runs, protoss_rspder_runs, protoss_der_runs, protoss_total_runs;
    std::vector<double> cpace_step1_runs, cpace_step2_runs, cpace_step3_runs, cpace_total_runs;

    for (size_t r = 1; r <= num_runs; ++r)
    {
        std::cout << "\n--- Run " << r << " of " << num_runs << " ---\n";

        double avg_init, avg_rspder, avg_der;
        benchmark_protoss(benchmark_iterations, r, avg_init, avg_rspder, avg_der);
        protoss_init_runs.push_back(avg_init);
        protoss_rspder_runs.push_back(avg_rspder);
        protoss_der_runs.push_back(avg_der);
        protoss_total_runs.push_back(avg_init + avg_rspder + avg_der);

        double avg_step1, avg_step2, avg_step3;
        benchmark_cpace(benchmark_iterations, r, avg_step1, avg_step2, avg_step3);
        cpace_step1_runs.push_back(avg_step1);
        cpace_step2_runs.push_back(avg_step2);
        cpace_step3_runs.push_back(avg_step3);
        cpace_total_runs.push_back(avg_step1 + avg_step2 + avg_step3);
    }

    // Calculate mean and standard deviation across runs for Protoss
    double mean_protoss_init = calc_mean(protoss_init_runs);
    double mean_protoss_rspder = calc_mean(protoss_rspder_runs);
    double mean_protoss_der = calc_mean(protoss_der_runs);
    double mean_protoss_total = calc_mean(protoss_total_runs);

    double std_protoss_init = calc_stddev(protoss_init_runs);
    double std_protoss_rspder = calc_stddev(protoss_rspder_runs);
    double std_protoss_der = calc_stddev(protoss_der_runs);
    double std_protoss_total = calc_stddev(protoss_total_runs);

    // Calculate mean and standard deviation across runs for CPace
    double mean_cpace_step1 = calc_mean(cpace_step1_runs);
    double mean_cpace_step2 = calc_mean(cpace_step2_runs);
    double mean_cpace_step3 = calc_mean(cpace_step3_runs);
    double mean_cpace_total = calc_mean(cpace_total_runs);

    double std_cpace_step1 = calc_stddev(cpace_step1_runs);
    double std_cpace_step2 = calc_stddev(cpace_step2_runs);
    double std_cpace_step3 = calc_stddev(cpace_step3_runs);
    double std_cpace_total = calc_stddev(cpace_total_runs);

    // Format and log Protoss results
    std::stringstream protoss_ss;
    protoss_ss << std::fixed << std::setprecision(3);
    protoss_ss << "Protoss PAKE Benchmark Results (" << benchmark_iterations << " iterations x " << num_runs << " runs):\n";
    protoss_ss << "Average Init time: " << mean_protoss_init << " +/- " << std_protoss_init << " us\n";
    protoss_ss << "Average RspDer time: " << mean_protoss_rspder << " +/- " << std_protoss_rspder << " us\n";
    protoss_ss << "Average Der time: " << mean_protoss_der << " +/- " << std_protoss_der << " us\n";
    protoss_ss << "Total average time per protocol run: " << mean_protoss_total << " +/- " << std_protoss_total << " us";

    logger.log(LoggingKeyword::BENCHMARK, protoss_ss.str());
    std::cout << "\n" << protoss_ss.str() << "\n";

    // Format and log CPace results
    std::stringstream cpace_ss;
    cpace_ss << std::fixed << std::setprecision(3);
    cpace_ss << "CPACE Benchmark Results (" << benchmark_iterations << " iterations x " << num_runs << " runs):\n";
    cpace_ss << "Average Step 1 time: " << mean_cpace_step1 << " +/- " << std_cpace_step1 << " us\n";
    cpace_ss << "Average Step 2 time: " << mean_cpace_step2 << " +/- " << std_cpace_step2 << " us\n";
    cpace_ss << "Average Step 3 time: " << mean_cpace_step3 << " +/- " << std_cpace_step3 << " us\n";
    cpace_ss << "Total average time per protocol run: " << mean_cpace_total << " +/- " << std_cpace_total << " us";

    logger.log(LoggingKeyword::BENCHMARK, cpace_ss.str());
    std::cout << "\n" << cpace_ss.str() << "\n";

    // Save final results to file
    auto now = std::time(nullptr);
    std::stringstream filename;
    filename << "benchmark_results_it" << benchmark_iterations << "_" << std::put_time(std::localtime(&now), "%Y-%m-%d_%H-%M-%S") << ".txt";

    std::stringstream final_results;
    final_results << "PAKE Protocol Comparison Benchmark Results\n";
    final_results << "=========================================\n";
    final_results << "Warm-up iterations: " << warmup_iterations << "\n";
    final_results << "Benchmark iterations: " << benchmark_iterations << "\n";
    final_results << "Number of runs: " << num_runs << "\n\n";
    final_results << protoss_ss.str() << "\n\n";
    final_results << cpace_ss.str() << "\n";

    logger.log_to_file(filename.str(), final_results.str());
    logger.log(LoggingKeyword::BENCHMARK, "PAKE Protocol Comparison Benchmark completed");

    std::cout << "\nBenchmark results saved to benchmark_results/sodium/" << filename.str() << std::endl;
    system("pause");
    return 0;
}
