#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include <cstring>
#include <random>
#include <iomanip>
#include <sstream>
#include "protoss_protocol.hpp"
#include "logger.hpp"
extern "C"
{
#include "crypto_cpace.h "
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

void benchmark_protoss(size_t iterations)
{
    Logger &logger = Logger::get_instance();
    logger.log(LoggingKeyword::BENCHMARK, "Starting Protoss PAKE benchmark with " + std::to_string(iterations) + " iterations");

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

    // Calculate averages
    double avg_init = (total_init_time.count() / iterations) / 1000.0;
    double avg_rspder = (total_rspder_time.count() / iterations) / 1000.0;
    double avg_der = (total_der_time.count() / iterations) / 1000.0;

    // Log results
    std::stringstream ss;
    ss << std::fixed << std::setprecision(3);
    ss << "Protoss PAKE Benchmark Results:\n";
    ss << "Average Init time: " << avg_init << " µs\n";
    ss << "Average RspDer time: " << avg_rspder << " µs\n";
    ss << "Average Der time: " << avg_der << " µs\n";
    ss << "Total average time per protocol run: " << (avg_init + avg_rspder + avg_der) << " µs";

    logger.log(LoggingKeyword::BENCHMARK, ss.str());

    // Also print to console
    std::cout << "\nBenchmarking Protoss PAKE (" << iterations << " iterations):\n";
    std::cout << ss.str() << "\n";
}

void benchmark_cpace(size_t iterations)
{
    Logger &logger = Logger::get_instance();
    logger.log(LoggingKeyword::BENCHMARK, "Starting CPACE benchmark with " + std::to_string(iterations) + " iterations");

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

    // Calculate averages
    double avg_step1 = (total_step1_time.count() / iterations) / 1000.0;
    double avg_step2 = (total_step2_time.count() / iterations) / 1000.0;
    double avg_step3 = (total_step3_time.count() / iterations) / 1000.0;

    // Log results
    std::stringstream ss;
    ss << std::fixed << std::setprecision(3);
    ss << "CPACE Benchmark Results:\n";
    ss << "Average Step 1 time: " << avg_step1 << " µs\n";
    ss << "Average Step 2 time: " << avg_step2 << " µs\n";
    ss << "Average Step 3 time: " << avg_step3 << " µs\n";
    ss << "Total average time per protocol run: " << (avg_step1 + avg_step2 + avg_step3) << " µs";

    logger.log(LoggingKeyword::BENCHMARK, ss.str());

    // Also print to console
    std::cout << "\nBenchmarking CPACE (" << iterations << " iterations):\n";
    std::cout << ss.str() << "\n";
}

int main()
{
    const size_t warmup_iterations = 5000;
    const size_t benchmark_iterations = 50000;
    Logger &logger = Logger::get_instance();

    logger.log(LoggingKeyword::BENCHMARK, "Starting PAKE Protocol Comparison Benchmark");
    std::cout << "Starting PAKE Protocol Benchmarking\n";
    std::cout << "==================================\n";

    // Warm-up runs
    std::cout << "Performing warm-up runs (" << warmup_iterations << " iterations)...\n";
    warmup_protoss(warmup_iterations);
    warmup_cpace(warmup_iterations);

    // Main benchmark runs
    std::cout << "\nStarting main benchmark runs (" << benchmark_iterations << " iterations)...\n";
    benchmark_protoss(benchmark_iterations);
    benchmark_cpace(benchmark_iterations);

    // Save final results to file
    auto now = std::time(nullptr);
    std::stringstream filename;
    filename << "benchmark_results_it" << benchmark_iterations << "_" << std::put_time(std::localtime(&now), "%Y-%m-%d_%H-%M-%S") << ".txt";

    std::stringstream final_results;
    final_results << "PAKE Protocol Comparison Benchmark Results\n";
    final_results << "=========================================\n";
    final_results << "Warm-up iterations: " << warmup_iterations << "\n";
    final_results << "Benchmark iterations: " << benchmark_iterations << "\n\n";
    final_results << "Results are logged in the benchmark log file.\n";

    logger.log_to_file(filename.str(), final_results.str());
    logger.log(LoggingKeyword::BENCHMARK, "PAKE Protocol Comparison Benchmark completed");

    std::cout << "\nBenchmark results saved to benchmark_results/sodium/" << filename.str() << std::endl;
    system("pause");
    return 0;
}