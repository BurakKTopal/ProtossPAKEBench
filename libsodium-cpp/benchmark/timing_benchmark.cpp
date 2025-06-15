#include <sodium.h>
#include <stdexcept>
#include <vector>
#include <string>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <thread>
#include <sstream>
#include "logger.hpp"
#include "protoss_protocol.hpp"

void run_benchmark(int iterations)
{
    std::cout << "Running Protoss protocol benchmark with " << iterations << " iterations..." << std::endl;

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

            // We only verify keys match in the first iteration
            if (i == 0)
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
            return;
        }
    }

    // Calculate average times
    double avg_total_ms = std::chrono::duration<double, std::milli>(init_time + rspder_time + der_time).count() / iterations;
    double avg_init_ms = std::chrono::duration<double, std::milli>(init_time).count() / iterations;
    double avg_rspder_ms = std::chrono::duration<double, std::milli>(rspder_time).count() / iterations;
    double avg_der_ms = std::chrono::duration<double, std::milli>(der_time).count() / iterations;

    // Save results to file
    Logger &logger = Logger::get_instance();
    std::stringstream ss;
    ss << std::fixed << std::setprecision(3);
    ss << "Benchmark Results with " << iterations << " iterations\n";
    ss << "Hash Lengths: " << INPUT_LEN_RISTRETTO_HASH_TO_POINT << " bytes input for Ristretto hash-to-point fn, " << SESSION_KEY_LEN << " bytes of session key\n";
    ss << "-------------------------\n";
    ss << "Avg. Init phase:     " << avg_init_ms << " ms\n";
    ss << "Avg. RspDer phase:   " << avg_rspder_ms << " ms\n";
    ss << "Avg. Der phase:      " << avg_der_ms << " ms\n";
    ss << "-------------------------\n";
    ss << "Avg. Total time:     " << avg_total_ms << " ms\n";
    ss << "\nRelative Cost:\n";
    ss << "Init phase:     " << (avg_init_ms / avg_total_ms * 100) << "%\n";
    ss << "RspDer phase:   " << (avg_rspder_ms / avg_total_ms * 100) << "%\n";
    ss << "Der phase:      " << (avg_der_ms / avg_total_ms * 100) << "%\n";

    // Get current timestamp for the filename
    auto now = std::time(nullptr);
    std::stringstream filename;
    filename << "benchmark_results_it" << iterations << "_" << std::put_time(std::localtime(&now), "%Y-%m-%d_%H-%M-%S") << ".txt";

    // Save to file in benchmark_results folder
    logger.log_to_file(filename.str(), ss.str());
    std::cout << "\nBenchmark results saved to benchmark_results/sodium/" << filename.str() << std::endl;
}

int main()
{
    Logger::get_instance().log(LoggingKeyword::BENCHMARK, "See the benchmark_results/sodium folder for the info of this run.");
    if (sodium_init() < 0)
    {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    std::cout << "Protoss Protocol Timing Benchmark" << std::endl;
    std::cout << "=================================" << std::endl;

    // First run a warmup to avoid cold-start effects
    std::cout << "Performing warmup runs..." << std::endl;
    run_benchmark(100);

    // Then run the actual benchmark
    std::cout << "\nRunning main benchmark..." << std::endl;
    run_benchmark(10000);

    system("pause");
    return 0;
}