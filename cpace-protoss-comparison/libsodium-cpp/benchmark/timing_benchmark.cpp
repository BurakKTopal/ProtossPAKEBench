#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include <cstring>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include "protoss_protocol.hpp"
#include "logger.hpp"
extern "C"
{
#include "crypto_cpace.h"
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

static const char *g_password = "SharedPassword";
static const char *g_id_a = "client_identif00";
static const char *g_id_b = "server_identif00";

static bool protoss_once(double &init_t, double &rspder_t, double &der_t)
{
    const std::string password = g_password;
    const std::vector<unsigned char> P_i(16, 0x01);
    std::vector<unsigned char> P_j(16, 0x02);

    auto start = std::chrono::high_resolution_clock::now();
    auto [I, state] = Init(password, P_i, P_j);
    auto end = std::chrono::high_resolution_clock::now();
    init_t += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

    start = std::chrono::high_resolution_clock::now();
    auto rspder_result = RspDer(password, P_i, P_j, I);
    end = std::chrono::high_resolution_clock::now();
    rspder_t += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

    start = std::chrono::high_resolution_clock::now();
    auto K_der = Der(g_password, state, rspder_result.R);
    end = std::chrono::high_resolution_clock::now();
    der_t += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

    return K_der == rspder_result.getSessionKey();
}

static bool cpace_once(double &step1_t, double &step2_t, double &step3_t)
{
    crypto_cpace_state ctx;
    unsigned char public_data[crypto_cpace_PUBLICDATABYTES];
    unsigned char response[crypto_cpace_RESPONSEBYTES];
    crypto_cpace_shared_keys sk_initiator, sk_responder;
    size_t pw = std::strlen(g_password);
    size_t la = std::strlen(g_id_a);
    size_t lb = std::strlen(g_id_b);

    auto start = std::chrono::high_resolution_clock::now();
    crypto_cpace_step1(&ctx, public_data, g_password, pw,
                       g_id_a, la, g_id_b, lb, nullptr, 0);
    auto end = std::chrono::high_resolution_clock::now();
    step1_t += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

    start = std::chrono::high_resolution_clock::now();
    crypto_cpace_step2(response, public_data, &sk_responder, g_password, pw,
                       g_id_a, la, g_id_b, lb, nullptr, 0);
    end = std::chrono::high_resolution_clock::now();
    step2_t += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

    start = std::chrono::high_resolution_clock::now();
    crypto_cpace_step3(&ctx, &sk_initiator, response);
    end = std::chrono::high_resolution_clock::now();
    step3_t += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

    return std::memcmp(sk_initiator.client_sk, sk_responder.client_sk, crypto_cpace_SHAREDKEYBYTES) == 0 &&
           std::memcmp(sk_initiator.server_sk, sk_responder.server_sk, crypto_cpace_SHAREDKEYBYTES) == 0;
}

static void run_rotated(size_t iterations,
                        double &pr_init, double &pr_rspder, double &pr_der,
                        double &cp_step1, double &cp_step2, double &cp_step3,
                        bool &mismatch)
{
    double pi = 0, pr = 0, pd = 0;
    double c1 = 0, c2 = 0, c3 = 0;

    for (size_t i = 0; i < iterations; ++i)
    {
        if (!protoss_once(pi, pr, pd))
            mismatch = true;
        if (!cpace_once(c1, c2, c3))
            mismatch = true;
    }

    pr_init = (pi / iterations) / 1000.0;
    pr_rspder = (pr / iterations) / 1000.0;
    pr_der = (pd / iterations) / 1000.0;
    cp_step1 = (c1 / iterations) / 1000.0;
    cp_step2 = (c2 / iterations) / 1000.0;
    cp_step3 = (c3 / iterations) / 1000.0;
}

int main(int argc, char *argv[])
{
    size_t warmup_iterations = 5000;
    size_t benchmark_iterations = 50000;
    size_t num_runs = 10;
    Logger &logger = Logger::get_instance();

    if (argc >= 2)
        benchmark_iterations = std::atoi(argv[1]);
    if (argc >= 3)
        num_runs = std::atoi(argv[2]);
    if (argc >= 4)
        warmup_iterations = std::atoi(argv[3]);

    if (sodium_init() < 0)
    {
        std::cerr << "Failed to initialize libsodium\n";
        return 1;
    }

    logger.log(LoggingKeyword::BENCHMARK, "Starting PAKE Protocol Comparison Benchmark");
    std::cout << "Starting PAKE Protocol Benchmarking\n";
    std::cout << "==================================\n";

    bool mismatch = false;

    std::cout << "Performing warm-up runs (" << warmup_iterations << " iterations)...\n";
    {
        double d[6];
        run_rotated(warmup_iterations, d[0], d[1], d[2], d[3], d[4], d[5], mismatch);
    }

    std::cout << "\nStarting main benchmark runs (" << num_runs << " runs x " << benchmark_iterations << " iterations)...\n";

    std::vector<double> protoss_init_runs, protoss_rspder_runs, protoss_der_runs, protoss_total_runs;
    std::vector<double> cpace_step1_runs, cpace_step2_runs, cpace_step3_runs, cpace_total_runs;

    for (size_t r = 1; r <= num_runs; ++r)
    {
        std::cout << "\n--- Run " << r << " of " << num_runs << " ---\n";

        double pr_init, pr_rspder, pr_der;
        double cp_step1, cp_step2, cp_step3;

        run_rotated(benchmark_iterations,
                    pr_init, pr_rspder, pr_der,
                    cp_step1, cp_step2, cp_step3, mismatch);

        protoss_init_runs.push_back(pr_init);
        protoss_rspder_runs.push_back(pr_rspder);
        protoss_der_runs.push_back(pr_der);
        protoss_total_runs.push_back(pr_init + pr_rspder + pr_der);

        cpace_step1_runs.push_back(cp_step1);
        cpace_step2_runs.push_back(cp_step2);
        cpace_step3_runs.push_back(cp_step3);
        cpace_total_runs.push_back(cp_step1 + cp_step2 + cp_step3);
    }

    if (mismatch)
        std::cerr << "ERROR: shared keys do not match in at least one protocol!\n";

    double mean_protoss_init = calc_mean(protoss_init_runs);
    double mean_protoss_rspder = calc_mean(protoss_rspder_runs);
    double mean_protoss_der = calc_mean(protoss_der_runs);
    double mean_protoss_total = calc_mean(protoss_total_runs);

    double std_protoss_init = calc_stddev(protoss_init_runs);
    double std_protoss_rspder = calc_stddev(protoss_rspder_runs);
    double std_protoss_der = calc_stddev(protoss_der_runs);
    double std_protoss_total = calc_stddev(protoss_total_runs);

    double mean_cpace_step1 = calc_mean(cpace_step1_runs);
    double mean_cpace_step2 = calc_mean(cpace_step2_runs);
    double mean_cpace_step3 = calc_mean(cpace_step3_runs);
    double mean_cpace_total = calc_mean(cpace_total_runs);

    double std_cpace_step1 = calc_stddev(cpace_step1_runs);
    double std_cpace_step2 = calc_stddev(cpace_step2_runs);
    double std_cpace_step3 = calc_stddev(cpace_step3_runs);
    double std_cpace_total = calc_stddev(cpace_total_runs);

    std::stringstream protoss_ss;
    protoss_ss << std::fixed << std::setprecision(3);
    protoss_ss << "Protoss PAKE Benchmark Results (" << benchmark_iterations << " iterations x " << num_runs << " runs):\n";
    protoss_ss << "Average Init time: " << mean_protoss_init << " +/- " << std_protoss_init << " us\n";
    protoss_ss << "Average RspDer time: " << mean_protoss_rspder << " +/- " << std_protoss_rspder << " us\n";
    protoss_ss << "Average Der time: " << mean_protoss_der << " +/- " << std_protoss_der << " us\n";
    protoss_ss << "Total average time per protocol run: " << mean_protoss_total << " +/- " << std_protoss_total << " us";

    logger.log(LoggingKeyword::BENCHMARK, protoss_ss.str());

    std::stringstream cpace_ss;
    cpace_ss << std::fixed << std::setprecision(3);
    cpace_ss << "CPACE Benchmark Results (" << benchmark_iterations << " iterations x " << num_runs << " runs):\n";
    cpace_ss << "Average Step 1 time: " << mean_cpace_step1 << " +/- " << std_cpace_step1 << " us\n";
    cpace_ss << "Average Step 2 time: " << mean_cpace_step2 << " +/- " << std_cpace_step2 << " us\n";
    cpace_ss << "Average Step 3 time: " << mean_cpace_step3 << " +/- " << std_cpace_step3 << " us\n";
    cpace_ss << "Total average time per protocol run: " << mean_cpace_total << " +/- " << std_cpace_total << " us";

    logger.log(LoggingKeyword::BENCHMARK, cpace_ss.str());

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
