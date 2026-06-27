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
#include "protoss_precomputed.hpp"
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
        sum_sq += (v - m) * (v - m);
    return std::sqrt(sum_sq / (values.size() - 1));
}

static double ns_since(const std::chrono::high_resolution_clock::time_point &start)
{
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
}

static const char *g_password = "SharedPassword";
static const char *g_id_a = "client_identif00";
static const char *g_id_b = "server_identif00";

struct ThreePhase
{
    double phase1 = 0, phase2 = 0, phase3 = 0;
};

struct FourPhase
{
    double precompute = 0, init = 0, rspder = 0, der = 0;
};

static bool protoss_once(ThreePhase &acc)
{
    const std::string password = g_password;
    const std::vector<unsigned char> P_i(16, 0x01);
    std::vector<unsigned char> P_j(16, 0x02);

    auto start = std::chrono::high_resolution_clock::now();
    auto [I, state] = Init(password, P_i, P_j);
    acc.phase1 += ns_since(start);

    start = std::chrono::high_resolution_clock::now();
    auto rspder_result = RspDer(password, P_i, P_j, I);
    acc.phase2 += ns_since(start);

    start = std::chrono::high_resolution_clock::now();
    auto K_der = Der(state, rspder_result.R);
    acc.phase3 += ns_since(start);

    return K_der == rspder_result.getSessionKey();
}

static bool precomputed_once(FourPhase &acc)
{
    const std::string password = g_password;
    const std::vector<unsigned char> P_i(16, 0x01);
    const std::vector<unsigned char> P_j(16, 0x02);

    auto start = std::chrono::high_resolution_clock::now();
    ProtossPrecomputedState init_state = precomputed_state_create(P_i, P_j);
    ProtossPrecomputedState rsp_state = precomputed_state_create(P_i, P_j);
    acc.precompute += ns_since(start);

    start = std::chrono::high_resolution_clock::now();
    auto I = precomputed_Init(init_state, password);
    acc.init += ns_since(start);

    start = std::chrono::high_resolution_clock::now();
    auto rspder_result = precomputed_RspDer(rsp_state, password, I);
    acc.rspder += ns_since(start);

    start = std::chrono::high_resolution_clock::now();
    auto K_init = precomputed_Der(init_state, rspder_result.R);
    acc.der += ns_since(start);

    bool ok = K_init == rspder_result.getSessionKey();

    precomputed_state_destroy(init_state);
    precomputed_state_destroy(rsp_state);
    return ok;
}

static bool cpace_once(ThreePhase &acc)
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
    acc.phase1 += ns_since(start);

    start = std::chrono::high_resolution_clock::now();
    crypto_cpace_step2(response, public_data, &sk_responder, g_password, pw,
                       g_id_a, la, g_id_b, lb, nullptr, 0);
    acc.phase2 += ns_since(start);

    start = std::chrono::high_resolution_clock::now();
    crypto_cpace_step3(&ctx, &sk_initiator, response);
    acc.phase3 += ns_since(start);

    return std::memcmp(sk_initiator.client_sk, sk_responder.client_sk, crypto_cpace_SHAREDKEYBYTES) == 0 &&
           std::memcmp(sk_initiator.server_sk, sk_responder.server_sk, crypto_cpace_SHAREDKEYBYTES) == 0;
}

struct RunResult
{
    double pr[3];
    double pc[4];
    double cp[3];
};

static RunResult run_rotated(size_t iterations, bool &mismatch)
{
    ThreePhase pr;
    FourPhase pc;
    ThreePhase cp;

    for (size_t i = 0; i < iterations; ++i)
    {
        if (!protoss_once(pr))
            mismatch = true;
        if (!precomputed_once(pc))
            mismatch = true;
        if (!cpace_once(cp))
            mismatch = true;
    }

    double n = static_cast<double>(iterations);
    RunResult r;
    r.pr[0] = pr.phase1 / n / 1000.0;
    r.pr[1] = pr.phase2 / n / 1000.0;
    r.pr[2] = pr.phase3 / n / 1000.0;
    r.pc[0] = pc.precompute / n / 1000.0;
    r.pc[1] = pc.init / n / 1000.0;
    r.pc[2] = pc.rspder / n / 1000.0;
    r.pc[3] = pc.der / n / 1000.0;
    r.cp[0] = cp.phase1 / n / 1000.0;
    r.cp[1] = cp.phase2 / n / 1000.0;
    r.cp[2] = cp.phase3 / n / 1000.0;
    return r;
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
    run_rotated(warmup_iterations, mismatch);

    std::cout << "\nStarting main benchmark runs (" << num_runs << " runs x " << benchmark_iterations << " iterations)...\n";

    std::vector<RunResult> runs;
    for (size_t r = 1; r <= num_runs; ++r)
    {
        std::cout << "\n--- Run " << r << " of " << num_runs << " ---\n";
        runs.push_back(run_rotated(benchmark_iterations, mismatch));
    }

    if (mismatch)
        std::cerr << "ERROR: shared keys do not match in at least one protocol!\n";

    double m_pr[3], s_pr[3], m_pc[4], s_pc[4], m_cp[3], s_cp[3];
    for (int j = 0; j < 3; j++)
    {
        std::vector<double> c;
        for (const auto &r : runs) c.push_back(r.pr[j]);
        m_pr[j] = calc_mean(c); s_pr[j] = calc_stddev(c);
    }
    for (int j = 0; j < 4; j++)
    {
        std::vector<double> c;
        for (const auto &r : runs) c.push_back(r.pc[j]);
        m_pc[j] = calc_mean(c); s_pc[j] = calc_stddev(c);
    }
    for (int j = 0; j < 3; j++)
    {
        std::vector<double> c;
        for (const auto &r : runs) c.push_back(r.cp[j]);
        m_cp[j] = calc_mean(c); s_cp[j] = calc_stddev(c);
    }

    double pr_total = m_pr[0] + m_pr[1] + m_pr[2];
    double pc_proto = m_pc[1] + m_pc[2] + m_pc[3];
    double pc_total = m_pc[0] + pc_proto;
    double cp_total = m_cp[0] + m_cp[1] + m_cp[2];

    std::stringstream out;
    out << std::fixed << std::setprecision(3);
    out << "PAKE Protocol Comparison Benchmark Results\n";
    out << "=========================================\n";
    out << "Warm-up iterations: " << warmup_iterations << "\n";
    out << "Benchmark iterations: " << benchmark_iterations << "\n";
    out << "Number of runs: " << num_runs << "\n\n";
    out << "PROTOSS (baseline):\n";
    out << "  Init:     " << m_pr[0] << " +/- " << s_pr[0] << " us\n";
    out << "  RspDer:   " << m_pr[1] << " +/- " << s_pr[1] << " us\n";
    out << "  Der:      " << m_pr[2] << " +/- " << s_pr[2] << " us\n";
    out << "  Total:    " << pr_total << " us\n\n";
    out << "PROTOSS (precomputed):\n";
    out << "  Precomp:  " << m_pc[0] << " +/- " << s_pc[0] << " us\n";
    out << "  Init:     " << m_pc[1] << " +/- " << s_pc[1] << " us\n";
    out << "  RspDer:   " << m_pc[2] << " +/- " << s_pc[2] << " us\n";
    out << "  Der:      " << m_pc[3] << " +/- " << s_pc[3] << " us\n";
    out << "  Protocol: " << pc_proto << " us (online cost, precompute done ahead)\n";
    out << "  Total:    " << pc_total << " us (precompute time included)\n\n";
    out << "CPACE:\n";
    out << "  Step 1:   " << m_cp[0] << " +/- " << s_cp[0] << " us\n";
    out << "  Step 2:   " << m_cp[1] << " +/- " << s_cp[1] << " us\n";
    out << "  Step 3:   " << m_cp[2] << " +/- " << s_cp[2] << " us\n";
    out << "  Total:    " << cp_total << " us\n";

    std::cout << "\n" << out.str();
    logger.log(LoggingKeyword::BENCHMARK, out.str());

    auto now = std::time(nullptr);
    std::stringstream filename;
    filename << "benchmark_results_it" << benchmark_iterations << "_" << std::put_time(std::localtime(&now), "%Y-%m-%d_%H-%M-%S") << ".txt";

    logger.log_to_file(filename.str(), out.str());
    logger.log(LoggingKeyword::BENCHMARK, "PAKE Protocol Comparison Benchmark completed");

    std::cout << "\nBenchmark results saved to benchmark_results/sodium/" << filename.str() << std::endl;
    system("pause");
    return 0;
}
