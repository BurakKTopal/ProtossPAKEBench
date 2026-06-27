#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <sodium.h>
#include "protoss_protocol.hpp"
#include "protoss_validated.hpp"
#include "protoss_orchestrated.hpp"
#include "protoss_precomputed.hpp"
#include "logger.hpp"

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

static double ms_since(const std::chrono::high_resolution_clock::time_point &start)
{
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count() / 1e6;
}

static const std::string g_password = "SharedPassword";
static const std::vector<unsigned char> g_P_i(16, 0x01);
static const std::vector<unsigned char> g_P_j(16, 0x02);

static bool baseline_once(double &init_t, double &rspder_t, double &der_t)
{
    std::vector<unsigned char> P_j = g_P_j;

    auto start = std::chrono::high_resolution_clock::now();
    auto res_init = Init(g_password, g_P_i, P_j);
    init_t += ms_since(start);

    start = std::chrono::high_resolution_clock::now();
    auto res_rspder = RspDer(g_password, g_P_i, P_j, res_init.I);
    rspder_t += ms_since(start);

    start = std::chrono::high_resolution_clock::now();
    auto k_der = Der(res_init.protoss_state, res_rspder.R);
    der_t += ms_since(start);

    return k_der == res_rspder.getSessionKey();
}

static bool validated_once(double &init_t, double &rspder_t, double &der_t)
{
    std::vector<unsigned char> P_j = g_P_j;

    auto start = std::chrono::high_resolution_clock::now();
    auto res_init = Init(g_password, g_P_i, P_j);
    init_t += ms_since(start);

    start = std::chrono::high_resolution_clock::now();
    auto res_rspder = validated_RspDer(g_password, g_P_i, P_j, res_init.I);
    rspder_t += ms_since(start);

    start = std::chrono::high_resolution_clock::now();
    auto k_der = validated_Der(res_init.protoss_state, res_rspder.R);
    der_t += ms_since(start);

    return k_der == res_rspder.getSessionKey();
}

static bool orchestrated_once(double &init_t, double &rspder_t, double &der_t)
{
    ProtossOrchestratedState init_state = orchestrated_state_create(g_P_i, g_P_j);
    ProtossOrchestratedState rsp_state = orchestrated_state_create(g_P_i, g_P_j);

    auto start = std::chrono::high_resolution_clock::now();
    auto I = orchestrated_Init(init_state, g_password);
    init_t += ms_since(start);

    start = std::chrono::high_resolution_clock::now();
    auto res_rspder = orchestrated_RspDer(rsp_state, g_password, I);
    rspder_t += ms_since(start);

    start = std::chrono::high_resolution_clock::now();
    auto k_init = orchestrated_Der(init_state, res_rspder.R);
    der_t += ms_since(start);

    bool ok = k_init == res_rspder.getSessionKey();

    orchestrated_state_destroy(init_state);
    orchestrated_state_destroy(rsp_state);
    return ok;
}

static bool precomputed_once(double &precompute_t, double &init_t, double &rspder_t, double &der_t)
{
    auto start = std::chrono::high_resolution_clock::now();
    ProtossPrecomputedState init_state = precomputed_state_create(g_P_i, g_P_j);
    ProtossPrecomputedState rsp_state = precomputed_state_create(g_P_i, g_P_j);
    precompute_t += ms_since(start);

    start = std::chrono::high_resolution_clock::now();
    auto I = precomputed_Init(init_state, g_password);
    init_t += ms_since(start);

    start = std::chrono::high_resolution_clock::now();
    auto res_rspder = precomputed_RspDer(rsp_state, g_password, I);
    rspder_t += ms_since(start);

    start = std::chrono::high_resolution_clock::now();
    auto k_init = precomputed_Der(init_state, res_rspder.R);
    der_t += ms_since(start);

    bool ok = k_init == res_rspder.getSessionKey();

    precomputed_state_destroy(init_state);
    precomputed_state_destroy(rsp_state);
    return ok;
}

struct RunResult
{
    double bl_init = 0, bl_rspder = 0, bl_der = 0;
    double vl_init = 0, vl_rspder = 0, vl_der = 0;
    double or_init = 0, or_rspder = 0, or_der = 0;
    double pc_precompute = 0, pc_init = 0, pc_rspder = 0, pc_der = 0;
};

static RunResult run_rotated(size_t iterations, bool &mismatch)
{
    RunResult r;
    for (size_t i = 0; i < iterations; ++i)
    {
        if (!baseline_once(r.bl_init, r.bl_rspder, r.bl_der))
            mismatch = true;
        if (!validated_once(r.vl_init, r.vl_rspder, r.vl_der))
            mismatch = true;
        if (!orchestrated_once(r.or_init, r.or_rspder, r.or_der))
            mismatch = true;
        if (!precomputed_once(r.pc_precompute, r.pc_init, r.pc_rspder, r.pc_der))
            mismatch = true;
    }

    double n = static_cast<double>(iterations);
    r.bl_init /= n; r.bl_rspder /= n; r.bl_der /= n;
    r.vl_init /= n; r.vl_rspder /= n; r.vl_der /= n;
    r.or_init /= n; r.or_rspder /= n; r.or_der /= n;
    r.pc_precompute /= n; r.pc_init /= n; r.pc_rspder /= n; r.pc_der /= n;
    return r;
}

int main(int argc, char *argv[])
{
    Logger &logger = Logger::get_instance();
    logger.log(LoggingKeyword::BENCHMARK, "See the benchmark_results/sodium folder for the info of this run.");

    if (sodium_init() < 0)
    {
        std::cerr << "Failed to initialize libsodium\n";
        return 1;
    }

    int iterations = 10000;
    int num_runs = 10;
    if (argc >= 2)
        iterations = std::atoi(argv[1]);
    if (argc >= 3)
        num_runs = std::atoi(argv[2]);

    std::cout << "Protoss Protocol Variant Comparison Benchmark\n";
    std::cout << "==============================================\n";
    std::cout << "Config: " << iterations << " iterations x " << num_runs << " runs (iteration-level rotation)\n\n";

    bool mismatch = false;

    std::cout << "Performing warmup...\n";
    run_rotated(100, mismatch);
    std::cout << "Warmup complete.\n\n";

    std::vector<double> bl_init, bl_rspder, bl_der;
    std::vector<double> vl_init, vl_rspder, vl_der;
    std::vector<double> or_init, or_rspder, or_der;
    std::vector<double> pc_precompute, pc_init, pc_rspder, pc_der;

    for (int run = 0; run < num_runs; ++run)
    {
        std::cout << "Run " << (run + 1) << "/" << num_runs << "...\n";
        RunResult r = run_rotated(iterations, mismatch);
        bl_init.push_back(r.bl_init); bl_rspder.push_back(r.bl_rspder); bl_der.push_back(r.bl_der);
        vl_init.push_back(r.vl_init); vl_rspder.push_back(r.vl_rspder); vl_der.push_back(r.vl_der);
        or_init.push_back(r.or_init); or_rspder.push_back(r.or_rspder); or_der.push_back(r.or_der);
        pc_precompute.push_back(r.pc_precompute);
        pc_init.push_back(r.pc_init); pc_rspder.push_back(r.pc_rspder); pc_der.push_back(r.pc_der);
    }

    if (mismatch)
        std::cerr << "ERROR: Session keys don't match in at least one variant!\n";

    double m_bl_init = calc_mean(bl_init), s_bl_init = calc_stddev(bl_init);
    double m_bl_rsp = calc_mean(bl_rspder), s_bl_rsp = calc_stddev(bl_rspder);
    double m_bl_der = calc_mean(bl_der), s_bl_der = calc_stddev(bl_der);

    double m_vl_init = calc_mean(vl_init), s_vl_init = calc_stddev(vl_init);
    double m_vl_rsp = calc_mean(vl_rspder), s_vl_rsp = calc_stddev(vl_rspder);
    double m_vl_der = calc_mean(vl_der), s_vl_der = calc_stddev(vl_der);

    double m_or_init = calc_mean(or_init), s_or_init = calc_stddev(or_init);
    double m_or_rsp = calc_mean(or_rspder), s_or_rsp = calc_stddev(or_rspder);
    double m_or_der = calc_mean(or_der), s_or_der = calc_stddev(or_der);

    double m_pc_pre = calc_mean(pc_precompute), s_pc_pre = calc_stddev(pc_precompute);
    double m_pc_init = calc_mean(pc_init), s_pc_init = calc_stddev(pc_init);
    double m_pc_rsp = calc_mean(pc_rspder), s_pc_rsp = calc_stddev(pc_rspder);
    double m_pc_der = calc_mean(pc_der), s_pc_der = calc_stddev(pc_der);

    double bl_total = m_bl_init + m_bl_rsp + m_bl_der;
    double vl_total = m_vl_init + m_vl_rsp + m_vl_der;
    double or_total = m_or_init + m_or_rsp + m_or_der;
    double pc_proto = m_pc_init + m_pc_rsp + m_pc_der;
    double pc_total = m_pc_pre + pc_proto;

    std::stringstream out;
    out << std::fixed << std::setprecision(4);
    out << "Protoss Variant Comparison Benchmark Results\n";
    out << "Config: " << iterations << " iterations x " << num_runs << " runs (iteration-level rotation)\n";
    out << "=============================================\n\n";
    out << "BASELINE:\n";
    out << "  Init:     " << m_bl_init << " +/- " << s_bl_init << " ms\n";
    out << "  RspDer:   " << m_bl_rsp << " +/- " << s_bl_rsp << " ms\n";
    out << "  Der:      " << m_bl_der << " +/- " << s_bl_der << " ms\n";
    out << "  Total:    " << bl_total << " ms\n\n";
    out << "VALIDATED (with point validation):\n";
    out << "  Init:     " << m_vl_init << " +/- " << s_vl_init << " ms\n";
    out << "  RspDer:   " << m_vl_rsp << " +/- " << s_vl_rsp << " ms\n";
    out << "  Der:      " << m_vl_der << " +/- " << s_vl_der << " ms\n";
    out << "  Total:    " << vl_total << " ms\n\n";
    out << "ORCHESTRATED (state manager, no precompute):\n";
    out << "  Init:     " << m_or_init << " +/- " << s_or_init << " ms\n";
    out << "  RspDer:   " << m_or_rsp << " +/- " << s_or_rsp << " ms\n";
    out << "  Der:      " << m_or_der << " +/- " << s_or_der << " ms\n";
    out << "  Total:    " << or_total << " ms\n\n";
    out << "PRECOMPUTED (state manager + precomputation):\n";
    out << "  Precomp:  " << m_pc_pre << " +/- " << s_pc_pre << " ms\n";
    out << "  Init:     " << m_pc_init << " +/- " << s_pc_init << " ms\n";
    out << "  RspDer:   " << m_pc_rsp << " +/- " << s_pc_rsp << " ms\n";
    out << "  Der:      " << m_pc_der << " +/- " << s_pc_der << " ms\n";
    out << "  Protocol: " << pc_proto << " ms (online cost, precompute done ahead)\n";
    out << "  Total:    " << pc_total << " ms (precompute time included)\n";

    std::cout << "\n" << out.str();

    auto now = std::time(nullptr);
    std::stringstream filename;
    filename << "variant_benchmark_it" << iterations << "_" << std::put_time(std::localtime(&now), "%Y-%m-%d_%H-%M-%S") << ".txt";

    logger.log_to_file(filename.str(), out.str());
    std::cout << "\nResults saved to benchmark_results/sodium/" << filename.str() << std::endl;

    logger.log(LoggingKeyword::BENCHMARK, "Protoss Variant Comparison Benchmark completed");
    return 0;
}
