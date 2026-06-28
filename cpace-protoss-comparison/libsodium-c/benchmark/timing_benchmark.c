
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <sodium.h>
#include "protoss_protocol.h"
#include "protoss_precomputed.h"
#include "logger.h"
#include "crypto_cpace.h"

static double timespec_diff_ns(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec) * 1e9 +
           (end->tv_nsec - start->tv_nsec);
}

// Print "[HH:MM:SS] Run r/N (elapsed Xs)" and flush, so progress is visible
// per run even when stdout is piped. Printing is outside every timed region.
static void print_run_progress(size_t run_id, size_t num_runs, time_t bench_start)
{
    time_t now = time(NULL);
    struct tm *lt = localtime(&now);
    printf("[%02d:%02d:%02d] Run %zu/%zu (elapsed %llds)\n",
           lt->tm_hour, lt->tm_min, lt->tm_sec, run_id, num_runs,
           (long long)(now - bench_start));
    fflush(stdout);
}

static double calc_mean(double *values, int count)
{
    double sum = 0.0;
    for (int i = 0; i < count; i++)
        sum += values[i];
    return sum / count;
}

static double calc_stddev(double *values, int count)
{
    if (count < 2)
        return 0.0;
    double m = calc_mean(values, count);
    double sum_sq = 0.0;
    for (int i = 0; i < count; i++)
    {
        double diff = values[i] - m;
        sum_sq += diff * diff;
    }
    return sqrt(sum_sq / (count - 1));
}

static const char *g_password = "SharedPassword";
static const char *g_id_a = "client_identif00";
static const char *g_id_b = "server_identif00";
static unsigned char g_P_i[16];
static unsigned char g_P_j[16];

static void init_inputs(void)
{
    memset(g_P_i, 0x01, sizeof(g_P_i));
    memset(g_P_j, 0x02, sizeof(g_P_j));
}

// Per-iteration nanosecond accumulators
typedef struct
{
    double phase1, phase2, phase3;
} ThreePhase;

typedef struct
{
    double precompute, init, rspder, der;
} FourPhase;

static int protoss_once(ThreePhase *acc, int *mismatch)
{
    ReturnTypeInit res_init;
    ReturnTypeRspDer res_rspder;
    unsigned char K_der[PROTOSS_SESSION_KEY_LEN];
    struct timespec start, end;
    size_t pw = strlen(g_password);

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (Init(&res_init, g_password, pw, g_P_i, sizeof(g_P_i), g_P_j, sizeof(g_P_j)) != 0)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &end);
    acc->phase1 += timespec_diff_ns(&start, &end);

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (RspDer(&res_rspder, g_password, pw, g_P_i, sizeof(g_P_i), g_P_j, sizeof(g_P_j), res_init.I) != 0)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &end);
    acc->phase2 += timespec_diff_ns(&start, &end);

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (Der(K_der, &res_init.state, res_rspder.R) != 0)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &end);
    acc->phase3 += timespec_diff_ns(&start, &end);

    if (memcmp(K_der, res_rspder.K, PROTOSS_SESSION_KEY_LEN) != 0)
        *mismatch = 1;
    return 0;
}

static int precomputed_once(FourPhase *acc, int *mismatch)
{
    ProtossPrecomputedState init_state, rsp_state;
    unsigned char I_out[PROTOSS_POINT_LEN];
    unsigned char R_out[PROTOSS_POINT_LEN];
    unsigned char K_init[PROTOSS_SESSION_KEY_LEN];
    unsigned char K_rsp[PROTOSS_SESSION_KEY_LEN];
    struct timespec start, end;
    size_t pw = strlen(g_password);

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (protoss_precomputed_state_create(&init_state, g_P_i, sizeof(g_P_i), g_P_j, sizeof(g_P_j)) != 0)
        return -1;
    if (protoss_precomputed_state_create(&rsp_state, g_P_i, sizeof(g_P_i), g_P_j, sizeof(g_P_j)) != 0)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &end);
    acc->precompute += timespec_diff_ns(&start, &end);

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (precomputed_Init(I_out, &init_state, g_password, pw) != 0)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &end);
    acc->init += timespec_diff_ns(&start, &end);

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (precomputed_RspDer(R_out, K_rsp, &rsp_state, g_password, pw, I_out) != 0)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &end);
    acc->rspder += timespec_diff_ns(&start, &end);

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (precomputed_Der(K_init, &init_state, R_out) != 0)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &end);
    acc->der += timespec_diff_ns(&start, &end);

    if (memcmp(K_init, K_rsp, PROTOSS_SESSION_KEY_LEN) != 0)
        *mismatch = 1;

    protoss_precomputed_state_destroy(&init_state);
    protoss_precomputed_state_destroy(&rsp_state);
    return 0;
}

static int cpace_once(ThreePhase *acc, int *mismatch)
{
    crypto_cpace_state ctx;
    unsigned char public_data[crypto_cpace_PUBLICDATABYTES];
    unsigned char response[crypto_cpace_RESPONSEBYTES];
    crypto_cpace_shared_keys sk_initiator, sk_responder;
    struct timespec start, end;
    size_t pw = strlen(g_password);

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (crypto_cpace_step1(&ctx, public_data, g_password, pw,
                           g_id_a, strlen(g_id_a), g_id_b, strlen(g_id_b),
                           NULL, 0) != 0)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &end);
    acc->phase1 += timespec_diff_ns(&start, &end);

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (crypto_cpace_step2(response, public_data, &sk_responder, g_password, pw,
                           g_id_a, strlen(g_id_a), g_id_b, strlen(g_id_b),
                           NULL, 0) != 0)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &end);
    acc->phase2 += timespec_diff_ns(&start, &end);

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (crypto_cpace_step3(&ctx, &sk_initiator, response) != 0)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &end);
    acc->phase3 += timespec_diff_ns(&start, &end);

    if (memcmp(sk_initiator.client_sk, sk_responder.client_sk, crypto_cpace_SHAREDKEYBYTES) != 0 ||
        memcmp(sk_initiator.server_sk, sk_responder.server_sk, crypto_cpace_SHAREDKEYBYTES) != 0)
        *mismatch = 1;
    return 0;
}

// Per-run averages in microseconds for the three competitors
typedef struct
{
    double pr[3];
    double pc[4];
    double cp[3];
} RunResult;

static int run_rotated(size_t iterations, RunResult *out, int *mismatch)
{
    ThreePhase pr = {0};
    FourPhase pc = {0};
    ThreePhase cp = {0};

    for (size_t i = 0; i < iterations; i++)
    {
        if (protoss_once(&pr, mismatch) != 0)
            return -1;
        if (precomputed_once(&pc, mismatch) != 0)
            return -1;
        if (cpace_once(&cp, mismatch) != 0)
            return -1;
    }

    double n = (double)iterations;
    out->pr[0] = pr.phase1 / n / 1000.0;
    out->pr[1] = pr.phase2 / n / 1000.0;
    out->pr[2] = pr.phase3 / n / 1000.0;
    out->pc[0] = pc.precompute / n / 1000.0;
    out->pc[1] = pc.init / n / 1000.0;
    out->pc[2] = pc.rspder / n / 1000.0;
    out->pc[3] = pc.der / n / 1000.0;
    out->cp[0] = cp.phase1 / n / 1000.0;
    out->cp[1] = cp.phase2 / n / 1000.0;
    out->cp[2] = cp.phase3 / n / 1000.0;
    return 0;
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);
    size_t warmup_iterations = 5000;
    size_t benchmark_iterations = 50000;
    size_t num_runs = 10;

    if (argc >= 2)
        benchmark_iterations = atoi(argv[1]);
    if (argc >= 3)
        num_runs = atoi(argv[2]);
    if (argc >= 4)
        warmup_iterations = atoi(argv[3]);

    logger_log(LOG_BENCHMARK, "Starting PAKE Protocol Comparison Benchmark");
    printf("Starting PAKE Protocol Benchmarking\n");
    printf("==================================\n");

    if (sodium_init() < 0)
    {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

    init_inputs();

    int mismatch = 0;

    printf("Performing warm-up runs (%zu iterations)...\n", warmup_iterations);
    fflush(stdout);
    {
        RunResult warm;
        run_rotated(warmup_iterations, &warm, &mismatch);
    }

    printf("\nStarting main benchmark runs (%zu runs x %zu iterations)...\n", num_runs, benchmark_iterations);

    RunResult *runs = (RunResult *)malloc(num_runs * sizeof(RunResult));
    time_t bench_start = time(NULL);

    for (size_t r = 0; r < num_runs; r++)
    {
        print_run_progress(r + 1, num_runs, bench_start);
        if (run_rotated(benchmark_iterations, &runs[r], &mismatch) != 0)
        {
            fprintf(stderr, "Benchmark failed on run %zu\n", r + 1);
            free(runs);
            return 1;
        }
    }

    if (mismatch)
        fprintf(stderr, "ERROR: shared keys do not match in at least one protocol!\n");

    // Collect each measured quantity across runs to compute mean and stddev
    double *col = (double *)malloc(num_runs * sizeof(double));

    double m_pr[3], s_pr[3], m_pc[4], s_pc[4], m_cp[3], s_cp[3];
    for (int j = 0; j < 3; j++)
    {
        for (size_t r = 0; r < num_runs; r++) col[r] = runs[r].pr[j];
        m_pr[j] = calc_mean(col, num_runs);
        s_pr[j] = calc_stddev(col, num_runs);
    }
    for (int j = 0; j < 4; j++)
    {
        for (size_t r = 0; r < num_runs; r++) col[r] = runs[r].pc[j];
        m_pc[j] = calc_mean(col, num_runs);
        s_pc[j] = calc_stddev(col, num_runs);
    }
    for (int j = 0; j < 3; j++)
    {
        for (size_t r = 0; r < num_runs; r++) col[r] = runs[r].cp[j];
        m_cp[j] = calc_mean(col, num_runs);
        s_cp[j] = calc_stddev(col, num_runs);
    }

    free(col);
    free(runs);

    double pr_total = m_pr[0] + m_pr[1] + m_pr[2];
    double pc_proto = m_pc[1] + m_pc[2] + m_pc[3];
    double pc_total = m_pc[0] + pc_proto;
    double cp_total = m_cp[0] + m_cp[1] + m_cp[2];

    char results[4096];
    snprintf(results, sizeof(results),
             "PAKE Protocol Comparison Benchmark Results\n"
             "=========================================\n"
             "Warm-up iterations: %zu\n"
             "Benchmark iterations: %zu\n"
             "Number of runs: %zu\n\n"
             "PROTOSS (baseline):\n"
             "  Init:     %.3f +/- %.3f us\n"
             "  RspDer:   %.3f +/- %.3f us\n"
             "  Der:      %.3f +/- %.3f us\n"
             "  Total:    %.3f us\n\n"
             "PROTOSS (precomputed):\n"
             "  Precomp:  %.3f +/- %.3f us\n"
             "  Init:     %.3f +/- %.3f us\n"
             "  RspDer:   %.3f +/- %.3f us\n"
             "  Der:      %.3f +/- %.3f us\n"
             "  Protocol: %.3f us (online cost, precompute done ahead)\n"
             "  Total:    %.3f us (precompute time included)\n\n"
             "CPACE:\n"
             "  Step 1:   %.3f +/- %.3f us\n"
             "  Step 2:   %.3f +/- %.3f us\n"
             "  Step 3:   %.3f +/- %.3f us\n"
             "  Total:    %.3f us\n",
             warmup_iterations, benchmark_iterations, num_runs,
             m_pr[0], s_pr[0], m_pr[1], s_pr[1], m_pr[2], s_pr[2], pr_total,
             m_pc[0], s_pc[0], m_pc[1], s_pc[1], m_pc[2], s_pc[2], m_pc[3], s_pc[3], pc_proto, pc_total,
             m_cp[0], s_cp[0], m_cp[1], s_cp[1], m_cp[2], s_cp[2], cp_total);

    printf("\n%s", results);
    logger_log(LOG_BENCHMARK, results);

    char filename[256];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d_%H-%M-%S", t);
    snprintf(filename, sizeof(filename),
             "benchmark_results_it%zu_%s.txt", benchmark_iterations, ts);

    logger_log_to_file(filename, results);
    logger_log(LOG_BENCHMARK, "PAKE Protocol Comparison Benchmark completed");

    printf("\nBenchmark results saved to benchmark_results/sodium/%s\n", filename);
    logger_flush();
    return 0;
}
