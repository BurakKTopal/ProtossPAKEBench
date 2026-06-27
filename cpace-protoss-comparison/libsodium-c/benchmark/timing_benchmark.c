
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <sodium.h>
#include "protoss_protocol.h"
#include "logger.h"
#include "crypto_cpace.h"

static double timespec_diff_ns(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec) * 1e9 +
           (end->tv_nsec - start->tv_nsec);
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

static int protoss_once(double *init_t, double *rspder_t, double *der_t, int *mismatch)
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
    *init_t += timespec_diff_ns(&start, &end);

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (RspDer(&res_rspder, g_password, pw, g_P_i, sizeof(g_P_i), g_P_j, sizeof(g_P_j), res_init.I) != 0)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &end);
    *rspder_t += timespec_diff_ns(&start, &end);

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (Der(K_der, &res_init.state, res_rspder.R) != 0)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &end);
    *der_t += timespec_diff_ns(&start, &end);

    if (memcmp(K_der, res_rspder.K, PROTOSS_SESSION_KEY_LEN) != 0)
        *mismatch = 1;
    return 0;
}

static int cpace_once(double *step1_t, double *step2_t, double *step3_t, int *mismatch)
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
    *step1_t += timespec_diff_ns(&start, &end);

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (crypto_cpace_step2(response, public_data, &sk_responder, g_password, pw,
                           g_id_a, strlen(g_id_a), g_id_b, strlen(g_id_b),
                           NULL, 0) != 0)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &end);
    *step2_t += timespec_diff_ns(&start, &end);

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (crypto_cpace_step3(&ctx, &sk_initiator, response) != 0)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &end);
    *step3_t += timespec_diff_ns(&start, &end);

    if (memcmp(sk_initiator.client_sk, sk_responder.client_sk, crypto_cpace_SHAREDKEYBYTES) != 0 ||
        memcmp(sk_initiator.server_sk, sk_responder.server_sk, crypto_cpace_SHAREDKEYBYTES) != 0)
        *mismatch = 1;
    return 0;
}

static int run_rotated(size_t iterations,
                       double *pr_init, double *pr_rspder, double *pr_der,
                       double *cp_step1, double *cp_step2, double *cp_step3,
                       int *mismatch)
{
    double pi = 0, pr = 0, pd = 0;
    double c1 = 0, c2 = 0, c3 = 0;

    for (size_t i = 0; i < iterations; i++)
    {
        if (protoss_once(&pi, &pr, &pd, mismatch) != 0)
            return -1;
        if (cpace_once(&c1, &c2, &c3, mismatch) != 0)
            return -1;
    }

    *pr_init = (pi / iterations) / 1000.0;
    *pr_rspder = (pr / iterations) / 1000.0;
    *pr_der = (pd / iterations) / 1000.0;
    *cp_step1 = (c1 / iterations) / 1000.0;
    *cp_step2 = (c2 / iterations) / 1000.0;
    *cp_step3 = (c3 / iterations) / 1000.0;
    return 0;
}

int main(int argc, char *argv[])
{
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
    {
        double d[6];
        run_rotated(warmup_iterations, &d[0], &d[1], &d[2], &d[3], &d[4], &d[5], &mismatch);
    }

    printf("\nStarting main benchmark runs (%zu runs x %zu iterations)...\n", num_runs, benchmark_iterations);

    double *protoss_init_runs = (double *)malloc(num_runs * sizeof(double));
    double *protoss_rspder_runs = (double *)malloc(num_runs * sizeof(double));
    double *protoss_der_runs = (double *)malloc(num_runs * sizeof(double));
    double *protoss_total_runs = (double *)malloc(num_runs * sizeof(double));

    double *cpace_step1_runs = (double *)malloc(num_runs * sizeof(double));
    double *cpace_step2_runs = (double *)malloc(num_runs * sizeof(double));
    double *cpace_step3_runs = (double *)malloc(num_runs * sizeof(double));
    double *cpace_total_runs = (double *)malloc(num_runs * sizeof(double));

    for (size_t r = 0; r < num_runs; r++)
    {
        printf("\n--- Run %zu of %zu ---\n", r + 1, num_runs);

        double pr_init, pr_rspder, pr_der;
        double cp_step1, cp_step2, cp_step3;

        if (run_rotated(benchmark_iterations,
                        &pr_init, &pr_rspder, &pr_der,
                        &cp_step1, &cp_step2, &cp_step3, &mismatch) != 0)
        {
            fprintf(stderr, "Benchmark failed on run %zu\n", r + 1);
            return 1;
        }

        protoss_init_runs[r] = pr_init;
        protoss_rspder_runs[r] = pr_rspder;
        protoss_der_runs[r] = pr_der;
        protoss_total_runs[r] = pr_init + pr_rspder + pr_der;

        cpace_step1_runs[r] = cp_step1;
        cpace_step2_runs[r] = cp_step2;
        cpace_step3_runs[r] = cp_step3;
        cpace_total_runs[r] = cp_step1 + cp_step2 + cp_step3;
    }

    if (mismatch)
        fprintf(stderr, "ERROR: shared keys do not match in at least one protocol!\n");

    double mean_protoss_init = calc_mean(protoss_init_runs, num_runs);
    double mean_protoss_rspder = calc_mean(protoss_rspder_runs, num_runs);
    double mean_protoss_der = calc_mean(protoss_der_runs, num_runs);
    double mean_protoss_total = calc_mean(protoss_total_runs, num_runs);

    double std_protoss_init = calc_stddev(protoss_init_runs, num_runs);
    double std_protoss_rspder = calc_stddev(protoss_rspder_runs, num_runs);
    double std_protoss_der = calc_stddev(protoss_der_runs, num_runs);
    double std_protoss_total = calc_stddev(protoss_total_runs, num_runs);

    double mean_cpace_step1 = calc_mean(cpace_step1_runs, num_runs);
    double mean_cpace_step2 = calc_mean(cpace_step2_runs, num_runs);
    double mean_cpace_step3 = calc_mean(cpace_step3_runs, num_runs);
    double mean_cpace_total = calc_mean(cpace_total_runs, num_runs);

    double std_cpace_step1 = calc_stddev(cpace_step1_runs, num_runs);
    double std_cpace_step2 = calc_stddev(cpace_step2_runs, num_runs);
    double std_cpace_step3 = calc_stddev(cpace_step3_runs, num_runs);
    double std_cpace_total = calc_stddev(cpace_total_runs, num_runs);

    free(protoss_init_runs); free(protoss_rspder_runs); free(protoss_der_runs); free(protoss_total_runs);
    free(cpace_step1_runs); free(cpace_step2_runs); free(cpace_step3_runs); free(cpace_total_runs);

    char protoss_results[1024];
    snprintf(protoss_results, sizeof(protoss_results),
             "Protoss PAKE Benchmark Results (%zu iterations x %zu runs):\n"
             "Average Init time: %.3f +/- %.3f us\n"
             "Average RspDer time: %.3f +/- %.3f us\n"
             "Average Der time: %.3f +/- %.3f us\n"
             "Total average time per protocol run: %.3f +/- %.3f us",
             benchmark_iterations, num_runs,
             mean_protoss_init, std_protoss_init,
             mean_protoss_rspder, std_protoss_rspder,
             mean_protoss_der, std_protoss_der,
             mean_protoss_total, std_protoss_total);

    logger_log(LOG_BENCHMARK, protoss_results);

    char cpace_results[1024];
    snprintf(cpace_results, sizeof(cpace_results),
             "CPACE Benchmark Results (%zu iterations x %zu runs):\n"
             "Average Step 1 time: %.3f +/- %.3f us\n"
             "Average Step 2 time: %.3f +/- %.3f us\n"
             "Average Step 3 time: %.3f +/- %.3f us\n"
             "Total average time per protocol run: %.3f +/- %.3f us",
             benchmark_iterations, num_runs,
             mean_cpace_step1, std_cpace_step1,
             mean_cpace_step2, std_cpace_step2,
             mean_cpace_step3, std_cpace_step3,
             mean_cpace_total, std_cpace_total);

    logger_log(LOG_BENCHMARK, cpace_results);

    char filename[256];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d_%H-%M-%S", t);
    snprintf(filename, sizeof(filename),
             "benchmark_results_it%zu_%s.txt", benchmark_iterations, ts);

    char final_results[4096];
    snprintf(final_results, sizeof(final_results),
             "PAKE Protocol Comparison Benchmark Results\n"
             "=========================================\n"
             "Warm-up iterations: %zu\n"
             "Benchmark iterations: %zu\n"
             "Number of runs: %zu\n\n"
             "%s\n\n"
             "%s\n",
             warmup_iterations, benchmark_iterations, num_runs,
             protoss_results, cpace_results);

    logger_log_to_file(filename, final_results);
    logger_log(LOG_BENCHMARK, "PAKE Protocol Comparison Benchmark completed");

    printf("\nBenchmark results saved to benchmark_results/sodium/%s\n", filename);
    logger_flush();
    system("pause");
    return 0;
}
