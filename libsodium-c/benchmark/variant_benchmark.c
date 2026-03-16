
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "logger.h"
#include "protoss_protocol.h"
#include "protoss_validated.h"
#include "protoss_orchestrated.h"
#include "protoss_precomputed.h"

static double timespec_diff_ms(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec) * 1000.0 +
           (end->tv_nsec - start->tv_nsec) / 1e6;
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

// ============================================================
// Baseline benchmark
// ============================================================
int run_baseline(int iterations, int run_id, int is_warmup,
                 double *out_init, double *out_rspder, double *out_der)
{
    const char *password = "SharedPassword";
    unsigned char P_i[] = {0x00};
    unsigned char P_j[] = {0x01};

    double init_time = 0.0, rspder_time = 0.0, der_time = 0.0;

    for (int i = 0; i < iterations; i++)
    {
        ReturnTypeInit res_init;
        ReturnTypeRspDer res_rspder;
        unsigned char K_i[PROTOSS_SESSION_KEY_LEN];
        struct timespec start, end;

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (Init(&res_init, password, strlen(password), P_i, 1, P_j, 1) != 0)
            return -1;
        clock_gettime(CLOCK_MONOTONIC, &end);
        init_time += timespec_diff_ms(&start, &end);

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (RspDer(&res_rspder, password, strlen(password), P_i, 1, P_j, 1, res_init.I) != 0)
            return -1;
        clock_gettime(CLOCK_MONOTONIC, &end);
        rspder_time += timespec_diff_ms(&start, &end);

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (Der(K_i, &res_init.state, res_rspder.R) != 0)
            return -1;
        clock_gettime(CLOCK_MONOTONIC, &end);
        der_time += timespec_diff_ms(&start, &end);

        if (i == 0 && run_id == 1 && !is_warmup)
        {
            if (memcmp(K_i, res_rspder.K, PROTOSS_SESSION_KEY_LEN) != 0)
                fprintf(stderr, "ERROR [Baseline]: Session keys don't match!\n");
        }
    }

    *out_init = init_time / iterations;
    *out_rspder = rspder_time / iterations;
    *out_der = der_time / iterations;
    return 0;
}

// ============================================================
// Validated benchmark
// ============================================================
int run_validated(int iterations, int run_id, int is_warmup,
                  double *out_init, double *out_rspder, double *out_der)
{
    const char *password = "SharedPassword";
    unsigned char P_i[] = {0x00};
    unsigned char P_j[] = {0x01};

    double init_time = 0.0, rspder_time = 0.0, der_time = 0.0;

    for (int i = 0; i < iterations; i++)
    {
        ValidatedReturnTypeInit res_init;
        ValidatedReturnTypeRspDer res_rspder;
        unsigned char K_i[PROTOSS_SESSION_KEY_LEN];
        struct timespec start, end;

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (validated_Init(&res_init, password, strlen(password), P_i, 1, P_j, 1) != 0)
            return -1;
        clock_gettime(CLOCK_MONOTONIC, &end);
        init_time += timespec_diff_ms(&start, &end);

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (validated_RspDer(&res_rspder, password, strlen(password), P_i, 1, P_j, 1, res_init.I) != 0)
            return -1;
        clock_gettime(CLOCK_MONOTONIC, &end);
        rspder_time += timespec_diff_ms(&start, &end);

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (validated_Der(K_i, &res_init.state, res_rspder.R) != 0)
            return -1;
        clock_gettime(CLOCK_MONOTONIC, &end);
        der_time += timespec_diff_ms(&start, &end);

        if (i == 0 && run_id == 1 && !is_warmup)
        {
            if (memcmp(K_i, res_rspder.K, PROTOSS_SESSION_KEY_LEN) != 0)
                fprintf(stderr, "ERROR [Validated]: Session keys don't match!\n");
        }
    }

    *out_init = init_time / iterations;
    *out_rspder = rspder_time / iterations;
    *out_der = der_time / iterations;
    return 0;
}

// ============================================================
// Orchestrated benchmark
// ============================================================
int run_orchestrated(int iterations, int run_id, int is_warmup,
                     double *out_init, double *out_rspder, double *out_der)
{
    const char *password = "SharedPassword";
    unsigned char P_i[] = {0x00};
    unsigned char P_j[] = {0x01};

    double init_time = 0.0, rspder_time = 0.0, der_time = 0.0;

    for (int i = 0; i < iterations; i++)
    {
        ProtossOrchestratedState init_state, rsp_state;
        unsigned char I_out[PROTOSS_POINT_LEN];
        unsigned char R_out[PROTOSS_POINT_LEN];
        unsigned char K_init[PROTOSS_SESSION_KEY_LEN];
        unsigned char K_rsp[PROTOSS_SESSION_KEY_LEN];
        struct timespec start, end;

        // State creation happens before the protocol begins
        protoss_orchestrated_state_create(&init_state, P_i, 1, P_j, 1);
        protoss_orchestrated_state_create(&rsp_state, P_i, 1, P_j, 1);

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (orchestrated_Init(I_out, &init_state, password, strlen(password)) != 0)
            return -1;
        clock_gettime(CLOCK_MONOTONIC, &end);
        init_time += timespec_diff_ms(&start, &end);

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (orchestrated_RspDer(R_out, K_rsp, &rsp_state, password, strlen(password), I_out) != 0)
            return -1;
        clock_gettime(CLOCK_MONOTONIC, &end);
        rspder_time += timespec_diff_ms(&start, &end);

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (orchestrated_Der(K_init, &init_state, R_out) != 0)
            return -1;
        clock_gettime(CLOCK_MONOTONIC, &end);
        der_time += timespec_diff_ms(&start, &end);

        if (i == 0 && run_id == 1 && !is_warmup)
        {
            if (memcmp(K_init, K_rsp, PROTOSS_SESSION_KEY_LEN) != 0)
                fprintf(stderr, "ERROR [Orchestrated]: Session keys don't match!\n");
        }

        protoss_orchestrated_state_destroy(&init_state);
        protoss_orchestrated_state_destroy(&rsp_state);
    }

    *out_init = init_time / iterations;
    *out_rspder = rspder_time / iterations;
    *out_der = der_time / iterations;
    return 0;
}

// ============================================================
// Precomputed benchmark
// ============================================================
int run_precomputed(int iterations, int run_id, int is_warmup,
                    double *out_precompute, double *out_init, double *out_rspder, double *out_der)
{
    const char *password = "SharedPassword";
    unsigned char P_i[] = {0x00};
    unsigned char P_j[] = {0x01};

    double precompute_time = 0.0;
    double init_time = 0.0, rspder_time = 0.0, der_time = 0.0;

    for (int i = 0; i < iterations; i++)
    {
        ProtossPrecomputedState init_state, rsp_state;
        unsigned char I_out[PROTOSS_POINT_LEN];
        unsigned char R_out[PROTOSS_POINT_LEN];
        unsigned char K_init[PROTOSS_SESSION_KEY_LEN];
        unsigned char K_rsp[PROTOSS_SESSION_KEY_LEN];
        struct timespec start, end;

        // Time precomputation separately
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (protoss_precomputed_state_create(&init_state, P_i, 1, P_j, 1) != 0)
            return -1;
        if (protoss_precomputed_state_create(&rsp_state, P_i, 1, P_j, 1) != 0)
            return -1;
        clock_gettime(CLOCK_MONOTONIC, &end);
        precompute_time += timespec_diff_ms(&start, &end);

        // Time protocol steps (without precomputation cost)
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (precomputed_Init(I_out, &init_state, password, strlen(password)) != 0)
            return -1;
        clock_gettime(CLOCK_MONOTONIC, &end);
        init_time += timespec_diff_ms(&start, &end);

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (precomputed_RspDer(R_out, K_rsp, &rsp_state, password, strlen(password), I_out) != 0)
            return -1;
        clock_gettime(CLOCK_MONOTONIC, &end);
        rspder_time += timespec_diff_ms(&start, &end);

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (precomputed_Der(K_init, &init_state, R_out) != 0)
            return -1;
        clock_gettime(CLOCK_MONOTONIC, &end);
        der_time += timespec_diff_ms(&start, &end);

        if (i == 0 && run_id == 1 && !is_warmup)
        {
            if (memcmp(K_init, K_rsp, PROTOSS_SESSION_KEY_LEN) != 0)
                fprintf(stderr, "ERROR [Precomputed]: Session keys don't match!\n");
        }

        protoss_precomputed_state_destroy(&init_state);
        protoss_precomputed_state_destroy(&rsp_state);
    }

    *out_precompute = precompute_time / iterations;
    *out_init = init_time / iterations;
    *out_rspder = rspder_time / iterations;
    *out_der = der_time / iterations;
    return 0;
}

// ============================================================
// Main
// ============================================================
int main(int argc, char *argv[])
{
    logger_log(LOG_BENCHMARK, "See the benchmark_results/variants folder for the info of this run.");

    if (sodium_init() < 0)
    {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

    int iterations = 10000;
    int num_runs = 10;

    if (argc >= 2)
        iterations = atoi(argv[1]);
    if (argc >= 3)
        num_runs = atoi(argv[2]);

    printf("Protoss Protocol Variant Comparison Benchmark\n");
    printf("==============================================\n");
    printf("Config: %d iterations x %d runs\n\n", iterations, num_runs);

    // Warmup all variants
    printf("Performing warmup...\n");
    {
        double d1, d2, d3, d4;
        run_baseline(100, 0, 1, &d1, &d2, &d3);
        run_validated(100, 0, 1, &d1, &d2, &d3);
        run_orchestrated(100, 0, 1, &d1, &d2, &d3);
        run_precomputed(100, 0, 1, &d4, &d1, &d2, &d3);
    }
    printf("Warmup complete.\n\n");

    // Allocate result arrays
    double *bl_init   = malloc(num_runs * sizeof(double));
    double *bl_rspder = malloc(num_runs * sizeof(double));
    double *bl_der    = malloc(num_runs * sizeof(double));

    double *vl_init   = malloc(num_runs * sizeof(double));
    double *vl_rspder = malloc(num_runs * sizeof(double));
    double *vl_der    = malloc(num_runs * sizeof(double));

    double *or_init   = malloc(num_runs * sizeof(double));
    double *or_rspder = malloc(num_runs * sizeof(double));
    double *or_der    = malloc(num_runs * sizeof(double));

    double *pc_precomp = malloc(num_runs * sizeof(double));
    double *pc_init    = malloc(num_runs * sizeof(double));
    double *pc_rspder  = malloc(num_runs * sizeof(double));
    double *pc_der     = malloc(num_runs * sizeof(double));

    // Run benchmarks with alternating order
    for (int r = 0; r < num_runs; r++)
    {
        printf("Run %d/%d...\n", r + 1, num_runs);

        if (r % 2 == 0)
        {
            // Order: baseline -> validated -> orchestrated -> precomputed
            if (run_baseline(iterations, r + 1, 0, &bl_init[r], &bl_rspder[r], &bl_der[r]) != 0)
            { fprintf(stderr, "Baseline failed on run %d\n", r + 1); return 1; }
            if (run_validated(iterations, r + 1, 0, &vl_init[r], &vl_rspder[r], &vl_der[r]) != 0)
            { fprintf(stderr, "Validated failed on run %d\n", r + 1); return 1; }
            if (run_orchestrated(iterations, r + 1, 0, &or_init[r], &or_rspder[r], &or_der[r]) != 0)
            { fprintf(stderr, "Orchestrated failed on run %d\n", r + 1); return 1; }
            if (run_precomputed(iterations, r + 1, 0, &pc_precomp[r], &pc_init[r], &pc_rspder[r], &pc_der[r]) != 0)
            { fprintf(stderr, "Precomputed failed on run %d\n", r + 1); return 1; }
        }
        else
        {
            // Reverse order: precomputed -> orchestrated -> validated -> baseline
            if (run_precomputed(iterations, r + 1, 0, &pc_precomp[r], &pc_init[r], &pc_rspder[r], &pc_der[r]) != 0)
            { fprintf(stderr, "Precomputed failed on run %d\n", r + 1); return 1; }
            if (run_orchestrated(iterations, r + 1, 0, &or_init[r], &or_rspder[r], &or_der[r]) != 0)
            { fprintf(stderr, "Orchestrated failed on run %d\n", r + 1); return 1; }
            if (run_validated(iterations, r + 1, 0, &vl_init[r], &vl_rspder[r], &vl_der[r]) != 0)
            { fprintf(stderr, "Validated failed on run %d\n", r + 1); return 1; }
            if (run_baseline(iterations, r + 1, 0, &bl_init[r], &bl_rspder[r], &bl_der[r]) != 0)
            { fprintf(stderr, "Baseline failed on run %d\n", r + 1); return 1; }
        }
    }

    // Calculate statistics
    double m_bl_init = calc_mean(bl_init, num_runs), s_bl_init = calc_stddev(bl_init, num_runs);
    double m_bl_rsp  = calc_mean(bl_rspder, num_runs), s_bl_rsp = calc_stddev(bl_rspder, num_runs);
    double m_bl_der  = calc_mean(bl_der, num_runs), s_bl_der = calc_stddev(bl_der, num_runs);

    double m_vl_init = calc_mean(vl_init, num_runs), s_vl_init = calc_stddev(vl_init, num_runs);
    double m_vl_rsp  = calc_mean(vl_rspder, num_runs), s_vl_rsp = calc_stddev(vl_rspder, num_runs);
    double m_vl_der  = calc_mean(vl_der, num_runs), s_vl_der = calc_stddev(vl_der, num_runs);

    double m_or_init = calc_mean(or_init, num_runs), s_or_init = calc_stddev(or_init, num_runs);
    double m_or_rsp  = calc_mean(or_rspder, num_runs), s_or_rsp = calc_stddev(or_rspder, num_runs);
    double m_or_der  = calc_mean(or_der, num_runs), s_or_der = calc_stddev(or_der, num_runs);

    double m_pc_pre  = calc_mean(pc_precomp, num_runs), s_pc_pre = calc_stddev(pc_precomp, num_runs);
    double m_pc_init = calc_mean(pc_init, num_runs), s_pc_init = calc_stddev(pc_init, num_runs);
    double m_pc_rsp  = calc_mean(pc_rspder, num_runs), s_pc_rsp = calc_stddev(pc_rspder, num_runs);
    double m_pc_der  = calc_mean(pc_der, num_runs), s_pc_der = calc_stddev(pc_der, num_runs);

    double bl_total = m_bl_init + m_bl_rsp + m_bl_der;
    double vl_total = m_vl_init + m_vl_rsp + m_vl_der;
    double or_total = m_or_init + m_or_rsp + m_or_der;
    double pc_proto = m_pc_init + m_pc_rsp + m_pc_der;
    double pc_total = m_pc_pre + pc_proto;

    // Print results
    printf("\n");
    printf("=============================================\n");
    printf("  Protoss Variant Comparison Results\n");
    printf("  %d iterations x %d runs\n", iterations, num_runs);
    printf("=============================================\n\n");

    printf("%-14s | %-22s | %-22s | %-22s | %-22s\n",
           "Phase", "Baseline", "Validated", "Orchestrated", "Precomputed (proto)");
    printf("%-14s-+-%-22s-+-%-22s-+-%-22s-+-%-22s\n",
           "--------------", "----------------------", "----------------------",
           "----------------------", "----------------------");
    printf("%-14s | %8.4f +/- %-8.4f | %8.4f +/- %-8.4f | %8.4f +/- %-8.4f | %8.4f +/- %-8.4f\n",
           "Init (ms)", m_bl_init, s_bl_init, m_vl_init, s_vl_init, m_or_init, s_or_init, m_pc_init, s_pc_init);
    printf("%-14s | %8.4f +/- %-8.4f | %8.4f +/- %-8.4f | %8.4f +/- %-8.4f | %8.4f +/- %-8.4f\n",
           "RspDer (ms)", m_bl_rsp, s_bl_rsp, m_vl_rsp, s_vl_rsp, m_or_rsp, s_or_rsp, m_pc_rsp, s_pc_rsp);
    printf("%-14s | %8.4f +/- %-8.4f | %8.4f +/- %-8.4f | %8.4f +/- %-8.4f | %8.4f +/- %-8.4f\n",
           "Der (ms)", m_bl_der, s_bl_der, m_vl_der, s_vl_der, m_or_der, s_or_der, m_pc_der, s_pc_der);
    printf("%-14s-+-%-22s-+-%-22s-+-%-22s-+-%-22s\n",
           "--------------", "----------------------", "----------------------",
           "----------------------", "----------------------");
    printf("%-14s | %8.4f               | %8.4f               | %8.4f               | %8.4f\n",
           "Total (ms)", bl_total, vl_total, or_total, pc_proto);
    printf("\n");
    printf("Precomputed: precompute cost = %.4f +/- %.4f ms, total with precompute = %.4f ms\n",
           m_pc_pre, s_pc_pre, pc_total);

    // Save results to file
    char results[4096];
    snprintf(results, sizeof(results),
             "Protoss Variant Comparison Benchmark Results\n"
             "Config: %d iterations x %d runs\n"
             "=============================================\n\n"
             "BASELINE:\n"
             "  Init:     %.4f +/- %.4f ms\n"
             "  RspDer:   %.4f +/- %.4f ms\n"
             "  Der:      %.4f +/- %.4f ms\n"
             "  Total:    %.4f ms\n\n"
             "VALIDATED (with point validation):\n"
             "  Init:     %.4f +/- %.4f ms\n"
             "  RspDer:   %.4f +/- %.4f ms\n"
             "  Der:      %.4f +/- %.4f ms\n"
             "  Total:    %.4f ms\n\n"
             "ORCHESTRATED (state manager, no precompute):\n"
             "  Init:     %.4f +/- %.4f ms\n"
             "  RspDer:   %.4f +/- %.4f ms\n"
             "  Der:      %.4f +/- %.4f ms\n"
             "  Total:    %.4f ms\n\n"
             "PRECOMPUTED (state manager + precomputation):\n"
             "  Precomp:  %.4f +/- %.4f ms\n"
             "  Init:     %.4f +/- %.4f ms\n"
             "  RspDer:   %.4f +/- %.4f ms\n"
             "  Der:      %.4f +/- %.4f ms\n"
             "  Protocol: %.4f ms (without precompute)\n"
             "  Total:    %.4f ms (with precompute)\n",
             iterations, num_runs,
             m_bl_init, s_bl_init, m_bl_rsp, s_bl_rsp, m_bl_der, s_bl_der, bl_total,
             m_vl_init, s_vl_init, m_vl_rsp, s_vl_rsp, m_vl_der, s_vl_der, vl_total,
             m_or_init, s_or_init, m_or_rsp, s_or_rsp, m_or_der, s_or_der, or_total,
             m_pc_pre, s_pc_pre, m_pc_init, s_pc_init, m_pc_rsp, s_pc_rsp, m_pc_der, s_pc_der,
             pc_proto, pc_total);

    char filename[256];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(filename, sizeof(filename), "variant_benchmark_it%d_", iterations);
    strftime(filename + strlen(filename), sizeof(filename) - strlen(filename),
             "%Y-%m-%d_%H-%M-%S.txt", t);

    logger_log_to_file(filename, results);
    printf("\nResults saved to benchmark_results/sodium/%s\n", filename);

    // Free all arrays
    free(bl_init); free(bl_rspder); free(bl_der);
    free(vl_init); free(vl_rspder); free(vl_der);
    free(or_init); free(or_rspder); free(or_der);
    free(pc_precomp); free(pc_init); free(pc_rspder); free(pc_der);

    logger_flush();
    system("pause");
    return 0;
}
