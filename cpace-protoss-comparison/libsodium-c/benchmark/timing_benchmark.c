
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <sodium.h>
#include "protoss_protocol.h"
#include "logger.h"
#include "crypto_cpace.h"

// Helper function to generate random password
static void generate_random_password(char *out, size_t length)
{
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    unsigned char random_bytes[64];
    randombytes_buf(random_bytes, length);
    for (size_t i = 0; i < length; i++)
    {
        out[i] = charset[random_bytes[i] % (sizeof(charset) - 1)];
    }
    out[length] = '\0';
}

// Helper function to generate random bytes
static void generate_random_bytes(unsigned char *out, size_t length)
{
    randombytes_buf(out, length);
}

static double timespec_diff_ns(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec) * 1e9 +
           (end->tv_nsec - start->tv_nsec);
}

static double calc_mean(double *values, int count)
{
    double sum = 0.0;
    for (int i = 0; i < count; i++)
    {
        sum += values[i];
    }
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

void warmup_protoss(size_t warmup_iterations)
{
    logger_log(LOG_BENCHMARK, "Warming up Protoss PAKE");

    for (size_t i = 0; i < warmup_iterations; i++)
    {
        char password[17];
        generate_random_password(password, 16);
        unsigned char P_i[32], P_j[32];
        generate_random_bytes(P_i, 32);
        generate_random_bytes(P_j, 32);

        ReturnTypeInit res_init;
        ReturnTypeRspDer res_rspder;
        unsigned char K_der[PROTOSS_SESSION_KEY_LEN];

        Init(&res_init, password, strlen(password), P_i, 32, P_j, 32);
        RspDer(&res_rspder, password, strlen(password), P_i, 32, P_j, 32, res_init.I);
        Der(K_der, &res_init.state, res_rspder.R);
    }
}

void warmup_cpace(size_t warmup_iterations)
{
    logger_log(LOG_BENCHMARK, "Warming up CPACE");

    for (size_t i = 0; i < warmup_iterations; i++)
    {
        char password[17];
        generate_random_password(password, 16);
        const char *id_a = "client";
        const char *id_b = "server";

        crypto_cpace_state ctx;
        unsigned char public_data[crypto_cpace_PUBLICDATABYTES];
        unsigned char response[crypto_cpace_RESPONSEBYTES];
        crypto_cpace_shared_keys shared_keys;

        crypto_cpace_step1(&ctx, public_data, password, strlen(password),
                           id_a, strlen(id_a), id_b, strlen(id_b),
                           NULL, 0);
        crypto_cpace_step2(response, public_data, &shared_keys, password,
                           strlen(password), id_a, strlen(id_a),
                           id_b, strlen(id_b), NULL, 0);
        crypto_cpace_step3(&ctx, &shared_keys, response);
    }
}

// Returns per-run averages in microseconds via out parameters
void benchmark_protoss(size_t iterations, size_t run_id,
                       double *out_init, double *out_rspder, double *out_der)
{
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg),
             "Run %zu: Starting Protoss PAKE benchmark with %zu iterations", run_id, iterations);
    logger_log(LOG_BENCHMARK, log_msg);

    double total_init_ns = 0;
    double total_rspder_ns = 0;
    double total_der_ns = 0;

    for (size_t i = 0; i < iterations; i++)
    {
        char password[17];
        generate_random_password(password, 16);
        unsigned char P_i[32], P_j[32];
        generate_random_bytes(P_i, 32);
        generate_random_bytes(P_j, 32);

        ReturnTypeInit res_init;
        ReturnTypeRspDer res_rspder;
        unsigned char K_der[PROTOSS_SESSION_KEY_LEN];
        struct timespec start, end;

        // Measure Init
        clock_gettime(CLOCK_MONOTONIC, &start);
        Init(&res_init, password, strlen(password), P_i, 32, P_j, 32);
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_init_ns += timespec_diff_ns(&start, &end);

        // Measure RspDer
        clock_gettime(CLOCK_MONOTONIC, &start);
        RspDer(&res_rspder, password, strlen(password), P_i, 32, P_j, 32, res_init.I);
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_rspder_ns += timespec_diff_ns(&start, &end);

        // Measure Der
        clock_gettime(CLOCK_MONOTONIC, &start);
        Der(K_der, &res_init.state, res_rspder.R);
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_der_ns += timespec_diff_ns(&start, &end);
    }

    // Calculate averages in microseconds
    *out_init = (total_init_ns / iterations) / 1000.0;
    *out_rspder = (total_rspder_ns / iterations) / 1000.0;
    *out_der = (total_der_ns / iterations) / 1000.0;
}

// Returns per-run averages in microseconds via out parameters
void benchmark_cpace(size_t iterations, size_t run_id,
                     double *out_step1, double *out_step2, double *out_step3)
{
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg),
             "Run %zu: Starting CPACE benchmark with %zu iterations", run_id, iterations);
    logger_log(LOG_BENCHMARK, log_msg);

    double total_step1_ns = 0;
    double total_step2_ns = 0;
    double total_step3_ns = 0;

    for (size_t i = 0; i < iterations; i++)
    {
        char password[17];
        generate_random_password(password, 16);
        const char *id_a = "client";
        const char *id_b = "server";

        crypto_cpace_state ctx;
        unsigned char public_data[crypto_cpace_PUBLICDATABYTES];
        unsigned char response[crypto_cpace_RESPONSEBYTES];
        crypto_cpace_shared_keys shared_keys;
        struct timespec start, end;

        // Measure Step 1
        clock_gettime(CLOCK_MONOTONIC, &start);
        crypto_cpace_step1(&ctx, public_data, password, strlen(password),
                           id_a, strlen(id_a), id_b, strlen(id_b),
                           NULL, 0);
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_step1_ns += timespec_diff_ns(&start, &end);

        // Measure Step 2
        clock_gettime(CLOCK_MONOTONIC, &start);
        crypto_cpace_step2(response, public_data, &shared_keys, password,
                           strlen(password), id_a, strlen(id_a),
                           id_b, strlen(id_b), NULL, 0);
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_step2_ns += timespec_diff_ns(&start, &end);

        // Measure Step 3
        clock_gettime(CLOCK_MONOTONIC, &start);
        crypto_cpace_step3(&ctx, &shared_keys, response);
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_step3_ns += timespec_diff_ns(&start, &end);
    }

    // Calculate averages in microseconds
    *out_step1 = (total_step1_ns / iterations) / 1000.0;
    *out_step2 = (total_step2_ns / iterations) / 1000.0;
    *out_step3 = (total_step3_ns / iterations) / 1000.0;
}

int main(int argc, char *argv[])
{
    size_t warmup_iterations = 5000;
    size_t benchmark_iterations = 50000;
    size_t num_runs = 10;

    // Parse optional CLI arguments: [iterations] [num_runs] [warmup_iterations]
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

    // Warm-up runs
    printf("Performing warm-up runs (%zu iterations)...\n", warmup_iterations);
    warmup_protoss(warmup_iterations);
    warmup_cpace(warmup_iterations);

    // Run the benchmark multiple times to average out external variability
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

        double avg_init, avg_rspder, avg_der;
        double avg_step1, avg_step2, avg_step3;

        // Alternate order to avoid ordering bias
        if ((r + 1) % 2 == 1)
        {
            benchmark_protoss(benchmark_iterations, r + 1, &avg_init, &avg_rspder, &avg_der);
            benchmark_cpace(benchmark_iterations, r + 1, &avg_step1, &avg_step2, &avg_step3);
        }
        else
        {
            benchmark_cpace(benchmark_iterations, r + 1, &avg_step1, &avg_step2, &avg_step3);
            benchmark_protoss(benchmark_iterations, r + 1, &avg_init, &avg_rspder, &avg_der);
        }

        protoss_init_runs[r] = avg_init;
        protoss_rspder_runs[r] = avg_rspder;
        protoss_der_runs[r] = avg_der;
        protoss_total_runs[r] = avg_init + avg_rspder + avg_der;

        cpace_step1_runs[r] = avg_step1;
        cpace_step2_runs[r] = avg_step2;
        cpace_step3_runs[r] = avg_step3;
        cpace_total_runs[r] = avg_step1 + avg_step2 + avg_step3;
    }

    // Calculate mean and standard deviation across runs for Protoss
    double mean_protoss_init = calc_mean(protoss_init_runs, num_runs);
    double mean_protoss_rspder = calc_mean(protoss_rspder_runs, num_runs);
    double mean_protoss_der = calc_mean(protoss_der_runs, num_runs);
    double mean_protoss_total = calc_mean(protoss_total_runs, num_runs);

    double std_protoss_init = calc_stddev(protoss_init_runs, num_runs);
    double std_protoss_rspder = calc_stddev(protoss_rspder_runs, num_runs);
    double std_protoss_der = calc_stddev(protoss_der_runs, num_runs);
    double std_protoss_total = calc_stddev(protoss_total_runs, num_runs);

    // Calculate mean and standard deviation across runs for CPace
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

    // Format and log Protoss results
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

    // Format and log CPace results
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

    // Save final results to file
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
