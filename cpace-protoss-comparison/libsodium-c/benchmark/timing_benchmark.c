
#include <stdio.h>
#include <string.h>
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

void benchmark_protoss(size_t iterations)
{
    logger_log(LOG_BENCHMARK, "Starting Protoss PAKE benchmark");

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
    double avg_init = (total_init_ns / iterations) / 1000.0;
    double avg_rspder = (total_rspder_ns / iterations) / 1000.0;
    double avg_der = (total_der_ns / iterations) / 1000.0;

    // Log results
    char results[1024];
    snprintf(results, sizeof(results),
             "Protoss PAKE Benchmark Results:\n"
             "Average Init time: %.3f us\n"
             "Average RspDer time: %.3f us\n"
             "Average Der time: %.3f us\n"
             "Total average time per protocol run: %.3f us",
             avg_init, avg_rspder, avg_der,
             avg_init + avg_rspder + avg_der);

    logger_log(LOG_BENCHMARK, results);

    // Also print to console
    printf("\nBenchmarking Protoss PAKE (%zu iterations):\n", iterations);
    printf("%s\n", results);
}

void benchmark_cpace(size_t iterations)
{
    logger_log(LOG_BENCHMARK, "Starting CPACE benchmark");

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
    double avg_step1 = (total_step1_ns / iterations) / 1000.0;
    double avg_step2 = (total_step2_ns / iterations) / 1000.0;
    double avg_step3 = (total_step3_ns / iterations) / 1000.0;

    // Log results
    char results[1024];
    snprintf(results, sizeof(results),
             "CPACE Benchmark Results:\n"
             "Average Step 1 time: %.3f us\n"
             "Average Step 2 time: %.3f us\n"
             "Average Step 3 time: %.3f us\n"
             "Total average time per protocol run: %.3f us",
             avg_step1, avg_step2, avg_step3,
             avg_step1 + avg_step2 + avg_step3);

    logger_log(LOG_BENCHMARK, results);

    // Also print to console
    printf("\nBenchmarking CPACE (%zu iterations):\n", iterations);
    printf("%s\n", results);
}

int main(void)
{
    const size_t warmup_iterations = 5000;
    const size_t benchmark_iterations = 50000;

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

    // Main benchmark runs
    printf("\nStarting main benchmark runs (%zu iterations)...\n", benchmark_iterations);
    benchmark_protoss(benchmark_iterations);
    benchmark_cpace(benchmark_iterations);

    // Save final results to file
    char filename[256];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d_%H-%M-%S", t);
    snprintf(filename, sizeof(filename),
             "benchmark_results_it%zu_%s.txt", benchmark_iterations, ts);

    char final_results[512];
    snprintf(final_results, sizeof(final_results),
             "PAKE Protocol Comparison Benchmark Results\n"
             "=========================================\n"
             "Warm-up iterations: %zu\n"
             "Benchmark iterations: %zu\n\n"
             "Results are logged in the benchmark log file.\n",
             warmup_iterations, benchmark_iterations);

    logger_log_to_file(filename, final_results);
    logger_log(LOG_BENCHMARK, "PAKE Protocol Comparison Benchmark completed");

    printf("\nBenchmark results saved to benchmark_results/sodium/%s\n", filename);
    logger_flush();
    system("pause");
    return 0;
}
