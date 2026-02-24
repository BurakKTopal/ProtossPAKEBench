
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "logger.h"
#include "protoss_protocol.h"

static double timespec_diff_ms(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec) * 1000.0 +
           (end->tv_nsec - start->tv_nsec) / 1e6;
}

void run_benchmark(int iterations)
{
    printf("Running Protoss protocol benchmark with %d iterations...\n", iterations);

    // Configure test params
    const char *password = "SharedPassword";
    unsigned char P_i[] = {0x00};
    unsigned char P_j[] = {0x01};

    // Initialize timing variables
    double init_time = 0.0;
    double rspder_time = 0.0;
    double der_time = 0.0;

    // Run the test multiple times to calculate average times
    for (int i = 0; i < iterations; i++)
    {
        ReturnTypeInit res_init;
        ReturnTypeRspDer res_rspder;
        unsigned char session_key_i[PROTOSS_SESSION_KEY_LEN];
        struct timespec start, end;

        // Time Init step
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (Init(&res_init, password, strlen(password), P_i, 1, P_j, 1) != 0)
        {
            fprintf(stderr, "ERROR: Init failed at iteration %d\n", i);
            return;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        init_time += timespec_diff_ms(&start, &end);

        // Time RspDer step
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (RspDer(&res_rspder, password, strlen(password),
                   P_i, 1, P_j, 1, res_init.I) != 0)
        {
            fprintf(stderr, "ERROR: RspDer failed at iteration %d\n", i);
            return;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        rspder_time += timespec_diff_ms(&start, &end);

        // Time Der step
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (Der(session_key_i, &res_init.state, res_rspder.R) != 0)
        {
            fprintf(stderr, "ERROR: Der failed at iteration %d\n", i);
            return;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        der_time += timespec_diff_ms(&start, &end);

        // We only verify keys match in the first iteration
        if (i == 0)
        {
            if (memcmp(session_key_i, res_rspder.K, PROTOSS_SESSION_KEY_LEN) != 0)
            {
                fprintf(stderr, "ERROR: Session keys don't match!\n");
            }
        }
    }

    // Calculate average times
    double avg_init_ms = init_time / iterations;
    double avg_rspder_ms = rspder_time / iterations;
    double avg_der_ms = der_time / iterations;
    double avg_total_ms = avg_init_ms + avg_rspder_ms + avg_der_ms;

    // Save results to file
    char results[2048];
    snprintf(results, sizeof(results),
             "Benchmark Results with %d iterations\n"
             "Hash Lengths: %d bytes input for Ristretto hash-to-point fn, %d bytes of session key\n"
             "-------------------------\n"
             "Avg. Init phase:     %.3f ms\n"
             "Avg. RspDer phase:   %.3f ms\n"
             "Avg. Der phase:      %.3f ms\n"
             "-------------------------\n"
             "Avg. Total time:     %.3f ms\n"
             "\nRelative Cost:\n"
             "Init phase:     %.3f%%\n"
             "RspDer phase:   %.3f%%\n"
             "Der phase:      %.3f%%\n",
             iterations,
             PROTOSS_HASH_INPUT_LEN, PROTOSS_SESSION_KEY_LEN,
             avg_init_ms, avg_rspder_ms, avg_der_ms, avg_total_ms,
             avg_init_ms / avg_total_ms * 100,
             avg_rspder_ms / avg_total_ms * 100,
             avg_der_ms / avg_total_ms * 100);

    // Get current timestamp for the filename
    char filename[256];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(filename, sizeof(filename), "benchmark_results_it", t);
    snprintf(filename + strlen(filename), sizeof(filename) - strlen(filename),
             "%d_", iterations);
    strftime(filename + strlen(filename), sizeof(filename) - strlen(filename),
             "%Y-%m-%d_%H-%M-%S.txt", t);

    // Save to file in benchmark_results folder
    logger_log_to_file(filename, results);
    printf("\nBenchmark results saved to benchmark_results/sodium/%s\n", filename);
}

int main(void)
{
    logger_log(LOG_BENCHMARK, "See the benchmark_results/sodium folder for the info of this run.");
    if (sodium_init() < 0)
    {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

    printf("Protoss Protocol Timing Benchmark\n");
    printf("=================================\n");

    // First run a warmup to avoid cold-start effects
    printf("Performing warmup runs...\n");
    run_benchmark(100);

    // Then run the actual benchmark
    printf("\nRunning main benchmark...\n");
    run_benchmark(10000);

    logger_flush();
    system("pause");
    return 0;
}
