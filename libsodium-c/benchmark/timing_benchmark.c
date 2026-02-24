
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "logger.h"
#include "protoss_protocol.h"

static double timespec_diff_ms(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec) * 1000.0 +
           (end->tv_nsec - start->tv_nsec) / 1e6;
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

// Returns 0 on success, -1 on failure.
// On success, stores per-run averages in out_init_ms, out_rspder_ms, out_der_ms.
int run_benchmark(int iterations, int run_id, int is_warmup,
                  double *out_init_ms, double *out_rspder_ms, double *out_der_ms)
{
    if (is_warmup)
        printf("Warmup: Running Protoss protocol benchmark with %d iterations...\n", iterations);
    else
        printf("Run %d: Running Protoss protocol benchmark with %d iterations...\n", run_id, iterations);

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
            return -1;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        init_time += timespec_diff_ms(&start, &end);

        // Time RspDer step
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (RspDer(&res_rspder, password, strlen(password),
                   P_i, 1, P_j, 1, res_init.I) != 0)
        {
            fprintf(stderr, "ERROR: RspDer failed at iteration %d\n", i);
            return -1;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        rspder_time += timespec_diff_ms(&start, &end);

        // Time Der step
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (Der(session_key_i, &res_init.state, res_rspder.R) != 0)
        {
            fprintf(stderr, "ERROR: Der failed at iteration %d\n", i);
            return -1;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        der_time += timespec_diff_ms(&start, &end);

        // We only verify keys match in the first iteration of the first run
        if (i == 0 && run_id == 1 && !is_warmup)
        {
            if (memcmp(session_key_i, res_rspder.K, PROTOSS_SESSION_KEY_LEN) != 0)
            {
                fprintf(stderr, "ERROR: Session keys don't match!\n");
            }
        }
    }

    // Calculate average times
    *out_init_ms = init_time / iterations;
    *out_rspder_ms = rspder_time / iterations;
    *out_der_ms = der_time / iterations;

    return 0;
}

int main(int argc, char *argv[])
{
    logger_log(LOG_BENCHMARK, "See the benchmark_results/sodium folder for the info of this run.");
    if (sodium_init() < 0)
    {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

    // Default parameters
    int iterations = 10000;
    int num_runs = 10;

    // Parse optional CLI arguments: [iterations] [num_runs]
    if (argc >= 2)
        iterations = atoi(argv[1]);
    if (argc >= 3)
        num_runs = atoi(argv[2]);

    printf("Protoss Protocol Timing Benchmark\n");
    printf("=================================\n");

    // First run a warmup to avoid cold-start effects
    printf("Performing warmup runs...\n");
    double dummy_init, dummy_rspder, dummy_der;
    run_benchmark(100, 0, 1, &dummy_init, &dummy_rspder, &dummy_der);

    // Run the benchmark multiple times to average out external variability
    printf("\nRunning main benchmark (%d runs x %d iterations)...\n", num_runs, iterations);
    double *run_init = (double *)malloc(num_runs * sizeof(double));
    double *run_rspder = (double *)malloc(num_runs * sizeof(double));
    double *run_der = (double *)malloc(num_runs * sizeof(double));
    double *run_total = (double *)malloc(num_runs * sizeof(double));

    for (int r = 0; r < num_runs; r++)
    {
        double avg_init, avg_rspder, avg_der;
        if (run_benchmark(iterations, r + 1, 0, &avg_init, &avg_rspder, &avg_der) != 0)
        {
            fprintf(stderr, "ERROR: Run %d failed, aborting.\n", r + 1);
            free(run_init); free(run_rspder); free(run_der); free(run_total);
            return 1;
        }
        run_init[r] = avg_init;
        run_rspder[r] = avg_rspder;
        run_der[r] = avg_der;
        run_total[r] = avg_init + avg_rspder + avg_der;
    }

    // Calculate mean and standard deviation across runs
    double mean_init = calc_mean(run_init, num_runs);
    double mean_rspder = calc_mean(run_rspder, num_runs);
    double mean_der = calc_mean(run_der, num_runs);
    double mean_total = calc_mean(run_total, num_runs);

    double std_init = calc_stddev(run_init, num_runs);
    double std_rspder = calc_stddev(run_rspder, num_runs);
    double std_der = calc_stddev(run_der, num_runs);
    double std_total = calc_stddev(run_total, num_runs);

    free(run_init); free(run_rspder); free(run_der); free(run_total);

    // Save results to file
    char results[2048];
    snprintf(results, sizeof(results),
             "Benchmark Results with %d iterations x %d runs\n"
             "Hash Lengths: %d bytes input for Ristretto hash-to-point fn, %d bytes of session key\n"
             "-------------------------\n"
             "Avg. Init phase:     %.3f +/- %.3f ms\n"
             "Avg. RspDer phase:   %.3f +/- %.3f ms\n"
             "Avg. Der phase:      %.3f +/- %.3f ms\n"
             "-------------------------\n"
             "Avg. Total time:     %.3f +/- %.3f ms\n"
             "\nRelative Cost:\n"
             "Init phase:     %.3f%%\n"
             "RspDer phase:   %.3f%%\n"
             "Der phase:      %.3f%%\n",
             iterations, num_runs,
             PROTOSS_HASH_INPUT_LEN, PROTOSS_SESSION_KEY_LEN,
             mean_init, std_init, mean_rspder, std_rspder, mean_der, std_der,
             mean_total, std_total,
             mean_init / mean_total * 100,
             mean_rspder / mean_total * 100,
             mean_der / mean_total * 100);

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

    logger_flush();
    system("pause");
    return 0;
}
