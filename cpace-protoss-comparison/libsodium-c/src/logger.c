
#include "logger.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <direct.h>

#define MAX_LOGS 2000
#define MAX_LOG_ENTRY_LEN 1024

static char logs[MAX_LOGS][MAX_LOG_ENTRY_LEN];
static int log_count = 0;

static void get_timestamp(char *buf, size_t len)
{
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", t);
}

void logger_log(LoggingKeyword keyword, const char *description)
{
    if (log_count >= MAX_LOGS)
        return;

    const char *kw_str;
    switch (keyword)
    {
    case LOG_INFO:
        kw_str = "INFO";
        break;
    case LOG_ERROR:
        kw_str = "ERROR";
        break;
    case LOG_DEBUG:
        kw_str = "DEBUG";
        break;
    case LOG_BENCHMARK:
        kw_str = "BENCHMARK";
        break;
    default:
        kw_str = "UNKNOWN";
        break;
    }

    char ts[64];
    get_timestamp(ts, sizeof(ts));
    snprintf(logs[log_count], MAX_LOG_ENTRY_LEN,
             "[%s] %s : %s", ts, kw_str, description);
    log_count++;

    printf("[%s - %lld] %s\n", kw_str, (long long)time(NULL), description);
}

void logger_log_to_file(const char *filename, const char *content)
{
    _mkdir("benchmark_results");
    _mkdir("benchmark_results/sodium");

    char path[512];
    snprintf(path, sizeof(path), "benchmark_results/sodium/%s", filename);
    FILE *f = fopen(path, "a");
    if (f)
    {
        fprintf(f, "%s\n", content);
        fclose(f);
    }
}

void logger_flush(void)
{
    _mkdir("logs");
    _mkdir("logs/sodium");

    char filename[256];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(filename, sizeof(filename),
             "logs/sodium/log_%Y-%m-%d_%H-%M-%S.txt", t);

    FILE *f = fopen(filename, "w");
    if (f)
    {
        for (int i = 0; i < log_count; i++)
        {
            fprintf(f, "%s\n", logs[i]);
        }
        fclose(f);
    }
}
