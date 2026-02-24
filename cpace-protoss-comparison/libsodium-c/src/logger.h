#ifndef LOGGER_H
#define LOGGER_H

typedef enum
{
    LOG_INFO,
    LOG_ERROR,
    LOG_DEBUG,
    LOG_BENCHMARK
} LoggingKeyword;

void logger_log(LoggingKeyword keyword, const char *description);
void logger_log_to_file(const char *filename, const char *content);
void logger_flush(void);

#endif // LOGGER_H
