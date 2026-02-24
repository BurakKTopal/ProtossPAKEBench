#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <string>
#include <vector>

enum class LoggingKeyword
{
    INFO,
    ERROR,
    DEBUG,
    BENCHMARK
};

class Logger
{
public:
    static Logger &get_instance();
    void log(LoggingKeyword keyword, const std::string &description);
    void log_to_file(const std::string &filename, const std::string &content);
    Logger(const Logger &) = delete;
    Logger &operator=(const Logger &) = delete;

private:
    Logger();
    ~Logger();
    std::vector<std::string> logs_;
    static std::string get_timestamp();
};

#endif // LOGGER_HPP