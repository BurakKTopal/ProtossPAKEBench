#include "logger.hpp"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <ctime>
#include <sstream>
#include <filesystem>

Logger::Logger()
{
    logs_.reserve(1000);
}

Logger::~Logger()
{
    // Creates logs folder to put the different loggings in there
    std::filesystem::create_directory("logs");
    std::filesystem::create_directory("logs/sodium");
    auto now = std::time(nullptr);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now), "logs/sodium/log_%Y-%m-%d_%H-%M-%S.txt");
    std::ofstream file(ss.str(), std::ios::out | std::ios::trunc);
    if (file.is_open())
    {
        for (const auto &log : logs_)
        {
            file << log << '\n';
        }
        file.close();
    }
}

Logger &Logger::get_instance()
{
    static Logger instance;
    return instance;
}

std::string Logger::get_timestamp()
{
    auto now = std::time(nullptr);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void Logger::log(LoggingKeyword keyword, const std::string &description)
{
    std::string keyword_str;
    switch (keyword)
    {
    case LoggingKeyword::INFO:
        keyword_str = "INFO";
        break;
    case LoggingKeyword::ERROR:
        keyword_str = "ERROR";
        break;
    case LoggingKeyword::DEBUG:
        keyword_str = "DEBUG";
        break;
    case LoggingKeyword::BENCHMARK:
        keyword_str = "BENCHMARK";
        break;
    }
    std::string log_entry = "[" + get_timestamp() + "] " + keyword_str + " : " + description;
    logs_.push_back(log_entry);

    auto epoch = std::time(nullptr);
    std::cout << "[" << keyword_str << " - " << epoch << "] " << description << std::endl;
}

void Logger::log_to_file(const std::string &filename, const std::string &content)
{
    std::filesystem::create_directory("benchmark_results");
    std::filesystem::create_directory("benchmark_results/sodium");

    std::ofstream file("benchmark_results/sodium/" + filename, std::ios::out | std::ios::app);
    if (file.is_open())
    {
        file << content << std::endl;
        file.close();
    }
}