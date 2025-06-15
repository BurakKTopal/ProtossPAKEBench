import os
from enum import Enum
from datetime import datetime
import atexit


class LoggingKeyword(Enum):
    INFO = "INFO"
    ERROR = "ERROR"
    DEBUG = "DEBUG"
    BENCHMARK = "BENCHMARK"


class Logger:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.logs_ = []
            # Register the save_logs method to be called on exit
            atexit.register(cls._instance.save_logs)
        return cls._instance

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def log(self, keyword: LoggingKeyword, description: str):
        keyword_str = keyword.value if isinstance(keyword, LoggingKeyword) else str(keyword)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {keyword_str} : {description}"
        self.logs_.append(log_entry)

    def save_logs(self):
        try:
            os.makedirs("build/logs/python-sodium", exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            path = f"build/logs/python-sodium/log_{timestamp}.txt"
            with open(path, "w") as f:
                for log in self.logs_:
                    f.write(log + "\n")
        except Exception as e:
            print(f"[Logger] Failed to save logs: {e}")

    def log_to_file(self, filename: str, content: str):
        try:
            os.makedirs("build/benchmark_results/python-sodium", exist_ok=True)
            path = f"build/benchmark_results/python-sodium/{filename}"
            with open(path, "a") as f:
                f.write(content + "\n")
        except Exception as e:
            print(f"[Logger] Failed to write to file {filename}: {e}")
