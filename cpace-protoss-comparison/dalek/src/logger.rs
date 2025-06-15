#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::fmt;
use chrono::Local;

pub enum LoggingKeyword {
    INFO,
    ERROR,
    DEBUG,
    BENCHMARK,
}

impl fmt::Display for LoggingKeyword {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LoggingKeyword::INFO => write!(f, "INFO"),
            LoggingKeyword::ERROR => write!(f, "ERROR"),
            LoggingKeyword::DEBUG => write!(f, "DEBUG"),
            LoggingKeyword::BENCHMARK => write!(f, "BENCHMARK"),
        }
    }
}

pub struct Logger {
    log_level: LoggingKeyword,
    log_directory: String,
    log_filename: String,
    benchmark_filename: String,
}

// Singleton
lazy_static::lazy_static! {
    static ref LOGGER: Arc<Mutex<Logger>> = Arc::new(Mutex::new(Logger::new(LoggingKeyword::INFO)));
}

impl Logger {
    fn new(log_level: LoggingKeyword) -> Self {
        let log_directory = "build/logs/dalek".to_string();  
        let dir_path = Path::new(&log_directory);
        if !dir_path.exists() {
            if let Err(e) = fs::create_dir_all(dir_path) {
                eprintln!("Failed to create logs directory: {}", e);
            }
        }

        let now = Local::now();
        let timestamp = now.format("%Y-%m-%d_%H-%M-%S").to_string();

        let log_filename = format!("log_{}.txt", timestamp);
        let benchmark_filename = format!("benchmark_results_{}.txt", timestamp);

        Logger {
            log_level,
            log_directory,
            log_filename,
            benchmark_filename,
        }
    }

    pub fn get_instance() -> Arc<Mutex<Logger>> {
        LOGGER.clone()
    }

    pub fn set_log_level(&mut self, log_level: LoggingKeyword) {
        self.log_level = log_level;
    }

    pub fn log(&self, keyword: LoggingKeyword, message: &str) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let log_message = format!("[{} - {}] {}\n", keyword, timestamp, message);

        // Print to console
        print!("{}", log_message);

        // Determine filename
        let filename = match keyword {
            LoggingKeyword::BENCHMARK => &self.benchmark_filename,
            _ => &self.log_filename,
        };

        let log_path = format!("{}/{}", self.log_directory, filename);

        // Write to file
        if let Err(e) = self.append_to_file(&log_path, &log_message) {
            eprintln!("Failed to write to log file: {}", e);
        }
    }

    fn append_to_file(&self, file_path: &str, message: &str) -> std::io::Result<()> {
        let file_path = Path::new(file_path);

        if let Some(parent) = file_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .open(file_path)?;

        file.write_all(message.as_bytes())?;  

        Ok(())
    }

    pub fn log_to_file(&self, filename: &str, message: &str) -> std::io::Result<()> {
        let dir_path = Path::new("build/benchmark_results/dalek");
        if !dir_path.exists() {
            fs::create_dir_all(dir_path)?; 
        }

        let file_path = dir_path.join(filename);
        let mut file = File::create(file_path)?; 
        file.write_all(message.as_bytes())?;  

        Ok(())
    }
}
