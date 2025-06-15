#![forbid(unsafe_code)]

use std::time::{Duration, Instant};
use std::io;
use chrono::Local;
use rand::{thread_rng, Rng};
use pake_cpace::CPace;
use protoss_rust::{
    init, rsp_der, der,
};
use protoss_rust::logger::{Logger, LoggingKeyword};

// Constants for standardized sizes
const PASSWORD_LENGTH: usize = 16;  // 16 bytes = 128 bits
const SESSION_ID_LENGTH: usize = 16; // 16 bytes = 128 bits

// Helper function to generate random password
fn generate_random_password(length: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

// Helper function to generate random bytes
fn generate_random_bytes(length: usize) -> [u8; 16] {
    let mut rng = thread_rng();
    let mut bytes = [0u8; 16];
    for i in 0..length {
        bytes[i] = rng.gen();
    }
    bytes
}

fn warmup_protoss(warmup_iterations: usize) {
    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::BENCHMARK, 
            &format!("Warming up Protoss PAKE with {} iterations", warmup_iterations));
    }

    for _ in 0..warmup_iterations {
        let password = generate_random_password(PASSWORD_LENGTH);
        let p_i = generate_random_bytes(SESSION_ID_LENGTH);
        let mut p_j = generate_random_bytes(SESSION_ID_LENGTH);

        let res_init = init(&password, &p_i, &mut p_j).unwrap();
        let res_rspder = rsp_der(&password, &p_i, &mut p_j, res_init.i).unwrap();
        let _ = der(&password, res_init.state, res_rspder.r).unwrap();
    }
}

fn warmup_cpace(warmup_iterations: usize) {
    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::BENCHMARK, 
            &format!("Warming up CPACE with {} iterations", warmup_iterations));
    }

    for _ in 0..warmup_iterations {
        let password = generate_random_password(PASSWORD_LENGTH);
        let id_a = "client";
        let id_b = "server";
        let ad = b"additional data";

        let client = CPace::step1(&password, id_a, id_b, Some(ad)).unwrap();
        let step2 = CPace::step2(&client.packet(), &password, id_a, id_b, Some(ad)).unwrap();
        let _ = client.step3(&step2.packet()).unwrap();
    }
}

fn benchmark_protoss(iterations: usize) {
    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::BENCHMARK, 
            &format!("Starting Protoss PAKE benchmark with {} iterations", iterations));
    }

    let mut total_init_time = Duration::new(0, 0);
    let mut total_rspder_time = Duration::new(0, 0);
    let mut total_der_time = Duration::new(0, 0);

    for _ in 0..iterations {
        let password = generate_random_password(PASSWORD_LENGTH);
        let p_i = generate_random_bytes(SESSION_ID_LENGTH);
        let mut p_j = generate_random_bytes(SESSION_ID_LENGTH);

        // Measure Init
        let start = Instant::now();
        let res_init = init(&password, &p_i, &mut p_j).unwrap();
        let end = Instant::now();
        total_init_time += end.duration_since(start);

        // Measure RspDer
        let start = Instant::now();
        let res_rspder = rsp_der(&password, &p_i, &mut p_j, res_init.i).unwrap();
        let end = Instant::now();
        total_rspder_time += end.duration_since(start);

        // Measure Der
        let start = Instant::now();
        let _ = der(&password, res_init.state, res_rspder.r).unwrap();
        let end = Instant::now();
        total_der_time += end.duration_since(start);
    }

    // Calculate averages
    let avg_init = total_init_time.as_secs_f64() * 1_000_000.0 / iterations as f64;
    let avg_rspder = total_rspder_time.as_secs_f64() * 1_000_000.0 / iterations as f64;
    let avg_der = total_der_time.as_secs_f64() * 1_000_000.0 / iterations as f64;
    let total_avg = avg_init + avg_rspder + avg_der;

    // Log results
    let mut result = String::new();
    result.push_str("Protoss PAKE Benchmark Results:\n");
    result.push_str(&format!("Average Init time:     {:.3} µs\n", avg_init));
    result.push_str(&format!("Average RspDer time:   {:.3} µs\n", avg_rspder));
    result.push_str(&format!("Average Der time:      {:.3} µs\n", avg_der));
    result.push_str(&format!("Total average time:    {:.3} µs\n", total_avg));
    result.push_str("\nRelative Cost:\n");
    result.push_str(&format!("Init phase:     {:.2}%\n", (avg_init / total_avg * 100.0)));
    result.push_str(&format!("RspDer phase:   {:.2}%\n", (avg_rspder / total_avg * 100.0)));
    result.push_str(&format!("Der phase:      {:.2}%\n", (avg_der / total_avg * 100.0)));

    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::BENCHMARK, &result);
    }

    // Also print to console
    println!("\nBenchmarking Protoss PAKE ({} iterations):", iterations);
    println!("{}", result);
}

fn benchmark_cpace(iterations: usize) {
    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::BENCHMARK, 
            &format!("Starting CPACE benchmark with {} iterations", iterations));
    }

    let mut total_step1_time = Duration::new(0, 0);
    let mut total_step2_time = Duration::new(0, 0);
    let mut total_step3_time = Duration::new(0, 0);

    for _ in 0..iterations {
        let password = generate_random_password(PASSWORD_LENGTH);
        let id_a = "client";
        let id_b = "server";
        let ad = b"additional data";

        // Measure Step 1
        let start = Instant::now();
        let client = CPace::step1(&password, id_a, id_b, Some(ad)).unwrap();
        let end = Instant::now();
        total_step1_time += end.duration_since(start);

        // Measure Step 2
        let start = Instant::now();
        let step2 = CPace::step2(&client.packet(), &password, id_a, id_b, Some(ad)).unwrap();
        let end = Instant::now();
        total_step2_time += end.duration_since(start);

        // Measure Step 3
        let start = Instant::now();
        let _ = client.step3(&step2.packet()).unwrap();
        let end = Instant::now();
        total_step3_time += end.duration_since(start);
    }

    // Calculate averages
    let avg_step1 = total_step1_time.as_secs_f64() * 1_000_000.0 / iterations as f64;
    let avg_step2 = total_step2_time.as_secs_f64() * 1_000_000.0 / iterations as f64;
    let avg_step3 = total_step3_time.as_secs_f64() * 1_000_000.0 / iterations as f64;
    let total_avg = avg_step1 + avg_step2 + avg_step3;

    // Log results
    let mut result = String::new();
    result.push_str("CPACE Benchmark Results:\n");
    result.push_str(&format!("Average Step 1 time:   {:.3} µs\n", avg_step1));
    result.push_str(&format!("Average Step 2 time:   {:.3} µs\n", avg_step2));
    result.push_str(&format!("Average Step 3 time:   {:.3} µs\n", avg_step3));
    result.push_str(&format!("Total average time:    {:.3} µs\n", total_avg));
    result.push_str("\nRelative Cost:\n");
    result.push_str(&format!("Step 1:         {:.2}%\n", (avg_step1 / total_avg * 100.0)));
    result.push_str(&format!("Step 2:         {:.2}%\n", (avg_step2 / total_avg * 100.0)));
    result.push_str(&format!("Step 3:         {:.2}%\n", (avg_step3 / total_avg * 100.0)));

    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::BENCHMARK, &result);
    }

    // Also print to console
    println!("\nBenchmarking CPACE ({} iterations):", iterations);
    println!("{}", result);
}

fn main() {
    const WARMUP_ITERATIONS: usize = 5000;
    const BENCHMARK_ITERATIONS: usize = 50000;

    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::BENCHMARK, "Starting PAKE Protocol Comparison Benchmark");
    }

    println!("Starting PAKE Protocol Benchmarking");
    println!("===================================");
    println!("Using standardized sizes:");
    println!("- Password length: {} bytes", PASSWORD_LENGTH);
    println!("- Session ID length: {} bytes", SESSION_ID_LENGTH);
    println!("===================================");

    // Warm-up runs
    println!("Performing warm-up runs ({} iterations)...", WARMUP_ITERATIONS);
    warmup_protoss(WARMUP_ITERATIONS);
    warmup_cpace(WARMUP_ITERATIONS);

    // Main benchmark runs
    println!("\nStarting main benchmark runs ({} iterations)...", BENCHMARK_ITERATIONS);
    benchmark_protoss(BENCHMARK_ITERATIONS);
    benchmark_cpace(BENCHMARK_ITERATIONS);

    // Save final results to file
    let now = Local::now();
    let filename = format!("benchmark_results_it{}_{}.txt", 
                          BENCHMARK_ITERATIONS, 
                          now.format("%Y-%m-%d_%H-%M-%S"));

    let mut final_results = String::new();
    final_results.push_str("PAKE Protocol Comparison Benchmark Results\n");
    final_results.push_str("=========================================\n");
    final_results.push_str(&format!("Warm-up iterations: {}\n", WARMUP_ITERATIONS));
    final_results.push_str(&format!("Benchmark iterations: {}\n", BENCHMARK_ITERATIONS));
    final_results.push_str(&format!("Password length: {} bytes\n", PASSWORD_LENGTH));
    final_results.push_str(&format!("Session ID length: {} bytes\n", SESSION_ID_LENGTH));
    final_results.push_str("\nResults are logged in the benchmark log file.\n");

    if let Ok(logger) = Logger::get_instance().lock() {
        if let Err(e) = logger.log_to_file(&filename, &final_results) {
            eprintln!("Failed to save benchmark results: {}", e);
        } else {
            println!("\nBenchmark results saved to benchmark_results/dalek/{}", filename);
        }
        logger.log(LoggingKeyword::BENCHMARK, "PAKE Protocol Comparison Benchmark completed");
    }

    println!("Press Enter to exit...");
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).unwrap();
} 