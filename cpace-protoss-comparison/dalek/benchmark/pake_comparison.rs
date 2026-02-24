#![forbid(unsafe_code)]

use std::time::{Duration, Instant};
use std::io;
use std::env;
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

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn stddev(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let m = mean(values);
    let variance = values.iter().map(|v| (v - m) * (v - m)).sum::<f64>() / (values.len() - 1) as f64;
    variance.sqrt()
}

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

// Returns (avg_init_us, avg_rspder_us, avg_der_us) for this run
fn benchmark_protoss(iterations: usize, run_id: usize) -> (f64, f64, f64) {
    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::BENCHMARK,
            &format!("Run {}: Starting Protoss PAKE benchmark with {} iterations", run_id, iterations));
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

    // Calculate averages in microseconds
    let avg_init = total_init_time.as_secs_f64() * 1_000_000.0 / iterations as f64;
    let avg_rspder = total_rspder_time.as_secs_f64() * 1_000_000.0 / iterations as f64;
    let avg_der = total_der_time.as_secs_f64() * 1_000_000.0 / iterations as f64;

    (avg_init, avg_rspder, avg_der)
}

// Returns (avg_step1_us, avg_step2_us, avg_step3_us) for this run
fn benchmark_cpace(iterations: usize, run_id: usize) -> (f64, f64, f64) {
    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::BENCHMARK,
            &format!("Run {}: Starting CPACE benchmark with {} iterations", run_id, iterations));
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

    // Calculate averages in microseconds
    let avg_step1 = total_step1_time.as_secs_f64() * 1_000_000.0 / iterations as f64;
    let avg_step2 = total_step2_time.as_secs_f64() * 1_000_000.0 / iterations as f64;
    let avg_step3 = total_step3_time.as_secs_f64() * 1_000_000.0 / iterations as f64;

    (avg_step1, avg_step2, avg_step3)
}

fn main() {
    let mut warmup_iterations: usize = 5000;
    let mut benchmark_iterations: usize = 50000;
    let mut num_runs: usize = 10;

    // Parse optional CLI arguments: [iterations] [num_runs] [warmup_iterations]
    let args: Vec<String> = env::args().collect();
    if args.len() >= 2 {
        benchmark_iterations = args[1].parse().expect("Invalid iterations argument");
    }
    if args.len() >= 3 {
        num_runs = args[2].parse().expect("Invalid num_runs argument");
    }
    if args.len() >= 4 {
        warmup_iterations = args[3].parse().expect("Invalid warmup_iterations argument");
    }

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
    println!("Performing warm-up runs ({} iterations)...", warmup_iterations);
    warmup_protoss(warmup_iterations);
    warmup_cpace(warmup_iterations);

    // Run the benchmark multiple times to average out external variability
    println!("\nStarting main benchmark runs ({} runs x {} iterations)...", num_runs, benchmark_iterations);

    let mut protoss_init_runs: Vec<f64> = Vec::new();
    let mut protoss_rspder_runs: Vec<f64> = Vec::new();
    let mut protoss_der_runs: Vec<f64> = Vec::new();
    let mut protoss_total_runs: Vec<f64> = Vec::new();

    let mut cpace_step1_runs: Vec<f64> = Vec::new();
    let mut cpace_step2_runs: Vec<f64> = Vec::new();
    let mut cpace_step3_runs: Vec<f64> = Vec::new();
    let mut cpace_total_runs: Vec<f64> = Vec::new();

    for r in 1..=num_runs {
        println!("\n--- Run {} of {} ---", r, num_runs);

        // Alternate order to avoid ordering bias
        if r % 2 == 1 {
            let (avg_init, avg_rspder, avg_der) = benchmark_protoss(benchmark_iterations, r);
            protoss_init_runs.push(avg_init);
            protoss_rspder_runs.push(avg_rspder);
            protoss_der_runs.push(avg_der);
            protoss_total_runs.push(avg_init + avg_rspder + avg_der);

            let (avg_step1, avg_step2, avg_step3) = benchmark_cpace(benchmark_iterations, r);
            cpace_step1_runs.push(avg_step1);
            cpace_step2_runs.push(avg_step2);
            cpace_step3_runs.push(avg_step3);
            cpace_total_runs.push(avg_step1 + avg_step2 + avg_step3);
        } else {
            let (avg_step1, avg_step2, avg_step3) = benchmark_cpace(benchmark_iterations, r);
            cpace_step1_runs.push(avg_step1);
            cpace_step2_runs.push(avg_step2);
            cpace_step3_runs.push(avg_step3);
            cpace_total_runs.push(avg_step1 + avg_step2 + avg_step3);

            let (avg_init, avg_rspder, avg_der) = benchmark_protoss(benchmark_iterations, r);
            protoss_init_runs.push(avg_init);
            protoss_rspder_runs.push(avg_rspder);
            protoss_der_runs.push(avg_der);
            protoss_total_runs.push(avg_init + avg_rspder + avg_der);
        }
    }

    // Calculate mean and standard deviation across runs for Protoss
    let mean_protoss_init = mean(&protoss_init_runs);
    let mean_protoss_rspder = mean(&protoss_rspder_runs);
    let mean_protoss_der = mean(&protoss_der_runs);
    let mean_protoss_total = mean(&protoss_total_runs);

    let std_protoss_init = stddev(&protoss_init_runs);
    let std_protoss_rspder = stddev(&protoss_rspder_runs);
    let std_protoss_der = stddev(&protoss_der_runs);
    let std_protoss_total = stddev(&protoss_total_runs);

    // Calculate mean and standard deviation across runs for CPace
    let mean_cpace_step1 = mean(&cpace_step1_runs);
    let mean_cpace_step2 = mean(&cpace_step2_runs);
    let mean_cpace_step3 = mean(&cpace_step3_runs);
    let mean_cpace_total = mean(&cpace_total_runs);

    let std_cpace_step1 = stddev(&cpace_step1_runs);
    let std_cpace_step2 = stddev(&cpace_step2_runs);
    let std_cpace_step3 = stddev(&cpace_step3_runs);
    let std_cpace_total = stddev(&cpace_total_runs);

    // Format and log Protoss results
    let mut protoss_result = String::new();
    protoss_result.push_str(&format!("Protoss PAKE Benchmark Results ({} iterations x {} runs):\n", benchmark_iterations, num_runs));
    protoss_result.push_str(&format!("Average Init time:     {:.3} +/- {:.3} us\n", mean_protoss_init, std_protoss_init));
    protoss_result.push_str(&format!("Average RspDer time:   {:.3} +/- {:.3} us\n", mean_protoss_rspder, std_protoss_rspder));
    protoss_result.push_str(&format!("Average Der time:      {:.3} +/- {:.3} us\n", mean_protoss_der, std_protoss_der));
    protoss_result.push_str(&format!("Total average time:    {:.3} +/- {:.3} us\n", mean_protoss_total, std_protoss_total));
    protoss_result.push_str("\nRelative Cost:\n");
    protoss_result.push_str(&format!("Init phase:     {:.2}%\n", (mean_protoss_init / mean_protoss_total * 100.0)));
    protoss_result.push_str(&format!("RspDer phase:   {:.2}%\n", (mean_protoss_rspder / mean_protoss_total * 100.0)));
    protoss_result.push_str(&format!("Der phase:      {:.2}%\n", (mean_protoss_der / mean_protoss_total * 100.0)));

    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::BENCHMARK, &protoss_result);
    }
    println!("\n{}", protoss_result);

    // Format and log CPace results
    let mut cpace_result = String::new();
    cpace_result.push_str(&format!("CPACE Benchmark Results ({} iterations x {} runs):\n", benchmark_iterations, num_runs));
    cpace_result.push_str(&format!("Average Step 1 time:   {:.3} +/- {:.3} us\n", mean_cpace_step1, std_cpace_step1));
    cpace_result.push_str(&format!("Average Step 2 time:   {:.3} +/- {:.3} us\n", mean_cpace_step2, std_cpace_step2));
    cpace_result.push_str(&format!("Average Step 3 time:   {:.3} +/- {:.3} us\n", mean_cpace_step3, std_cpace_step3));
    cpace_result.push_str(&format!("Total average time:    {:.3} +/- {:.3} us\n", mean_cpace_total, std_cpace_total));
    cpace_result.push_str("\nRelative Cost:\n");
    cpace_result.push_str(&format!("Step 1:         {:.2}%\n", (mean_cpace_step1 / mean_cpace_total * 100.0)));
    cpace_result.push_str(&format!("Step 2:         {:.2}%\n", (mean_cpace_step2 / mean_cpace_total * 100.0)));
    cpace_result.push_str(&format!("Step 3:         {:.2}%\n", (mean_cpace_step3 / mean_cpace_total * 100.0)));

    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::BENCHMARK, &cpace_result);
    }
    println!("{}", cpace_result);

    // Save final results to file
    let now = Local::now();
    let filename = format!("benchmark_results_it{}_{}.txt",
                          benchmark_iterations,
                          now.format("%Y-%m-%d_%H-%M-%S"));

    let mut final_results = String::new();
    final_results.push_str("PAKE Protocol Comparison Benchmark Results\n");
    final_results.push_str("=========================================\n");
    final_results.push_str(&format!("Warm-up iterations: {}\n", warmup_iterations));
    final_results.push_str(&format!("Benchmark iterations: {}\n", benchmark_iterations));
    final_results.push_str(&format!("Number of runs: {}\n", num_runs));
    final_results.push_str(&format!("Password length: {} bytes\n", PASSWORD_LENGTH));
    final_results.push_str(&format!("Session ID length: {} bytes\n", SESSION_ID_LENGTH));
    final_results.push_str("\n");
    final_results.push_str(&protoss_result);
    final_results.push_str("\n");
    final_results.push_str(&cpace_result);

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
