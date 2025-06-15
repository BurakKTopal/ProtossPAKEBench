#![forbid(unsafe_code)]

use std::time::{Duration, Instant};
use std::io;
use chrono::Local;
use protoss_rust::{
    init, rsp_der, der,
    SESSION_ID_BYTES, SESSION_KEY_BYTES,
};
use protoss_rust::logger::{Logger, LoggingKeyword};

fn run_benchmark(iterations: usize) {
    println!("Running Protoss protocol benchmark with {} iterations...", iterations);

    // Configure test params
    let password = "SharedPassword";
    let p_i = [0u8; SESSION_ID_BYTES];
    let mut p_j = [1u8; SESSION_ID_BYTES];

    // Initialize timing variables
    let mut init_time = Duration::new(0, 0);
    let mut rspder_time = Duration::new(0, 0);
    let mut der_time = Duration::new(0, 0);

    // Run the test multiple times to calculate average times
    for i in 0..iterations {
        // Time Init step
        let start = Instant::now();
        let res_init = init(password, &p_i, &mut p_j).unwrap();
        let end = Instant::now();
        init_time += end.duration_since(start);

        let i_point = res_init.i;
        let protoss_state = res_init.state;

        // Time RspDer step
        let start = Instant::now();
        let res_rspder = rsp_der(password, &p_i, &mut p_j, i_point).unwrap();
        let end = Instant::now();
        rspder_time += end.duration_since(start);

        let r_point = res_rspder.r;
        let session_key_j = res_rspder.k;

        // Time Der step
        let start = Instant::now();
        let session_key_i = der(password, protoss_state, r_point).unwrap();
        let end = Instant::now();
        der_time += end.duration_since(start);

        // Only verify keys match in the first iteration
        if i == 0 {
            let match_result = session_key_i == session_key_j;
            if !match_result {
                eprintln!("ERROR: Session keys don't match!");
            }
        }
    }

    // Calculate average times
    let avg_total_ms = (init_time + rspder_time + der_time).as_secs_f64() * 1000.0 / iterations as f64;
    let avg_init_ms = init_time.as_secs_f64() * 1000.0 / iterations as f64;
    let avg_rspder_ms = rspder_time.as_secs_f64() * 1000.0 / iterations as f64;
    let avg_der_ms = der_time.as_secs_f64() * 1000.0 / iterations as f64;

    // Save results to file
    let mut result = String::new();
    
    result.push_str(&format!("Benchmark Results with {} iterations\n", iterations));
    result.push_str(&format!("Hash Lengths: {} bytes input for Ristretto hash-to-point fn, {} bytes of session key\n",
                             64, SESSION_KEY_BYTES));
    result.push_str("-------------------------\n");
    result.push_str(&format!("Avg. Init phase:     {:.3} ms\n", avg_init_ms));
    result.push_str(&format!("Avg. RspDer phase:   {:.3} ms\n", avg_rspder_ms));
    result.push_str(&format!("Avg. Der phase:      {:.3} ms\n", avg_der_ms));
    result.push_str("-------------------------\n");
    result.push_str(&format!("Avg. Total time:     {:.3} ms\n", avg_total_ms));
    result.push_str("\nRelative Cost:\n");
    result.push_str(&format!("Init phase:     {:.2}%\n", (avg_init_ms / avg_total_ms * 100.0)));
    result.push_str(&format!("RspDer phase:   {:.2}%\n", (avg_rspder_ms / avg_total_ms * 100.0)));
    result.push_str(&format!("Der phase:      {:.2}%\n", (avg_der_ms / avg_total_ms * 100.0)));

    // Get current timestamp for the filename
    let now = Local::now();
    let filename = format!("benchmark_results_it{}_{}.txt", 
                          iterations, 
                          now.format("%Y-%m-%d_%H-%M-%S"));

    // Save to file in benchmark_results folder
    if let Ok(logger_lock) = Logger::get_instance().lock() {
        if let Err(e) = logger_lock.log_to_file(&filename, &result) {
            eprintln!("Failed to save benchmark results: {}", e);
        } else {
            println!("\nBenchmark results saved to benchmark_results/dalek/{}", filename);
        }
    }
}

fn main() {
    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::BENCHMARK, "See the benchmark_results folder for the info of this run.");
    }

    println!("Protoss Protocol Timing Benchmark");
    println!("=================================");

    // First run a warmup to avoid cold-start effects
    println!("Performing warmup runs...");
    run_benchmark(10);

    // Then run the actual benchmark
    println!("\nRunning main benchmark...");
    run_benchmark(10000);

    println!("Press Enter to exit...");
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).unwrap();
} 