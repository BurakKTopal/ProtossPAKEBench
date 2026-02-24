#![forbid(unsafe_code)]

use std::time::{Duration, Instant};
use std::io;
use std::env;
use chrono::Local;
use protoss_rust::{
    init, rsp_der, der,
    SESSION_ID_BYTES, SESSION_KEY_BYTES,
};
use protoss_rust::logger::{Logger, LoggingKeyword};

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

// Returns (avg_init_ms, avg_rspder_ms, avg_der_ms) for this run
fn run_benchmark(iterations: usize, run_id: usize, is_warmup: bool) -> Option<(f64, f64, f64)> {
    let prefix = if is_warmup { "Warmup".to_string() } else { format!("Run {}", run_id) };
    println!("{}: Running Protoss protocol benchmark with {} iterations...", prefix, iterations);

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

        // Only verify keys match in the first iteration of the first run
        if i == 0 && run_id == 1 && !is_warmup {
            let match_result = session_key_i == session_key_j;
            if !match_result {
                eprintln!("ERROR: Session keys don't match!");
            }
        }
    }

    // Calculate average times
    let avg_init_ms = init_time.as_secs_f64() * 1000.0 / iterations as f64;
    let avg_rspder_ms = rspder_time.as_secs_f64() * 1000.0 / iterations as f64;
    let avg_der_ms = der_time.as_secs_f64() * 1000.0 / iterations as f64;

    Some((avg_init_ms, avg_rspder_ms, avg_der_ms))
}

fn main() {
    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::BENCHMARK, "See the benchmark_results folder for the info of this run.");
    }

    // Default parameters
    let mut iterations: usize = 10000;
    let mut num_runs: usize = 10;

    // Parse optional CLI arguments: [iterations] [num_runs]
    let args: Vec<String> = env::args().collect();
    if args.len() >= 2 {
        iterations = args[1].parse().expect("Invalid iterations argument");
    }
    if args.len() >= 3 {
        num_runs = args[2].parse().expect("Invalid num_runs argument");
    }

    println!("Protoss Protocol Timing Benchmark");
    println!("=================================");

    // First run a warmup to avoid cold-start effects
    println!("Performing warmup runs...");
    run_benchmark(10, 0, true);

    // Run the benchmark multiple times to average out external variability
    println!("\nRunning main benchmark ({} runs x {} iterations)...", num_runs, iterations);
    let mut run_init: Vec<f64> = Vec::new();
    let mut run_rspder: Vec<f64> = Vec::new();
    let mut run_der: Vec<f64> = Vec::new();
    let mut run_total: Vec<f64> = Vec::new();

    for r in 1..=num_runs {
        match run_benchmark(iterations, r, false) {
            Some((avg_init, avg_rspder, avg_der)) => {
                run_init.push(avg_init);
                run_rspder.push(avg_rspder);
                run_der.push(avg_der);
                run_total.push(avg_init + avg_rspder + avg_der);
            }
            None => {
                eprintln!("ERROR: Run {} failed, aborting.", r);
                return;
            }
        }
    }

    // Calculate mean and standard deviation across runs
    let mean_init = mean(&run_init);
    let mean_rspder = mean(&run_rspder);
    let mean_der = mean(&run_der);
    let mean_total = mean(&run_total);

    let std_init = stddev(&run_init);
    let std_rspder = stddev(&run_rspder);
    let std_der = stddev(&run_der);
    let std_total = stddev(&run_total);

    // Save results to file
    let mut result = String::new();

    result.push_str(&format!("Benchmark Results with {} iterations x {} runs\n", iterations, num_runs));
    result.push_str(&format!("Hash Lengths: {} bytes input for Ristretto hash-to-point fn, {} bytes of session key\n",
                             64, SESSION_KEY_BYTES));
    result.push_str("-------------------------\n");
    result.push_str(&format!("Avg. Init phase:     {:.3} +/- {:.3} ms\n", mean_init, std_init));
    result.push_str(&format!("Avg. RspDer phase:   {:.3} +/- {:.3} ms\n", mean_rspder, std_rspder));
    result.push_str(&format!("Avg. Der phase:      {:.3} +/- {:.3} ms\n", mean_der, std_der));
    result.push_str("-------------------------\n");
    result.push_str(&format!("Avg. Total time:     {:.3} +/- {:.3} ms\n", mean_total, std_total));
    result.push_str("\nRelative Cost:\n");
    result.push_str(&format!("Init phase:     {:.2}%\n", (mean_init / mean_total * 100.0)));
    result.push_str(&format!("RspDer phase:   {:.2}%\n", (mean_rspder / mean_total * 100.0)));
    result.push_str(&format!("Der phase:      {:.2}%\n", (mean_der / mean_total * 100.0)));

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

    println!("Press Enter to exit...");
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).unwrap();
}
