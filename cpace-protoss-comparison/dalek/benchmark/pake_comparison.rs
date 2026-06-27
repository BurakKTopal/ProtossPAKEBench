#![forbid(unsafe_code)]

use std::time::{Duration, Instant};
use std::io;
use std::env;
use chrono::Local;
use pake_cpace::CPace;
use protoss_rust::{
    init, rsp_der, der,
};
use protoss_rust::logger::{Logger, LoggingKeyword};

const PASSWORD: &str = "SharedPassword";
const ID_A: &str = "client_identif00";
const ID_B: &str = "server_identif00";

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

fn protoss_once(init_t: &mut Duration, rspder_t: &mut Duration, der_t: &mut Duration) -> bool {
    let p_i = [0x01u8; 16];
    let mut p_j = [0x02u8; 16];

    let start = Instant::now();
    let res_init = init(PASSWORD, &p_i, &mut p_j).unwrap();
    *init_t += start.elapsed();

    let start = Instant::now();
    let res_rspder = rsp_der(PASSWORD, &p_i, &mut p_j, res_init.i).unwrap();
    *rspder_t += start.elapsed();

    let start = Instant::now();
    let k_der = der(res_init.state, res_rspder.r).unwrap();
    *der_t += start.elapsed();

    k_der == res_rspder.k
}

fn cpace_once(step1_t: &mut Duration, step2_t: &mut Duration, step3_t: &mut Duration) -> bool {
    let start = Instant::now();
    let client = CPace::step1(PASSWORD, ID_A, ID_B, None::<&[u8]>).unwrap();
    *step1_t += start.elapsed();

    let start = Instant::now();
    let step2 = CPace::step2(&client.packet(), PASSWORD, ID_A, ID_B, None::<&[u8]>).unwrap();
    *step2_t += start.elapsed();

    let start = Instant::now();
    let sk_initiator = client.step3(&step2.packet()).unwrap();
    *step3_t += start.elapsed();

    let sk_responder = step2.shared_keys();
    sk_initiator.k1 == sk_responder.k1 && sk_initiator.k2 == sk_responder.k2
}

fn run_rotated(iterations: usize) -> ([f64; 3], [f64; 3], bool) {
    let mut pr_init = Duration::new(0, 0);
    let mut pr_rspder = Duration::new(0, 0);
    let mut pr_der = Duration::new(0, 0);
    let mut cp_step1 = Duration::new(0, 0);
    let mut cp_step2 = Duration::new(0, 0);
    let mut cp_step3 = Duration::new(0, 0);
    let mut mismatch = false;

    for _ in 0..iterations {
        if !protoss_once(&mut pr_init, &mut pr_rspder, &mut pr_der) {
            mismatch = true;
        }
        if !cpace_once(&mut cp_step1, &mut cp_step2, &mut cp_step3) {
            mismatch = true;
        }
    }

    let to_us = |d: Duration| d.as_secs_f64() * 1_000_000.0 / iterations as f64;
    (
        [to_us(pr_init), to_us(pr_rspder), to_us(pr_der)],
        [to_us(cp_step1), to_us(cp_step2), to_us(cp_step3)],
        mismatch,
    )
}

fn main() {
    let mut warmup_iterations: usize = 5000;
    let mut benchmark_iterations: usize = 50000;
    let mut num_runs: usize = 10;

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

    let mut mismatch = false;

    println!("Performing warm-up runs ({} iterations)...", warmup_iterations);
    let (_, _, wm) = run_rotated(warmup_iterations);
    mismatch |= wm;

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

        let (pr, cp, mm) = run_rotated(benchmark_iterations);
        mismatch |= mm;

        protoss_init_runs.push(pr[0]);
        protoss_rspder_runs.push(pr[1]);
        protoss_der_runs.push(pr[2]);
        protoss_total_runs.push(pr[0] + pr[1] + pr[2]);

        cpace_step1_runs.push(cp[0]);
        cpace_step2_runs.push(cp[1]);
        cpace_step3_runs.push(cp[2]);
        cpace_total_runs.push(cp[0] + cp[1] + cp[2]);
    }

    if mismatch {
        eprintln!("ERROR: shared keys do not match in at least one protocol!");
    }

    let mean_protoss_init = mean(&protoss_init_runs);
    let mean_protoss_rspder = mean(&protoss_rspder_runs);
    let mean_protoss_der = mean(&protoss_der_runs);
    let mean_protoss_total = mean(&protoss_total_runs);

    let std_protoss_init = stddev(&protoss_init_runs);
    let std_protoss_rspder = stddev(&protoss_rspder_runs);
    let std_protoss_der = stddev(&protoss_der_runs);
    let std_protoss_total = stddev(&protoss_total_runs);

    let mean_cpace_step1 = mean(&cpace_step1_runs);
    let mean_cpace_step2 = mean(&cpace_step2_runs);
    let mean_cpace_step3 = mean(&cpace_step3_runs);
    let mean_cpace_total = mean(&cpace_total_runs);

    let std_cpace_step1 = stddev(&cpace_step1_runs);
    let std_cpace_step2 = stddev(&cpace_step2_runs);
    let std_cpace_step3 = stddev(&cpace_step3_runs);
    let std_cpace_total = stddev(&cpace_total_runs);

    let mut protoss_result = String::new();
    protoss_result.push_str(&format!("Protoss PAKE Benchmark Results ({} iterations x {} runs):\n", benchmark_iterations, num_runs));
    protoss_result.push_str(&format!("Average Init time:     {:.3} +/- {:.3} us\n", mean_protoss_init, std_protoss_init));
    protoss_result.push_str(&format!("Average RspDer time:   {:.3} +/- {:.3} us\n", mean_protoss_rspder, std_protoss_rspder));
    protoss_result.push_str(&format!("Average Der time:      {:.3} +/- {:.3} us\n", mean_protoss_der, std_protoss_der));
    protoss_result.push_str(&format!("Total average time:    {:.3} +/- {:.3} us\n", mean_protoss_total, std_protoss_total));

    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::BENCHMARK, &protoss_result);
    }
    println!("\n{}", protoss_result);

    let mut cpace_result = String::new();
    cpace_result.push_str(&format!("CPACE Benchmark Results ({} iterations x {} runs):\n", benchmark_iterations, num_runs));
    cpace_result.push_str(&format!("Average Step 1 time:   {:.3} +/- {:.3} us\n", mean_cpace_step1, std_cpace_step1));
    cpace_result.push_str(&format!("Average Step 2 time:   {:.3} +/- {:.3} us\n", mean_cpace_step2, std_cpace_step2));
    cpace_result.push_str(&format!("Average Step 3 time:   {:.3} +/- {:.3} us\n", mean_cpace_step3, std_cpace_step3));
    cpace_result.push_str(&format!("Total average time:    {:.3} +/- {:.3} us\n", mean_cpace_total, std_cpace_total));

    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::BENCHMARK, &cpace_result);
    }
    println!("{}", cpace_result);

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
