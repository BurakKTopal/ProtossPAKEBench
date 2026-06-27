#![forbid(unsafe_code)]

use std::time::{Duration, Instant};
use std::env;
use chrono::Local;
use pake_cpace::CPace;
use protoss_rust::{init, rsp_der, der};
use protoss_rust::protoss_precomputed::{
    precomputed_state_create, precomputed_state_destroy,
    precomputed_init, precomputed_rsp_der, precomputed_der,
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

struct ThreePhase {
    phase1: Duration,
    phase2: Duration,
    phase3: Duration,
}

struct FourPhase {
    precompute: Duration,
    init: Duration,
    rspder: Duration,
    der: Duration,
}

fn protoss_once(acc: &mut ThreePhase) -> bool {
    let p_i = [0x01u8; 16];
    let mut p_j = [0x02u8; 16];

    let start = Instant::now();
    let res_init = init(PASSWORD, &p_i, &mut p_j).unwrap();
    acc.phase1 += start.elapsed();

    let start = Instant::now();
    let res_rspder = rsp_der(PASSWORD, &p_i, &mut p_j, res_init.i).unwrap();
    acc.phase2 += start.elapsed();

    let start = Instant::now();
    let k_der = der(res_init.state, res_rspder.r).unwrap();
    acc.phase3 += start.elapsed();

    k_der == res_rspder.k
}

fn precomputed_once(acc: &mut FourPhase) -> bool {
    let p_i = [0x01u8; 16];
    let p_j = [0x02u8; 16];

    let start = Instant::now();
    let mut init_state = precomputed_state_create(&p_i, &p_j).unwrap();
    let mut rsp_state = precomputed_state_create(&p_i, &p_j).unwrap();
    acc.precompute += start.elapsed();

    let start = Instant::now();
    let i = precomputed_init(&mut init_state, PASSWORD);
    acc.init += start.elapsed();

    let start = Instant::now();
    let res_rspder = precomputed_rsp_der(&mut rsp_state, PASSWORD, i).unwrap();
    acc.rspder += start.elapsed();

    let start = Instant::now();
    let k_init = precomputed_der(&init_state, res_rspder.r).unwrap();
    acc.der += start.elapsed();

    let ok = k_init == res_rspder.k;
    precomputed_state_destroy(&mut init_state);
    precomputed_state_destroy(&mut rsp_state);
    ok
}

fn cpace_once(acc: &mut ThreePhase) -> bool {
    let start = Instant::now();
    let client = CPace::step1(PASSWORD, ID_A, ID_B, None::<&[u8]>).unwrap();
    acc.phase1 += start.elapsed();

    let start = Instant::now();
    let step2 = CPace::step2(&client.packet(), PASSWORD, ID_A, ID_B, None::<&[u8]>).unwrap();
    acc.phase2 += start.elapsed();

    let start = Instant::now();
    let sk_initiator = client.step3(&step2.packet()).unwrap();
    acc.phase3 += start.elapsed();

    let sk_responder = step2.shared_keys();
    sk_initiator.k1 == sk_responder.k1 && sk_initiator.k2 == sk_responder.k2
}

struct RunResult {
    pr: [f64; 3],
    pc: [f64; 4],
    cp: [f64; 3],
}

fn run_rotated(iterations: usize, mismatch: &mut bool) -> RunResult {
    let mut pr = ThreePhase { phase1: Duration::ZERO, phase2: Duration::ZERO, phase3: Duration::ZERO };
    let mut pc = FourPhase { precompute: Duration::ZERO, init: Duration::ZERO, rspder: Duration::ZERO, der: Duration::ZERO };
    let mut cp = ThreePhase { phase1: Duration::ZERO, phase2: Duration::ZERO, phase3: Duration::ZERO };

    for _ in 0..iterations {
        if !protoss_once(&mut pr) {
            *mismatch = true;
        }
        if !precomputed_once(&mut pc) {
            *mismatch = true;
        }
        if !cpace_once(&mut cp) {
            *mismatch = true;
        }
    }

    let to_us = |d: Duration| d.as_secs_f64() * 1_000_000.0 / iterations as f64;
    RunResult {
        pr: [to_us(pr.phase1), to_us(pr.phase2), to_us(pr.phase3)],
        pc: [to_us(pc.precompute), to_us(pc.init), to_us(pc.rspder), to_us(pc.der)],
        cp: [to_us(cp.phase1), to_us(cp.phase2), to_us(cp.phase3)],
    }
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
    run_rotated(warmup_iterations, &mut mismatch);

    println!("\nStarting main benchmark runs ({} runs x {} iterations)...", num_runs, benchmark_iterations);

    let mut runs: Vec<RunResult> = Vec::new();
    for r in 1..=num_runs {
        println!("\n--- Run {} of {} ---", r, num_runs);
        runs.push(run_rotated(benchmark_iterations, &mut mismatch));
    }

    if mismatch {
        eprintln!("ERROR: shared keys do not match in at least one protocol!");
    }

    let pr_col = |i: usize| -> Vec<f64> { runs.iter().map(|r| r.pr[i]).collect() };
    let pc_col = |i: usize| -> Vec<f64> { runs.iter().map(|r| r.pc[i]).collect() };
    let cp_col = |i: usize| -> Vec<f64> { runs.iter().map(|r| r.cp[i]).collect() };

    let m_pr: Vec<f64> = (0..3).map(|i| mean(&pr_col(i))).collect();
    let s_pr: Vec<f64> = (0..3).map(|i| stddev(&pr_col(i))).collect();
    let m_pc: Vec<f64> = (0..4).map(|i| mean(&pc_col(i))).collect();
    let s_pc: Vec<f64> = (0..4).map(|i| stddev(&pc_col(i))).collect();
    let m_cp: Vec<f64> = (0..3).map(|i| mean(&cp_col(i))).collect();
    let s_cp: Vec<f64> = (0..3).map(|i| stddev(&cp_col(i))).collect();

    let pr_total = m_pr[0] + m_pr[1] + m_pr[2];
    let pc_proto = m_pc[1] + m_pc[2] + m_pc[3];
    let pc_total = m_pc[0] + pc_proto;
    let cp_total = m_cp[0] + m_cp[1] + m_cp[2];

    let mut out = String::new();
    out.push_str("PAKE Protocol Comparison Benchmark Results\n");
    out.push_str("=========================================\n");
    out.push_str(&format!("Warm-up iterations: {}\n", warmup_iterations));
    out.push_str(&format!("Benchmark iterations: {}\n", benchmark_iterations));
    out.push_str(&format!("Number of runs: {}\n\n", num_runs));
    out.push_str("PROTOSS (baseline):\n");
    out.push_str(&format!("  Init:     {:.3} +/- {:.3} us\n", m_pr[0], s_pr[0]));
    out.push_str(&format!("  RspDer:   {:.3} +/- {:.3} us\n", m_pr[1], s_pr[1]));
    out.push_str(&format!("  Der:      {:.3} +/- {:.3} us\n", m_pr[2], s_pr[2]));
    out.push_str(&format!("  Total:    {:.3} us\n\n", pr_total));
    out.push_str("PROTOSS (precomputed):\n");
    out.push_str(&format!("  Precomp:  {:.3} +/- {:.3} us\n", m_pc[0], s_pc[0]));
    out.push_str(&format!("  Init:     {:.3} +/- {:.3} us\n", m_pc[1], s_pc[1]));
    out.push_str(&format!("  RspDer:   {:.3} +/- {:.3} us\n", m_pc[2], s_pc[2]));
    out.push_str(&format!("  Der:      {:.3} +/- {:.3} us\n", m_pc[3], s_pc[3]));
    out.push_str(&format!("  Protocol: {:.3} us (online cost, precompute done ahead)\n", pc_proto));
    out.push_str(&format!("  Total:    {:.3} us (precompute time included)\n\n", pc_total));
    out.push_str("CPACE:\n");
    out.push_str(&format!("  Step 1:   {:.3} +/- {:.3} us\n", m_cp[0], s_cp[0]));
    out.push_str(&format!("  Step 2:   {:.3} +/- {:.3} us\n", m_cp[1], s_cp[1]));
    out.push_str(&format!("  Step 3:   {:.3} +/- {:.3} us\n", m_cp[2], s_cp[2]));
    out.push_str(&format!("  Total:    {:.3} us\n", cp_total));

    println!("\n{}", out);

    let now = Local::now();
    let filename = format!("benchmark_results_it{}_{}.txt",
                          benchmark_iterations,
                          now.format("%Y-%m-%d_%H-%M-%S"));

    if let Ok(logger) = Logger::get_instance().lock() {
        logger.log(LoggingKeyword::BENCHMARK, &out);
        if let Err(e) = logger.log_to_file(&filename, &out) {
            eprintln!("Failed to save benchmark results: {}", e);
        } else {
            println!("\nBenchmark results saved to benchmark_results/dalek/{}", filename);
        }
        logger.log(LoggingKeyword::BENCHMARK, "PAKE Protocol Comparison Benchmark completed");
    }
}
