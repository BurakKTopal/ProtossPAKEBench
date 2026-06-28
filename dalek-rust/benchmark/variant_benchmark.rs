use std::env;
use std::time::{Duration, Instant};

use protoss_rust::{init, rsp_der, der, SESSION_ID_BYTES};
use protoss_rust::protoss_validated::{validated_rsp_der, validated_der};
use protoss_rust::protoss_orchestrated::{
    orchestrated_state_create, orchestrated_state_destroy,
    orchestrated_init, orchestrated_rsp_der, orchestrated_der,
};
use protoss_rust::protoss_precomputed::{
    precomputed_state_create, precomputed_state_destroy,
    precomputed_init, precomputed_rsp_der, precomputed_der,
};

const PASSWORD: &str = "SharedPassword";

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

fn to_ms(d: Duration, iterations: usize) -> f64 {
    d.as_secs_f64() * 1000.0 / iterations as f64
}

fn p_i() -> [u8; SESSION_ID_BYTES] {
    [0x01; SESSION_ID_BYTES]
}

fn p_j() -> [u8; SESSION_ID_BYTES] {
    [0x02; SESSION_ID_BYTES]
}

fn baseline_once(init_t: &mut Duration, rspder_t: &mut Duration, der_t: &mut Duration) -> bool {
    let pi = p_i();
    let mut pj = p_j();

    let start = Instant::now();
    let res_init = init(PASSWORD, &pi, &mut pj).unwrap();
    *init_t += start.elapsed();

    let start = Instant::now();
    let res_rspder = rsp_der(PASSWORD, &pi, &mut pj, res_init.i).unwrap();
    *rspder_t += start.elapsed();

    let start = Instant::now();
    let k = der(res_init.state, res_rspder.r).unwrap();
    *der_t += start.elapsed();

    k == res_rspder.k
}

fn validated_once(init_t: &mut Duration, rspder_t: &mut Duration, der_t: &mut Duration) -> bool {
    let pi = p_i();
    let mut pj = p_j();

    let start = Instant::now();
    let res_init = init(PASSWORD, &pi, &mut pj).unwrap();
    *init_t += start.elapsed();

    let start = Instant::now();
    let res_rspder = validated_rsp_der(PASSWORD, &pi, &mut pj, &res_init.i.compress()).unwrap();
    *rspder_t += start.elapsed();

    let start = Instant::now();
    let k = validated_der(res_init.state, &res_rspder.r.compress()).unwrap();
    *der_t += start.elapsed();

    k == res_rspder.k
}

fn orchestrated_once(init_t: &mut Duration, rspder_t: &mut Duration, der_t: &mut Duration) -> bool {
    let mut init_state = orchestrated_state_create(&p_i(), &p_j());
    let mut rsp_state = orchestrated_state_create(&p_i(), &p_j());

    let start = Instant::now();
    let i = orchestrated_init(&mut init_state, PASSWORD).unwrap();
    *init_t += start.elapsed();

    let start = Instant::now();
    let res_rspder = orchestrated_rsp_der(&mut rsp_state, PASSWORD, i).unwrap();
    *rspder_t += start.elapsed();

    let start = Instant::now();
    let k = orchestrated_der(&init_state, res_rspder.r).unwrap();
    *der_t += start.elapsed();

    let ok = k == res_rspder.k;
    orchestrated_state_destroy(&mut init_state);
    orchestrated_state_destroy(&mut rsp_state);
    ok
}

fn precomputed_once(
    precompute_t: &mut Duration,
    init_t: &mut Duration,
    rspder_t: &mut Duration,
    der_t: &mut Duration,
) -> bool {
    let start = Instant::now();
    let mut init_state = precomputed_state_create(&p_i(), &p_j()).unwrap();
    let mut rsp_state = precomputed_state_create(&p_i(), &p_j()).unwrap();
    *precompute_t += start.elapsed();

    let start = Instant::now();
    let i = precomputed_init(&mut init_state, PASSWORD);
    *init_t += start.elapsed();

    let start = Instant::now();
    let res_rspder = precomputed_rsp_der(&mut rsp_state, PASSWORD, i).unwrap();
    *rspder_t += start.elapsed();

    let start = Instant::now();
    let k = precomputed_der(&init_state, res_rspder.r).unwrap();
    *der_t += start.elapsed();

    let ok = k == res_rspder.k;
    precomputed_state_destroy(&mut init_state);
    precomputed_state_destroy(&mut rsp_state);
    ok
}

struct RunResult {
    bl: [f64; 3],
    vl: [f64; 3],
    or: [f64; 3],
    pc: [f64; 4],
}

fn run_rotated(iterations: usize, mismatch: &mut bool) -> RunResult {
    let mut bl_init = Duration::ZERO;
    let mut bl_rspder = Duration::ZERO;
    let mut bl_der = Duration::ZERO;
    let mut vl_init = Duration::ZERO;
    let mut vl_rspder = Duration::ZERO;
    let mut vl_der = Duration::ZERO;
    let mut or_init = Duration::ZERO;
    let mut or_rspder = Duration::ZERO;
    let mut or_der = Duration::ZERO;
    let mut pc_pre = Duration::ZERO;
    let mut pc_init = Duration::ZERO;
    let mut pc_rspder = Duration::ZERO;
    let mut pc_der = Duration::ZERO;

    for _ in 0..iterations {
        if !baseline_once(&mut bl_init, &mut bl_rspder, &mut bl_der) {
            *mismatch = true;
        }
        if !validated_once(&mut vl_init, &mut vl_rspder, &mut vl_der) {
            *mismatch = true;
        }
        if !orchestrated_once(&mut or_init, &mut or_rspder, &mut or_der) {
            *mismatch = true;
        }
        if !precomputed_once(&mut pc_pre, &mut pc_init, &mut pc_rspder, &mut pc_der) {
            *mismatch = true;
        }
    }

    RunResult {
        bl: [to_ms(bl_init, iterations), to_ms(bl_rspder, iterations), to_ms(bl_der, iterations)],
        vl: [to_ms(vl_init, iterations), to_ms(vl_rspder, iterations), to_ms(vl_der, iterations)],
        or: [to_ms(or_init, iterations), to_ms(or_rspder, iterations), to_ms(or_der, iterations)],
        pc: [
            to_ms(pc_pre, iterations),
            to_ms(pc_init, iterations),
            to_ms(pc_rspder, iterations),
            to_ms(pc_der, iterations),
        ],
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let iterations: usize = if args.len() >= 2 { args[1].parse().unwrap() } else { 10000 };
    let num_runs: usize = if args.len() >= 3 { args[2].parse().unwrap() } else { 10 };

    println!("Protoss Protocol Variant Comparison Benchmark");
    println!("==============================================");
    println!("Config: {} iterations x {} runs (iteration-level rotation)\n", iterations, num_runs);

    let mut mismatch = false;

    println!("Performing warmup...");
    run_rotated(100, &mut mismatch);
    println!("Warmup complete.\n");

    let mut bl: Vec<[f64; 3]> = Vec::new();
    let mut vl: Vec<[f64; 3]> = Vec::new();
    let mut or: Vec<[f64; 3]> = Vec::new();
    let mut pc: Vec<[f64; 4]> = Vec::new();

    let bench_start = Instant::now();
    for run in 0..num_runs {
        println!("Run {}/{} (elapsed {}s)", run + 1, num_runs, bench_start.elapsed().as_secs());
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let r = run_rotated(iterations, &mut mismatch);
        bl.push(r.bl);
        vl.push(r.vl);
        or.push(r.or);
        pc.push(r.pc);
    }

    if mismatch {
        eprintln!("ERROR: Session keys don't match in at least one variant!");
    }

    let col = |runs: &[[f64; 3]], idx: usize| -> Vec<f64> { runs.iter().map(|r| r[idx]).collect() };
    let col4 = |runs: &[[f64; 4]], idx: usize| -> Vec<f64> { runs.iter().map(|r| r[idx]).collect() };

    let report3 = |label: &str, runs: &[[f64; 3]]| {
        let i = col(runs, 0);
        let r = col(runs, 1);
        let d = col(runs, 2);
        let total = mean(&i) + mean(&r) + mean(&d);
        println!("{}:", label);
        println!("  Init:     {:.4} +/- {:.4} ms", mean(&i), stddev(&i));
        println!("  RspDer:   {:.4} +/- {:.4} ms", mean(&r), stddev(&r));
        println!("  Der:      {:.4} +/- {:.4} ms", mean(&d), stddev(&d));
        println!("  Total:    {:.4} ms\n", total);
    };

    println!("\nProtoss Variant Comparison Benchmark Results");
    println!("Config: {} iterations x {} runs (iteration-level rotation)", iterations, num_runs);
    println!("=============================================\n");

    report3("BASELINE", &bl);
    report3("VALIDATED (with point validation)", &vl);
    report3("ORCHESTRATED (state manager, no precompute)", &or);

    let pre = col4(&pc, 0);
    let pi = col4(&pc, 1);
    let pr = col4(&pc, 2);
    let pd = col4(&pc, 3);
    let proto = mean(&pi) + mean(&pr) + mean(&pd);
    let total = mean(&pre) + proto;
    println!("PRECOMPUTED (state manager + precomputation):");
    println!("  Precomp:  {:.4} +/- {:.4} ms", mean(&pre), stddev(&pre));
    println!("  Init:     {:.4} +/- {:.4} ms", mean(&pi), stddev(&pi));
    println!("  RspDer:   {:.4} +/- {:.4} ms", mean(&pr), stddev(&pr));
    println!("  Der:      {:.4} +/- {:.4} ms", mean(&pd), stddev(&pd));
    println!("  Protocol: {:.4} ms (online cost, precompute done ahead)", proto);
    println!("  Total:    {:.4} ms (precompute time included)", total);
}
