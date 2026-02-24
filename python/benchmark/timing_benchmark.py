import time
import datetime
import os
import sys
import math
from typing import List, Tuple, Optional
import statistics
from logger import Logger, LoggingKeyword
from protoss_protocol import (
    Init, RspDer, Der,
    INPUT_LEN_HASH_TO_POINT,
    SESSION_KEY_LEN
)

def run_benchmark(iterations: int, run_id: int = 1, is_warmup: bool = False) -> Optional[Tuple[float, float, float]]:
    prefix = "Warmup" if is_warmup else f"Run {run_id}"
    print(f"{prefix}: Running Protoss protocol benchmark with {iterations} iterations...")

    # Configure test params
    password = "SharedPassword"
    P_i = b'\x00'
    P_j = b'\x01'

    # Initialize timing lists
    init_times = []
    rspder_times = []
    der_times = []

    # Run the test multiple times
    for i in range(iterations):
        try:
            # Time Init step
            start = time.perf_counter()
            res_init = Init(password, P_i, P_j)
            end = time.perf_counter()
            init_times.append(end - start)

            I = res_init.I
            protoss_state = res_init.protoss_state

            # Time RspDer step
            start = time.perf_counter()
            res_rspDer = RspDer(password, P_i, P_j, I)
            end = time.perf_counter()
            rspder_times.append(end - start)

            R = res_rspDer.R
            session_key_j = res_rspDer.get_session_key()

            # Time Der step
            start = time.perf_counter()
            session_key_i = Der(password, protoss_state, R)
            end = time.perf_counter()
            der_times.append(end - start)

            # Verify keys match only in the first iteration of the first run
            if i == 0 and run_id == 1 and not is_warmup:
                match = (session_key_i == session_key_j)
                if not match:
                    print("ERROR: Session keys don't match!")

        except Exception as e:
            print(f"Exception: {str(e)}")
            return None

    # Calculate average times in ms for this run
    avg_init_ms = statistics.mean(init_times) * 1000
    avg_rspder_ms = statistics.mean(rspder_times) * 1000
    avg_der_ms = statistics.mean(der_times) * 1000

    return (avg_init_ms, avg_rspder_ms, avg_der_ms)

def main():
    logger = Logger.get_instance()
    logger.log(LoggingKeyword.BENCHMARK, "See the benchmark_results/sodium folder for the info of this run.")

    # Default parameters
    iterations = 10000
    num_runs = 10

    # Parse optional CLI arguments: [iterations] [num_runs]
    if len(sys.argv) >= 2:
        iterations = int(sys.argv[1])
    if len(sys.argv) >= 3:
        num_runs = int(sys.argv[2])

    print("Protoss Protocol Timing Benchmark")
    print("=================================")

    # First run a warmup to avoid cold-start effects
    print("Performing warmup runs...")
    run_benchmark(100, is_warmup=True)

    # Run the benchmark multiple times to average out external variability
    print(f"\nRunning main benchmark ({num_runs} runs x {iterations} iterations)...")
    run_init = []
    run_rspder = []
    run_der = []
    run_total = []

    for r in range(1, num_runs + 1):
        result = run_benchmark(iterations, run_id=r, is_warmup=False)
        if result is None:
            print(f"ERROR: Run {r} failed, aborting.")
            return
        avg_init_ms, avg_rspder_ms, avg_der_ms = result
        run_init.append(avg_init_ms)
        run_rspder.append(avg_rspder_ms)
        run_der.append(avg_der_ms)
        run_total.append(avg_init_ms + avg_rspder_ms + avg_der_ms)

    # Calculate mean and standard deviation across runs
    mean_init = statistics.mean(run_init)
    mean_rspder = statistics.mean(run_rspder)
    mean_der = statistics.mean(run_der)
    mean_total = statistics.mean(run_total)

    std_init = statistics.stdev(run_init) if num_runs > 1 else 0.0
    std_rspder = statistics.stdev(run_rspder) if num_runs > 1 else 0.0
    std_der = statistics.stdev(run_der) if num_runs > 1 else 0.0
    std_total = statistics.stdev(run_total) if num_runs > 1 else 0.0

    # Format results
    results = []
    results.append(f"Benchmark Results with {iterations} iterations x {num_runs} runs")
    results.append(f"Hash Lengths: {INPUT_LEN_HASH_TO_POINT} bytes input for hash-to-point fn, {SESSION_KEY_LEN} bytes of session key")
    results.append("-------------------------")
    results.append(f"Avg. Init phase:     {mean_init:.3f} +/- {std_init:.3f} ms")
    results.append(f"Avg. RspDer phase:   {mean_rspder:.3f} +/- {std_rspder:.3f} ms")
    results.append(f"Avg. Der phase:      {mean_der:.3f} +/- {std_der:.3f} ms")
    results.append("-------------------------")
    results.append(f"Avg. Total time:     {mean_total:.3f} +/- {std_total:.3f} ms")
    results.append("\nRelative Cost:")
    results.append(f"Init phase:     {(mean_init / mean_total * 100):.1f}%")
    results.append(f"RspDer phase:   {(mean_rspder / mean_total * 100):.1f}%")
    results.append(f"Der phase:      {(mean_der / mean_total * 100):.1f}%")

    results_str = "\n".join(results)

    # Get current timestamp for the filename
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"benchmark_results_it{iterations}_{timestamp}.txt"

    # Save to file in benchmark_results folder
    logger.log_to_file(filename, results_str)
    print(f"\nBenchmark results saved to benchmark_results/sodium/{filename}")

    # Save logs before exit
    logger.save_logs()

if __name__ == "__main__":
    main()
