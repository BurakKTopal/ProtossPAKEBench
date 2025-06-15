import time
import datetime
import os
import sys
from typing import List
import statistics
from logger import Logger, LoggingKeyword
from protoss_protocol import (
    Init, RspDer, Der, 
    INPUT_LEN_HASH_TO_POINT, 
    SESSION_KEY_LEN
)

def run_benchmark(iterations: int, run_id: int = 1, is_warmup: bool = False):
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

    # Calculate average times
    avg_init_ms = statistics.mean(init_times) * 1000
    avg_rspder_ms = statistics.mean(rspder_times) * 1000
    avg_der_ms = statistics.mean(der_times) * 1000
    avg_total_ms = avg_init_ms + avg_rspder_ms + avg_der_ms

    # Format results
    results = []
    results.append(f"Benchmark Results with {iterations} iterations")
    results.append(f"Hash Lengths: {INPUT_LEN_HASH_TO_POINT} bytes input for hash-to-point fn, {SESSION_KEY_LEN} bytes of session key")
    results.append("-------------------------")
    results.append(f"Avg. Init phase:     {avg_init_ms:.3f} ms")
    results.append(f"Avg. RspDer phase:   {avg_rspder_ms:.3f} ms")
    results.append(f"Avg. Der phase:      {avg_der_ms:.3f} ms")
    results.append("-------------------------")
    results.append(f"Avg. Total time:     {avg_total_ms:.3f} ms")
    results.append("\nRelative Cost:")
    results.append(f"Init phase:     {(avg_init_ms / avg_total_ms * 100):.1f}%")
    results.append(f"RspDer phase:   {(avg_rspder_ms / avg_total_ms * 100):.1f}%")
    results.append(f"Der phase:      {(avg_der_ms / avg_total_ms * 100):.1f}%")
    
    results_str = "\n".join(results)
    
    # Get current timestamp for the filename
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"benchmark_results_it{iterations}_{timestamp}.txt"

    # Save to file in benchmark_results folder
    logger = Logger.get_instance()
    logger.log_to_file(filename, results_str)
    print(f"\nBenchmark results saved to benchmark_results/sodium/{filename}")

def main():
    logger = Logger.get_instance()
    logger.log(LoggingKeyword.BENCHMARK, "See the benchmark_results/sodium folder for the info of this run.")
    
    print("Protoss Protocol Timing Benchmark")
    print("=================================")

    # First run a warmup to avoid cold-start effects
    print("Performing warmup runs...")
    run_benchmark(100, is_warmup=True)

    # Then run the actual benchmark
    print("\nRunning main benchmark...")
    run_benchmark(10000, is_warmup=False)
    
    # Save logs before exit
    logger.save_logs()

if __name__ == "__main__":
    main() 