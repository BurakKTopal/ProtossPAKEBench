import time
import datetime
import sys
import statistics

from logger import Logger, LoggingKeyword
from protoss_protocol import Init, RspDer, Der
from protoss_validated import validated_RspDer, validated_Der
from protoss_orchestrated import (
    orchestrated_state_create, orchestrated_state_destroy,
    orchestrated_Init, orchestrated_RspDer, orchestrated_Der,
)
from protoss_precomputed import (
    precomputed_state_create, precomputed_state_destroy,
    precomputed_Init, precomputed_RspDer, precomputed_Der,
)

PASSWORD = "SharedPassword"
P_I = bytes([0x01] * 16)
P_J = bytes([0x02] * 16)


def baseline_once(acc):
    start = time.perf_counter()
    res_init = Init(PASSWORD, P_I, P_J)
    acc["bl_init"] += time.perf_counter() - start

    start = time.perf_counter()
    res_rspder = RspDer(PASSWORD, P_I, P_J, res_init.I)
    acc["bl_rspder"] += time.perf_counter() - start

    start = time.perf_counter()
    k = Der(res_init.protoss_state, res_rspder.R)
    acc["bl_der"] += time.perf_counter() - start

    return k == res_rspder.get_session_key()


def validated_once(acc):
    start = time.perf_counter()
    res_init = Init(PASSWORD, P_I, P_J)
    acc["vl_init"] += time.perf_counter() - start

    start = time.perf_counter()
    res_rspder = validated_RspDer(PASSWORD, P_I, P_J, res_init.I)
    acc["vl_rspder"] += time.perf_counter() - start

    start = time.perf_counter()
    k = validated_Der(res_init.protoss_state, res_rspder.R)
    acc["vl_der"] += time.perf_counter() - start

    return k == res_rspder.get_session_key()


def orchestrated_once(acc):
    init_state = orchestrated_state_create(P_I, P_J)
    rsp_state = orchestrated_state_create(P_I, P_J)

    start = time.perf_counter()
    I = orchestrated_Init(init_state, PASSWORD)
    acc["or_init"] += time.perf_counter() - start

    start = time.perf_counter()
    res_rspder = orchestrated_RspDer(rsp_state, PASSWORD, I)
    acc["or_rspder"] += time.perf_counter() - start

    start = time.perf_counter()
    k = orchestrated_Der(init_state, res_rspder.R)
    acc["or_der"] += time.perf_counter() - start

    ok = k == res_rspder.get_session_key()
    orchestrated_state_destroy(init_state)
    orchestrated_state_destroy(rsp_state)
    return ok


def precomputed_once(acc):
    start = time.perf_counter()
    init_state = precomputed_state_create(P_I, P_J)
    rsp_state = precomputed_state_create(P_I, P_J)
    acc["pc_pre"] += time.perf_counter() - start

    start = time.perf_counter()
    I = precomputed_Init(init_state, PASSWORD)
    acc["pc_init"] += time.perf_counter() - start

    start = time.perf_counter()
    res_rspder = precomputed_RspDer(rsp_state, PASSWORD, I)
    acc["pc_rspder"] += time.perf_counter() - start

    start = time.perf_counter()
    k = precomputed_Der(init_state, res_rspder.R)
    acc["pc_der"] += time.perf_counter() - start

    ok = k == res_rspder.get_session_key()
    precomputed_state_destroy(init_state)
    precomputed_state_destroy(rsp_state)
    return ok


KEYS = ["bl_init", "bl_rspder", "bl_der",
        "vl_init", "vl_rspder", "vl_der",
        "or_init", "or_rspder", "or_der",
        "pc_pre", "pc_init", "pc_rspder", "pc_der"]


def run_rotated(iterations):
    acc = {k: 0.0 for k in KEYS}
    mismatch = False
    for _ in range(iterations):
        if not baseline_once(acc):
            mismatch = True
        if not validated_once(acc):
            mismatch = True
        if not orchestrated_once(acc):
            mismatch = True
        if not precomputed_once(acc):
            mismatch = True
    return {k: acc[k] / iterations * 1000 for k in KEYS}, mismatch


def main():
    logger = Logger.get_instance()
    logger.log(LoggingKeyword.BENCHMARK, "See the benchmark_results/sodium folder for the info of this run.")

    iterations = 10000
    num_runs = 10
    if len(sys.argv) >= 2:
        iterations = int(sys.argv[1])
    if len(sys.argv) >= 3:
        num_runs = int(sys.argv[2])

    print("Protoss Protocol Variant Comparison Benchmark")
    print("==============================================")
    print(f"Config: {iterations} iterations x {num_runs} runs (iteration-level rotation)\n")

    mismatch = False

    print("Performing warmup...", flush=True)
    run_rotated(5000)
    print("Warmup complete.\n", flush=True)

    runs = {k: [] for k in KEYS}
    bench_start = time.time()
    for r in range(num_runs):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] Run {r + 1}/{num_runs} (elapsed {int(time.time() - bench_start)}s)", flush=True)
        result, mm = run_rotated(iterations)
        mismatch = mismatch or mm
        for k in KEYS:
            runs[k].append(result[k])

    if mismatch:
        print("ERROR: Session keys don't match in at least one variant!")

    def m(key):
        return statistics.mean(runs[key])

    def s(key):
        return statistics.stdev(runs[key]) if num_runs > 1 else 0.0

    bl_total = m("bl_init") + m("bl_rspder") + m("bl_der")
    vl_total = m("vl_init") + m("vl_rspder") + m("vl_der")
    or_total = m("or_init") + m("or_rspder") + m("or_der")
    pc_proto = m("pc_init") + m("pc_rspder") + m("pc_der")
    pc_total = m("pc_pre") + pc_proto

    lines = []
    lines.append("Protoss Variant Comparison Benchmark Results")
    lines.append(f"Config: {iterations} iterations x {num_runs} runs (iteration-level rotation)")
    lines.append("=============================================\n")
    lines.append("BASELINE:")
    lines.append(f"  Init:     {m('bl_init'):.4f} +/- {s('bl_init'):.4f} ms")
    lines.append(f"  RspDer:   {m('bl_rspder'):.4f} +/- {s('bl_rspder'):.4f} ms")
    lines.append(f"  Der:      {m('bl_der'):.4f} +/- {s('bl_der'):.4f} ms")
    lines.append(f"  Total:    {bl_total:.4f} ms\n")
    lines.append("VALIDATED (with point validation):")
    lines.append(f"  Init:     {m('vl_init'):.4f} +/- {s('vl_init'):.4f} ms")
    lines.append(f"  RspDer:   {m('vl_rspder'):.4f} +/- {s('vl_rspder'):.4f} ms")
    lines.append(f"  Der:      {m('vl_der'):.4f} +/- {s('vl_der'):.4f} ms")
    lines.append(f"  Total:    {vl_total:.4f} ms\n")
    lines.append("ORCHESTRATED (state manager, no precompute):")
    lines.append(f"  Init:     {m('or_init'):.4f} +/- {s('or_init'):.4f} ms")
    lines.append(f"  RspDer:   {m('or_rspder'):.4f} +/- {s('or_rspder'):.4f} ms")
    lines.append(f"  Der:      {m('or_der'):.4f} +/- {s('or_der'):.4f} ms")
    lines.append(f"  Total:    {or_total:.4f} ms\n")
    lines.append("PRECOMPUTED (state manager + precomputation):")
    lines.append(f"  Precomp:  {m('pc_pre'):.4f} +/- {s('pc_pre'):.4f} ms")
    lines.append(f"  Init:     {m('pc_init'):.4f} +/- {s('pc_init'):.4f} ms")
    lines.append(f"  RspDer:   {m('pc_rspder'):.4f} +/- {s('pc_rspder'):.4f} ms")
    lines.append(f"  Der:      {m('pc_der'):.4f} +/- {s('pc_der'):.4f} ms")
    lines.append(f"  Protocol: {pc_proto:.4f} ms (online cost, precompute done ahead)")
    lines.append(f"  Total:    {pc_total:.4f} ms (precompute time included)")

    results_str = "\n".join(lines)
    print("\n" + results_str)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"variant_benchmark_it{iterations}_{timestamp}.txt"
    logger.log_to_file(filename, results_str)
    print(f"\nResults saved to benchmark_results/sodium/{filename}")
    logger.save_logs()


if __name__ == "__main__":
    main()
