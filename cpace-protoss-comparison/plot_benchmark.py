import matplotlib.pyplot as plt
import numpy as np

# ============================================================
# Benchmark data (edit these values with your benchmark results)
# ============================================================

# Implementation label (e.g., "libsodium-c", "dalek-rust", "libsodium-cpp")
implementation = "libsodium-c"

# Number of iterations and runs used
iterations = 100000
num_runs = 50

# Protoss phase results: (mean_us, std_us)
protoss_init   = (89.969, 2.192)
protoss_rspder = (232.225, 5.666)
protoss_der    = (142.335, 3.463)
protoss_total  = (464.529, 11.274)

# CPace phase results: (mean_us, std_us)
cpace_step1 = (143.230, 3.057)
cpace_step2 = (261.256, 5.633)
cpace_step3 = (118.146, 2.665)
cpace_total = (522.633, 11.302)

# ============================================================
# Plot
# ============================================================

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6), gridspec_kw={"width_ratios": [3, 1]})

# --- Phase breakdown bar chart ---
phases = ["Init / Step 1", "RspDer / Step 2", "Der / Step 3"]
protoss_means = [protoss_init[0], protoss_rspder[0], protoss_der[0]]
protoss_stds  = [protoss_init[1], protoss_rspder[1], protoss_der[1]]
cpace_means   = [cpace_step1[0], cpace_step2[0], cpace_step3[0]]
cpace_stds    = [cpace_step1[1], cpace_step2[1], cpace_step3[1]]

x = np.arange(len(phases))
bar_width = 0.35

bars1 = ax1.bar(x - bar_width / 2, protoss_means, bar_width,
                yerr=protoss_stds, capsize=5, label="Protoss", color="#4C72B0", edgecolor="black", linewidth=0.5)
bars2 = ax1.bar(x + bar_width / 2, cpace_means, bar_width,
                yerr=cpace_stds, capsize=5, label="CPace", color="#DD8452", edgecolor="black", linewidth=0.5)

ax1.set_xlabel("Protocol Phase")
ax1.set_ylabel("Average Time (us)")
ax1.set_title(f"Phase Breakdown ({implementation}, {iterations} iter x {num_runs} runs)")
ax1.set_xticks(x)
ax1.set_xticklabels(phases)
ax1.legend()
ax1.set_ylim(bottom=0)

# Add value labels on bars
for bar in bars1:
    h = bar.get_height()
    ax1.text(bar.get_x() + bar.get_width() / 2, h + 8, f"{h:.1f}", ha="center", va="bottom", fontsize=8)
for bar in bars2:
    h = bar.get_height()
    ax1.text(bar.get_x() + bar.get_width() / 2, h + 8, f"{h:.1f}", ha="center", va="bottom", fontsize=8)

# --- Total comparison bar chart ---
protocols = ["Protoss", "CPace"]
totals = [protoss_total[0], cpace_total[0]]
total_stds = [protoss_total[1], cpace_total[1]]
colors = ["#4C72B0", "#DD8452"]

bars3 = ax2.bar(protocols, totals, yerr=total_stds, capsize=5,
                color=colors, edgecolor="black", linewidth=0.5, width=0.5)

ax2.set_ylabel("Average Time (us)")
ax2.set_title(f"Total Protocol Time")
ax2.set_ylim(bottom=0)

# Add value labels on bars
for bar, std in zip(bars3, total_stds):
    h = bar.get_height()
    ax2.text(bar.get_x() + bar.get_width() / 2, h + std + 5,
             f"{h:.1f} +/- {std:.1f}", ha="center", va="bottom", fontsize=9)

plt.tight_layout()
plt.savefig(f"benchmark_comparison_{implementation}.png", dpi=150, bbox_inches="tight")
plt.show()
print(f"Plot saved to benchmark_comparison_{implementation}.png")
