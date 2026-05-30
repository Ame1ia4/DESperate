"""
testing/bench_argon2id.py

Benchmark Argon2id key derivation with the current parameters.
Target: idk yet

Run with:
    python testing/bench_argon2id.py
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.kdf import argon2id_derive_key
from core.constants import ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM

RUNS       = 5
PASSWORD   = "test-password-for-benchmarking"

print(f"Argon2id parameters: t={ARGON2_TIME_COST}, m={ARGON2_MEMORY_COST} KiB (~{ARGON2_MEMORY_COST // 1024} MiB), p={ARGON2_PARALLELISM}")

# Warm up — first call allocates the memory block
print("Warming up...", end=" ", flush=True)
argon2id_derive_key(PASSWORD)
print("done\n")

times = []
for i in range(1, RUNS + 1):
    start   = time.perf_counter()
    argon2id_derive_key(PASSWORD)
    elapsed = (time.perf_counter() - start) * 1000
    times.append(elapsed)
    print(f"  run {i}: {elapsed:.1f} ms")

avg = sum(times) / len(times)
mn  = min(times)
mx  = max(times)

print(f"\n  min {mn:.1f} ms  |  avg {avg:.1f} ms  |  max {mx:.1f} ms")