"""
testing/bench_pq_keygen.py

Benchmark ML-KEM-1024 and ML-DSA-87 key generation via liboqs.

Run with:
    python testing/bench_pq_keygen.py
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.keys import (
    generate_kem_keypair,
    generate_signing_keypair,
    generate_opk_pairs,
    generate_identity_bundle,
)
from core.constants import KEM_ALG, SIG_ALG, OPK_COUNT

RUNS = 1000
#PQ keygen average: 3.7ms


def bench(label: str, fn, *args, runs: int = RUNS) -> list[float]:
    # Warm up
    fn(*args)

    times = []
    for i in range(1, runs + 1):
        start   = time.perf_counter()
        fn(*args)
        elapsed = (time.perf_counter() - start) * 1000
        times.append(elapsed)
        print(f"  run {i}: {elapsed:.1f} ms")

    avg = sum(times) / len(times)
    print(f"  min {min(times):.1f} ms  |  avg {avg:.1f} ms  |  max {max(times):.1f} ms\n")
    return times


print(f"{'─' * 52}")
print(f"ML-KEM-1024 keypair ({KEM_ALG})")
print(f"{'─' * 52}")
bench("ML-KEM-1024 keypair", generate_kem_keypair)

print(f"{'─' * 52}")
print(f"ML-DSA-87 keypair ({SIG_ALG})")
print(f"{'─' * 52}")
bench("ML-DSA-87 keypair", generate_signing_keypair)

print(f"{'─' * 52}")
print(f"OPK pairs ({OPK_COUNT} pairs: X25519 + ML-KEM-1024)")
print(f"{'─' * 52}")
bench("OPK pairs", generate_opk_pairs, OPK_COUNT)

print(f"{'─' * 52}")
print("Full identity bundle (all keys combined)")
print(f"{'─' * 52}")
bench("Full identity bundle", generate_identity_bundle, "bench-user")
