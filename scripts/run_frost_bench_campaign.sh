#!/usr/bin/env bash
# run_frost_bench_campaign.sh
#
# Run the secp256k1-frost benchmark campaign and store raw logs, metadata,
# parsed CSV files, and optional plots.
#
# Usage from the repository root:
#
#   chmod +x scripts/run_frost_bench_campaign.sh
#   ./scripts/run_frost_bench_campaign.sh
#
# Useful environment variables:
#
#   OUTDIR=results/frost-bench-$(date +%Y%m%d-%H%M%S)
#   ITERS_LIST="1000 5000"
#   REPS=3
#   BENCH_ARGS="frost"
#   CONFIGURE_FLAGS="--enable-module-frost --enable-benchmark"
#   NO_BUILD=1
#   MAKE_JOBS=8
#   BENCH_EXE=./bench

set -euo pipefail

OUTDIR="${OUTDIR:-results/frost-bench-$(date +%Y%m%d-%H%M%S)}"
ITERS_LIST="${ITERS_LIST:-1000}"
REPS="${REPS:-3}"
BENCH_ARGS="${BENCH_ARGS:-frost}"
CONFIGURE_FLAGS="${CONFIGURE_FLAGS:---enable-module-frost --enable-benchmark --enable-experimental}"
MAKE_JOBS="${MAKE_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
NO_BUILD="${NO_BUILD:-0}"
BENCH_EXE="${BENCH_EXE:-}"

mkdir -p "$OUTDIR/raw"

echo "[campaign] Output directory: $OUTDIR"

write_metadata() {
    {
        echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "hostname=$(hostname 2>/dev/null || true)"
        echo "uname=$(uname -a 2>/dev/null || true)"
        echo "repo=$(pwd)"
        echo "git_commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
        echo "git_dirty_files=$(git status --short 2>/dev/null | wc -l | tr -d ' ')"
        echo "cc=$(${CC:-cc} --version 2>/dev/null | head -n 1 || true)"
        echo "configure_flags=$CONFIGURE_FLAGS"
        echo "make_jobs=$MAKE_JOBS"
        echo "iters_list=$ITERS_LIST"
        echo "reps=$REPS"
        echo "bench_args=$BENCH_ARGS"
        echo ""
        echo "[cpu]"
        if command -v lscpu >/dev/null 2>&1; then
            lscpu || true
        else
            sysctl -a 2>/dev/null | grep -E 'machdep.cpu|hw.memsize|hw.ncpu' || true
        fi
    } > "$OUTDIR/metadata.txt"
}

detect_bench_exe() {
    if [ -n "$BENCH_EXE" ]; then
        if [ ! -x "$BENCH_EXE" ]; then
            echo "[campaign] ERROR: BENCH_EXE is set but not executable: $BENCH_EXE" >&2
            exit 1
        fi
        echo "$BENCH_EXE"
        return
    fi

    for candidate in ./bench ./src/bench ./build/bench ./build/src/bench ./cmake-build-release/bench ./cmake-build-release/src/bench; do
        if [ -x "$candidate" ]; then
            echo "$candidate"
            return
        fi
    done

    echo "[campaign] ERROR: could not find benchmark executable. Set BENCH_EXE=/path/to/bench." >&2
    exit 1
}

build_if_needed() {
    if [ "$NO_BUILD" = "1" ]; then
        echo "[campaign] Skipping build because NO_BUILD=1"
        return
    fi

    echo "[campaign] Building benchmark executable"

    if [ -f "./configure" ] || [ -f "./configure.ac" ]; then
        if [ ! -f "./configure" ] && [ -x "./autogen.sh" ]; then
            ./autogen.sh
        fi

        if [ -f "./configure" ]; then
            ./configure $CONFIGURE_FLAGS
            make -j"$MAKE_JOBS"
            return
        fi
    fi

    if [ -f "./CMakeLists.txt" ]; then
        cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
        cmake --build build -j "$MAKE_JOBS"
        return
    fi

    echo "[campaign] ERROR: no supported build system found." >&2
    exit 1
}

run_one() {
    local bench_exe="$1"
    local iters="$2"
    local rep="$3"
    local raw="$OUTDIR/raw/bench-iters${iters}-rep${rep}.txt"

    echo "[campaign] Running iters=$iters rep=$rep -> $raw"

    {
        echo "# command: SECP256K1_BENCH_ITERS=$iters $bench_exe $BENCH_ARGS"
        echo "# date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        SECP256K1_BENCH_ITERS="$iters" "$bench_exe" $BENCH_ARGS
    } | tee "$raw"
}

write_metadata
build_if_needed

BENCH_PATH="$(detect_bench_exe)"
echo "[campaign] Benchmark executable: $BENCH_PATH" | tee -a "$OUTDIR/metadata.txt"

for iters in $ITERS_LIST; do
    for rep in $(seq 1 "$REPS"); do
        run_one "$BENCH_PATH" "$iters" "$rep"
    done
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARSER="$SCRIPT_DIR/parse_frost_bench.py"

if [ -f "$PARSER" ]; then
    echo "[campaign] Parsing results"
    python3 "$PARSER" "$OUTDIR/raw" --outdir "$OUTDIR" --plot
else
    echo "[campaign] Parser not found at $PARSER"
    echo "[campaign] Raw logs are available in $OUTDIR/raw"
fi

echo "[campaign] Done."
