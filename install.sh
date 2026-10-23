#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 0 ]]; then
    echo "Usage: INSTALL_PREFIX=... CMAKE_PREFIX_PATH=... BUILD_JOBS=3 ./install.sh" >&2
    exit 2
fi
source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
install_prefix="${INSTALL_PREFIX:-$HOME/.local/SDK/iiNetwork}"
prefix_path="${CMAKE_PREFIX_PATH:-$HOME/.local/SDK/iiSDKCore;$HOME/.local/SDK/iiJson}"
build_jobs="${BUILD_JOBS:-3}"
case "$build_jobs" in
    ''|*[!0-9]*|0) echo "BUILD_JOBS must be a positive integer" >&2; exit 2 ;;
esac
build_dir="$source_dir/build"
cmake -S "$source_dir" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release \
    -DIINETWORK_BUILD_TESTS=ON -DIINETWORK_BUILD_EXAMPLES=ON \
    -DCMAKE_PREFIX_PATH="$prefix_path" -DCMAKE_INSTALL_PREFIX="$install_prefix"
cmake --build "$build_dir" --config Release --parallel "$build_jobs"
ctest --test-dir "$build_dir" -C Release --output-on-failure
cmake --install "$build_dir" --config Release

consumer_build="$build_dir/consumer/build"
cmake -S "$source_dir/tests/consumer" -B "$consumer_build" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$install_prefix;$prefix_path" \
    -DiiNetwork_DIR="$install_prefix/lib/cmake/iiNetwork" \
    -DCMAKE_DISABLE_FIND_PACKAGE_Qt6=ON
cmake --build "$consumer_build" --config Release --parallel "$build_jobs"
ctest --test-dir "$consumer_build" -C Release --output-on-failure
