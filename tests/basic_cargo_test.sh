#!/bin/bash
set -e

echo "--- Running Basic Cargo Tests ---"
cargo test -- --nocapture
echo "--- Basic Cargo Tests Completed ---" 