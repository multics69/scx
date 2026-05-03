#!/bin/bash

# 01-baseline
git checkout 84ee789de
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../result-01-baseline --scx-path ../target/release/scx_lavd cpu_max_bench.ini

# 02-pressure
git checkout ee3f5db92
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../result-04-pressure --scx-path ../target/release/scx_lavd cpu_max_bench.ini

# 03-blend
git checkout a61784767
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../result-05-blend --scx-path ../target/release/scx_lavd cpu_max_bench.ini
