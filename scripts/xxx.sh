#!/bin/bash

# 01-baseline 
git checkout 3644b29bf
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../result-01-baseline --scx-path ../target/release/scx_lavd cpu_max_bench.ini

# 02-pressure 
git checkout c75658f08
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../result-02-pressure --scx-path ../target/release/scx_lavd cpu_max_bench.ini

# 03-blend 
git checkout 487aacd5b
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../result-03-blend --scx-path ../target/release/scx_lavd cpu_max_bench.ini
