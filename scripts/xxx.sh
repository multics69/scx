#!/bin/bash

# 01-baseline
git checkout b14cc4d0e
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../result-01-baseline --scx-path ../target/release/scx_lavd cpu_max_bench.ini

# 02-bound
git checkout e2c9b3cab
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../result-02-bound --scx-path ../target/release/scx_lavd cpu_max_bench.ini

# 03-half-jiffy
git checkout cc5f08314
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../result-03-half-jiffy --scx-path ../target/release/scx_lavd cpu_max_bench.ini

# 04-pressure
git checkout c07feb716
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../result-04-pressure --scx-path ../target/release/scx_lavd cpu_max_bench.ini

# 05-blend
git checkout d415b7adc
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../result-05-blend --scx-path ../target/release/scx_lavd cpu_max_bench.ini

# 06-emergency
git checkout 84087d9ec
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../result-06-emergency --scx-path ../target/release/scx_lavd cpu_max_bench.ini

# 07-clamp
git checkout ff7e64426
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../result-07-clamp --scx-path ../target/release/scx_lavd cpu_max_bench.ini

