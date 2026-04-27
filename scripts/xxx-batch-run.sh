#!/usr/bin/bash

# baseline
git checkout eede0775c6122cf3a9c2fa96e1549e5382e03a0d
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../results-01-baseline --scx-path ../target/release/scx_lavd cpu_max_bench.ini

# pressure
git clone d345051f411a2cf44d236723dc8f60645ce85df8
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../results-02-pressure --scx-path ../target/release/scx_lavd cpu_max_bench.ini

# bounded throttled delay
git clone ba15eff6483cc57112b9d1f686805d362c9d1247
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../results-03-bound --scx-path ../target/release/scx_lavd cpu_max_bench.ini

# emergency mode
git clone 2315eebca925bff5dea4475f8581db70f18815e2
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../results-04-emergency --scx-path ../target/release/scx_lavd cpu_max_bench.ini

# clamp budget period
git clone bdcf3cb016b9b6d6bf05d0cc9bac4e65969071b2
cargo build --profile release -p scx_lavd
sudo ./cpu_max_bench.py -o ../results-05-clamp --scx-path ../target/release/scx_lavd cpu_max_bench.ini

