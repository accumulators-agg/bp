# Bilinear Accumulators

Based on Nguyen accumulators and uses BLS12-381.

## Instructions
Dependencies
```bash
sudo apt-get update
sudo apt-get install cmake build-essential checkinstall autotools-dev autoconf libgmp-dev libgmp3-dev libflint-dev
sudo snap install go --classic
```

Install [go-mcl](https://github.com/herumi/mcl)
```
git clone --recursive https://github.com/herumi/mcl
cd mcl/
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --build build --target install
sudo ldconfig
```

Run benchmarks
```bash
time sh scripts/bp-acc-bench.sh
```
