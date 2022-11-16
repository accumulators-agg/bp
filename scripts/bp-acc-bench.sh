#!/usr/bin/env bash
set -e
shopt -s expand_aliases
alias time='date; time'

scriptdir=$(cd $(dirname $0); pwd -P)
sourcedir=$(cd $scriptdir/..; pwd -P)

time go test ./bpacc -benchtime 4x -benchmem -timeout 10800m -run=^$ -bench=BenchmarkAccumulator
time go test ./bpacc -benchtime 4x -benchmem -timeout 10800m -run=^$ -bench=BenchmarkZKAcc
time go test ./bpacc -benchtime 4x -benchmem -timeout 10800m -run=^$ -bench=BenchmarkZKAccWitness
