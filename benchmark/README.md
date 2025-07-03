# TraceGuard Benchmark Suite

This directory contains the comprehensive evaluation and benchmarking infrastructure for TraceGuard's taint-guided symbolic execution approach.

## Overview

The benchmark suite compares TraceGuard against classical Angr symbolic execution across multiple test scenarios, measuring vulnerability detection effectiveness, execution time performance, and exploration efficiency.

## Quick Start

```bash
# Install benchmark dependencies
cd benchmark
uv sync

# Build test programs
make

# Run single benchmark
python benchmark_bin.py test_programs/simple_test

# Run comprehensive evaluation (thesis results)
python evaluation_runner.py --runs 10
```

## Test Programs

The `test_programs/` directory contains 7 synthetic test cases designed to evaluate specific aspects:

- **simple_test**: Basic vulnerability detection baseline
- **test_conditional_explosion**: Complex branching scenarios  
- **test_deep_exploration**: Deep call stack analysis
- **test_many_functions**: Multi-function inter-procedural analysis
- **test_perfect_scenario**: Optimal taint flow patterns
- **test_recursive_exploration**: Recursive function handling
- **test_state_explosion**: State explosion management

Each test program includes a corresponding `.meta` file defining function signatures.

## Benchmarking Tools

### Individual Benchmark Runner (`benchmark_bin.py`)

Compares TraceGuard vs Classical Angr on a single program:

```bash
python benchmark_bin.py <binary_path> [--timeout SECONDS]
```

**Output**: Detailed comparison including execution time, states explored, vulnerabilities found, and coverage analysis.

### Batch Evaluation Runner (`evaluation_runner.py`)

Runs comprehensive multi-program evaluation with statistical analysis:

```bash
# Run 10 iterations per program (thesis standard)
python evaluation_runner.py --runs 10 --timeout 120

# Evaluate specific programs
python evaluation_runner.py --programs test_programs/simple_test test_programs/test_state_explosion

# Quick evaluation (5 runs)
python evaluation_runner.py --runs 5
```

**Output**: 
- Individual program analysis reports
- Aggregated statistical results with confidence intervals
- Comparative plots and visualizations
- JSON data for further analysis

## Evaluation Metrics

The benchmark suite measures:

- **Effectiveness**: Vulnerability detection rate, number of vulnerabilities found
- **Efficiency**: Total execution time, time to first vulnerability
- **Coverage**: Basic blocks covered, exploration efficiency ratio
- **Scalability**: Performance under state explosion conditions
- **Reliability**: Success rate across multiple runs, statistical variance

## Results Structure

```
evaluation_results/
├── eval_YYYYMMDD_HHMMSS/
│   ├── program_name_raw_results.json      # Raw benchmark data
│   ├── program_name_aggregated.json       # Statistical summary
│   ├── program_name_comparison.png        # Comparative plots
│   ├── evaluation_summary.txt             # Human-readable report
│   └── latest_program_name.json           # Symlink to latest results
```

## Dependencies

The benchmark suite requires one additional dependency beyond the main project:

```toml
[project]
dependencies = [
    "matplotlib>=3.10.3",  # For result visualization and statistical plots
]
```

Angr is inherited from the main project workspace. Install via: `uv sync` or `pip install -r requirements.txt`

## Research Applications

This benchmarking infrastructure supports:

- **Thesis Evaluation**: Quantitative comparison for academic research
- **Performance Regression Testing**: Ensuring optimization improvements
- **Methodology Validation**: Verifying taint-guided approach effectiveness  
- **Baseline Establishment**: Reference performance for future enhancements

## Configuration

Key parameters in evaluation scripts:

- **Timeout**: Maximum analysis time per run (default: 120s)
- **Iterations**: Number of runs for statistical significance (default: 10)
- **State Limits**: Maximum concurrent states (default: 15)
- **Exploration Techniques**: DFS, LoopSeer, LengthLimiter configurations

## Implementation Notes

The benchmark suite implements:

- **Isolated Execution**: Each run uses fresh TraceGuard/Angr instances
- **Resource Monitoring**: Memory usage and execution time tracking
- **Statistical Analysis**: Mean, standard deviation, confidence intervals
- **Result Validation**: Consistency checks across multiple runs
- **Progress Tracking**: Real-time feedback during long evaluations

## Integration with Main Project

The benchmark suite integrates with TraceGuard through:

- **Direct Import**: Uses `taint_se.TraceGuard` class for analysis
- **Shared Configuration**: Common constants and architecture definitions
- **Result Compatibility**: JSON output format compatible with thesis analysis

For technical implementation details, see the main project [README](../README.md) and [scripts documentation](../scripts/README.md).
