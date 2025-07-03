# TraceGuard

A research tool implementing taint-guided symbolic execution to optimize binary analysis by focusing on security-relevant execution paths.

## Overview

This project addresses the path explosion problem in symbolic execution by combining dynamic taint analysis with symbolic execution. The approach tracks taint propagation from input sources and uses this information to guide symbolic execution toward functions that process potentially malicious data, significantly reducing analysis time while maintaining security coverage.

**Research Context**: This implementation is part of my Bachelor's thesis in Computer Science at the University of Basel, investigating novel approaches to optimize symbolic execution for security analysis.

## Key Features

- **Taint-guided exploration**: Automatically identifies and prioritizes security-relevant execution paths
- **Selective function execution**: Reduces analysis overhead by skipping functions that don't process tainted data
- **Multi-architecture support**: Works with AMD64 and X86 binaries
- **Interactive visualization**: Integrates with Schnauzer for real-time analysis exploration
- **Comprehensive benchmarking**: Includes dedicated benchmarking suite for performance evaluation
- **Flexible configuration**: Supports custom taint sources and analysis parameters

## Quick Start

### Prerequisites

- Python 3.13+
- GCC or Clang compiler
- Linux/Unix environment (macOS users may need Rosetta for x86_64)

### Installation

#### Using uv (Recommended)

```bash
# Clone the repository
git clone https://github.com/ruben-hutter/TraceGuard.git
cd TraceGuard

# Install dependencies for main project
uv sync

# Install benchmark dependencies (optional)
cd benchmark
uv sync
cd ..
```

#### Using pip

```bash
# Clone and set up virtual environment
git clone https://github.com/ruben-hutter/TraceGuard.git
cd TraceGuard
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install main project dependencies
pip install -r requirements.txt

# Install benchmark dependencies (optional)
cd benchmark
pip install -r requirements.txt
cd ..
```

### Basic Usage

```bash
# Build example programs
make

# Run analysis with visualization (orchestrator)
python scripts/trace_guard.py examples/program1

# Run analysis with visualization (terminal entry point)
python scripts/trace_guard.py examples/program1 --verbose

# Run analysis without visualization (direct engine)
python scripts/taint_se.py examples/program1 --verbose
```

The tool will automatically:
1. Load and analyze the binary
2. Identify input functions and taint sources
3. Perform taint-guided symbolic execution
4. Generate analysis results and visualizations

## Repository Structure

```
├── examples/              # Test programs demonstrating various taint scenarios
│   ├── *.c               # C source files for testing
│   └── *.meta            # Function signature metadata
├── scripts/              # Main analysis implementation
│   ├── main.py           # Orchestrator script with visualization
│   ├── trace_guard.py    # Terminal entry point with visualization
│   ├── taint_se.py       # Core taint analysis engine (TraceGuard class)
│   ├── taint_exploration.py # Custom Angr exploration technique
│   ├── constants.py      # Configuration and architecture definitions
│   ├── meta.py          # Meta file parsing utilities
│   ├── visualize.py     # Schnauzer integration
│   └── README.md        # Detailed technical documentation
├── benchmark/            # Benchmarking and evaluation suite
│   ├── benchmark_bin.py  # Individual benchmark runner
│   ├── evaluation_runner.py # Batch evaluation for thesis
│   ├── test_programs/    # Benchmark test programs
│   ├── pyproject.toml    # Benchmark-specific dependencies
│   └── Makefile         # Build system for benchmark programs
├── thesis/              # LaTeX thesis documentation
├── pyproject.toml       # Main project dependencies and uv workspace
└── Makefile            # Build system for examples
```

## How It Works

The tool implements a three-phase approach:

1. **Static Analysis Phase**: Constructs control flow graph and identifies potential taint sources
2. **Dynamic Taint Tracking**: Monitors data flow from input functions and propagates taint through function calls
3. **Guided Symbolic Execution**: Prioritizes exploration of paths that process tainted data while maintaining comprehensive coverage

### Key Components

- **TraceGuard Class**: Main analysis engine implementing the complete taint-guided symbolic execution workflow
- **TaintGuidedExploration**: Custom Angr exploration technique for intelligent state prioritization
- **Function Hooking System**: Monitors input functions (scanf, fgets, read, etc.) to track taint propagation
- **Visualization Integration**: Real-time analysis visualization through Schnauzer web interface

## Performance Evaluation

TraceGuard includes a comprehensive benchmarking suite for evaluating performance against classical symbolic execution:

```bash
# Run individual benchmark comparison
cd benchmark
python benchmark_bin.py test_programs/program1

# Run batch evaluation for thesis
python evaluation_runner.py

# Build benchmark test programs
make
```

The benchmarking suite provides:
- **Execution time comparison**: TraceGuard vs classical symbolic execution
- **State exploration efficiency**: Reduction in states explored while maintaining coverage
- **Vulnerability detection rates**: Effectiveness at finding security-relevant issues
- **Statistical analysis**: Multiple runs with aggregated results and confidence intervals

## Configuration Options

### Command Line Arguments

- `--verbose`, `-v`: Enable verbose logging output
- `--debug`, `-d`: Enable debug-level logging with detailed state information
- `--meta-file <path>`: Specify custom meta file for function parameter counts
- `--show-libc-prints`: Show details for hooked libc function calls
- `--show-syscall-prints`: Show details for hooked system calls

### Meta Files

Function signature metadata files (`.meta`) provide parameter count information for accurate taint tracking:

```c
// Example: program1.meta
// Program1 function definitions
void helper_function(const char *data);
void process_data(const char *input, const char *fixed);
void analyze_string(const char *str);
void untainted_function(const char *fixed_str);
```

Meta files are automatically detected alongside binaries or can be specified with `--meta-file`.

### Architecture Support

Currently supports:
- **AMD64**: Full register-based argument tracking (rdi, rsi, rdx, rcx, r8, r9)
- **X86**: Stack-based argument tracking with return value monitoring (partially supported)

## Development Workflow

### Workspace Structure

The project uses uv workspace management with two main components:

1. **Main Project** (`pyproject.toml`): Core TraceGuard implementation
2. **Benchmark Suite** (`benchmark/pyproject.toml`): Evaluation and benchmarking tools

### Adding New Features

1. **Taint Sources**: Add function names to `INPUT_FUNCTION_NAMES` in `constants.py`
2. **Architecture Support**: Extend register mappings in architecture configuration
3. **Custom Hooks**: Implement new SimProcedures and register in `_setup_hooks()`
4. **Benchmark Programs**: Add test cases to `benchmark/test_programs/`

### Testing

```bash
# Test core functionality
python scripts/taint_se.py examples/program1 --debug

# Test with meta files
python scripts/taint_se.py examples/program5 --meta-file examples/program5.meta

# Test visualization integration
python scripts/trace_guard.py examples/program3 --verbose

# Run benchmarks
cd benchmark && python benchmark_bin.py test_programs/program1
```

## Research Applications

This tool supports various research applications in program analysis:

- **Vulnerability Discovery**: Focused exploration of security-relevant code paths
- **Fuzzing Target Identification**: Prioritizing functions for targeted fuzzing campaigns
- **Code Coverage Analysis**: Understanding which parts of programs process external input
- **Performance Optimization**: Reducing symbolic execution overhead through intelligent guidance

## Citation

If you use TraceGuard in your research, please cite:

```
[Bachelor's Thesis Citation - To be updated upon completion]
University of Basel, Computer Science Department
Taint-Guided Symbolic Execution for Enhanced Binary Analysis
```

## Contributing

This is a research project developed as part of a Bachelor's thesis. For questions or collaboration opportunities, please contact the University of Basel Computer Science Department.

## License

This project is developed for academic research purposes. See thesis documentation for detailed licensing information.

## Known Limitations

- **Taint Granularity**: Currently tracks taint at function parameter level
- **Complex Data Structures**: Limited byte-level tracking within nested structures  
- **Indirect Calls**: Function pointer scenarios may require manual annotation
- **Solver Complexity**: Performance scales with constraint system complexity

For technical details, implementation notes, and API documentation, see [scripts/README.md](scripts/README.md).
