# TraceGuard

A research tool implementing taint-guided symbolic execution to optimize binary analysis by focusing on security-relevant execution paths.

## Overview

This project addresses the path explosion problem in symbolic execution by combining dynamic taint analysis with symbolic execution. The approach tracks taint propagation from input sources and uses this information to guide symbolic execution toward functions that process potentially malicious data, significantly reducing analysis time while maintaining security coverage.

**Research Context**: This implementation is part of a Bachelor's thesis in Computer Science at the University of Basel, investigating novel approaches to optimize symbolic execution for security analysis.

## Key Features

- **Taint-guided exploration**: Automatically identifies and prioritizes security-relevant execution paths
- **Selective function execution**: Reduces analysis overhead by skipping functions that don't process tainted data
- **Multi-architecture support**: Works with AMD64 and X86 binaries
- **Interactive visualization**: Integrates with Schnauzer for real-time analysis exploration
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
git clone <repository-url>
cd taint-guided-se

# Install dependencies
uv sync
```

#### Using pip
```bash
# Clone and set up virtual environment
git clone <repository-url>
cd taint-guided-se
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install angr>=9.2.146 claripy>=9.2.146 matplotlib>=3.10.1 schnauzer>=0.1.1
```

### Basic Usage

```bash
# Build example programs
make

# Run analysis with visualization
python scripts/main.py examples/program1

# Run analysis without visualization
python scripts/taint_se.py examples/program1 --verbose
```

The tool will automatically:
1. Load and analyze the binary
2. Identify input functions and taint sources
3. Perform taint-guided symbolic execution
4. Generate analysis results and visualizations

## Repository Structure

```
├── examples/          # Test programs demonstrating various taint scenarios
│   ├── *.c           # C source files for testing
│   └── *.meta        # Function signature metadata
├── scripts/          # Main analysis implementation
│   ├── main.py       # Orchestrator script with visualization
│   ├── taint_se.py   # Core taint analysis engine
│   └── README.md     # Detailed technical documentation
├── thesis/           # LaTeX thesis documentation
├── pyproject.toml    # Project dependencies and metadata
└── Makefile          # Build system for examples
```

## How It Works

The tool implements a three-phase approach:

1. **Taint Source Identification**: Automatically identifies input functions (fgets, scanf, read, etc.) as taint sources
2. **Dynamic Taint Tracking**: Monitors taint propagation through function calls and memory operations  
3. **Guided Symbolic Execution**: Prioritizes exploration of execution paths that process tainted data

This approach significantly reduces the state space that symbolic execution must explore while maintaining comprehensive coverage of security-relevant code paths.

## Example Programs

The `examples/` directory contains test programs of increasing complexity:

- **program1.c**: Simple linear taint flow
- **program3.c**: Complex multi-input scenarios with deep call chains
- **program5.c**: Advanced control flow and conditional execution

Each program includes corresponding `.meta` files specifying function signatures for optimal analysis.

## Research Applications

This tool is designed for:

- **Security researchers** investigating automated vulnerability discovery
- **Binary analysis** of programs with complex input processing
- **Academic research** in symbolic execution optimization
- **Comparative studies** of different program analysis approaches

## Documentation

- **[Technical Documentation](scripts/README.md)**: Comprehensive implementation details, API reference, and troubleshooting
- **[Thesis Documentation](thesis/)**: Academic background, theoretical foundations, and evaluation results
- **[Example Programs](examples/)**: Annotated test cases demonstrating different analysis scenarios

## Performance

Preliminary results show significant improvements over traditional symbolic execution:

- **Reduced state explosion**: 60-80% reduction in explored states for typical programs
- **Maintained coverage**: Preserves coverage of security-relevant execution paths  
- **Faster vulnerability discovery**: Finds security issues more quickly by focusing on tainted data flows

*Detailed evaluation results are available in the thesis documentation.*

## Contributing

This project is part of ongoing academic research. Contributions are welcome, particularly:

- Additional test programs and benchmarks
- Support for new architectures
- Enhanced taint tracking precision
- Integration with other analysis frameworks

Please see the [technical documentation](scripts/README.md) for development guidelines.

## Academic Citation

If you use this tool in academic research, please cite:

```
@mastersthesis{hutter2025taint,
  title={Taint-Guided Symbolic Execution},
  author={Ruben Hutter},
  school={University of Basel},
  year={2025}
}
```

## License

This project is developed as part of academic research at the University of Basel. Please contact the author for licensing information.

## Contact

- **Author**: Ruben Hutter (ruben.hutter@unibas.ch)
- **Supervisor**: Prof. Dr. Christopher Scherb
- **Institution**: University of Basel, Department of Mathematics and Computer Science

---

*This work is part of a Bachelor's thesis investigating novel approaches to optimize symbolic execution for security analysis. The research aims to address the fundamental path explosion problem in symbolic execution while maintaining comprehensive security coverage.*
