# Technical Documentation

This directory contains the core implementation of the taint-guided symbolic execution engine. For project overview and quick start instructions, see the [main README](../README.md).

## Implementation Architecture

### Core Components

- **`main.py`**: Orchestrator script that manages Schnauzer visualization server and coordinates analysis execution
- **`trace_guard.py`**: Terminal entry point with visualization integration for TraceGuard analysis
- **`taint_se.py`**: Main analysis engine implementing the TraceGuard class and core taint tracking logic  
- **`taint_exploration.py`**: Custom Angr exploration technique for taint-guided state prioritization
- **`constants.py`**: Configuration constants, function databases, and architecture-specific definitions
- **`meta.py`**: Parser for function signature metadata files
- **`visualize.py`**: Integration with Schnauzer for analysis visualization

## Dependencies

The main project dependencies are defined in the root `requirements.txt`:

- **angr**: Binary analysis framework
- **claripy**: Symbolic constraint solver  
- **schnauzer**: Interactive analysis visualization
- **networkx**: Graph processing for visualization

## API Reference

### TraceGuard Class

The main analysis engine class that orchestrates the entire analysis process.

```python
from scripts.taint_se import TraceGuard

# Initialize analyzer
trace_guard = TraceGuard(binary_path, args)

# Run analysis and get structured results
result = trace_guard.run_analysis()
```

#### Initialization Parameters

- `binary_path` (Path): Path to the binary file to analyze
- `args` (dict): Configuration dictionary with the following optional keys:
  - `verbose` (bool): Enable verbose logging output
  - `debug` (bool): Enable debug-level logging
  - `meta_file` (str): Path to custom meta file
  - `show_libc_prints` (bool): Show libc function call details
  - `show_syscall_prints` (bool): Show system call details  
  - `quite` (bool): Suppress detailed output for benchmarking

#### Key Methods

- `run_analysis()`: Execute the complete analysis workflow and return `AnalysisResult`
- `_load_project()`: Initialize Angr project and load binary
- `_build_cfg_and_function_map()`: Construct control flow graph and function database
- `_setup_hooks()`: Install function hooks for taint tracking
- `_analyze_with_simgr()`: Perform guided symbolic execution

#### Return Value: AnalysisResult

The `run_analysis()` method returns a structured `AnalysisResult` dataclass containing:

```python
@dataclass
class AnalysisResult:
    # Basic execution info
    success: bool
    analysis_time: float
    
    # Simulation states
    active_states: int
    deadended_states: int
    errored_states: int
    unconstrained_states: int
    
    # Taint-specific metrics
    functions_analyzed: int
    functions_executed: int
    functions_skipped: int
    taint_sources_found: int
    tainted_functions: List[str]
    tainted_edges: List[tuple]
    
    # Vulnerability metrics
    vulnerabilities_found: int
    time_to_first_vuln: Optional[float]
    vulnerability_details: List[Dict[str, Any]]
    
    # Coverage metrics
    basic_blocks_covered: int
    states_explored: int
    
    # Additional metrics
    memory_usage_mb: float
    error_message: Optional[str] = None
```

### Command Line Interfaces

#### Main Orchestrator (main.py)
```bash
python scripts/main.py <binary_path> [options]
```

#### Terminal Entry Point (trace_guard.py)
```bash
python scripts/trace_guard.py <binary_path> [options]
```

#### Direct Analysis Engine (taint_se.py)
```bash
python scripts/taint_se.py <binary_path> [options]
```

#### Available Options

- `--verbose`, `-v`: Enable verbose logging output
- `--debug`, `-d`: Enable debug-level logging with detailed state information  
- `--meta-file <path>`: Specify custom meta file for function parameter counts
- `--show-libc-prints`: Show details for hooked libc function calls
- `--show-syscall-prints`: Show details for hooked system calls

#### Example Usage

```bash
# Run analysis with visualization integration
python scripts/trace_guard.py examples/program1 --verbose

# Direct analysis with debugging
python scripts/taint_se.py examples/program1 --debug --verbose

# Use custom meta file
python scripts/taint_se.py /path/to/binary --meta-file custom.meta

# Orchestrated analysis with visualization server
python scripts/main.py examples/program3 --show-libc-prints
```

## Configuration and Customization

### Meta Files

Meta files provide function signature information for accurate parameter taint checking. They use a C-like syntax:

```c
// Function signatures with parameter counts
void process_data(const char *input, const char *fixed);
void analyze_string(const char *str);
int helper_function(char *buffer, int size, const char *format);
```

**Format Rules**:
- One function signature per line
- Comments start with `//` or `#` and are ignored
- Trailing semicolons are optional
- Function name is extracted from the rightmost identifier before parentheses
- Parameter count is determined by comma-separated arguments (void = 0 parameters)

### Taint Source Configuration

Input functions are automatically detected from the built-in database in `constants.py`:

```python
INPUT_FUNCTION_NAMES = {
    "fgets", "gets", "scanf", "fscanf", "fread", "read",
    "getchar", "fgetc", "getline", "recv", "recvfrom"
}
```

To add custom taint sources, modify this set or extend the `_is_input_function()` method in `TraceGuard`.

### Architecture-Specific Settings

Register mappings for different architectures are defined in `constants.py`:

```python
# AMD64 calling convention
AMD64_ARGUMENT_REGISTERS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
AMD64_RETURN_REGISTER = "rax"

# X86 calling convention  
X86_ARGUMENT_REGISTERS = []  # Stack-based
X86_RETURN_REGISTER = "eax"
```

### Performance Tuning

Key parameters for optimization in `constants.py`:

```python
# Taint tracking parameters
MAX_TAINT_SIZE_BYTES = 1024      # Maximum size of tainted objects
DEFAULT_BUFFER_SIZE = 256        # Input buffer simulation size
TAINT_SCORE_DECAY_FACTOR = 0.9   # Score decay for distant taint

# Scoring weights
TAINT_SCORE_INPUT_FUNCTION = 100     # Base score for input functions
TAINT_SCORE_TAINTED_CALL = 50        # Score for calls with tainted args
TAINT_SCORE_FUNCTION_CALL = 10       # Base score for function calls
TAINT_SCORE_INPUT_HOOK_BONUS = 25    # Bonus for input function hooks
TAINT_SCORE_MINIMUM_TAINTED = 5      # Minimum score for tainted states
```

## Advanced Features

### Custom Exploration Techniques

The tool implements a custom Angr exploration technique in `taint_exploration.py`:

```python
from scripts.taint_exploration import TaintGuidedExploration

# Custom state prioritization based on taint density
technique = TaintGuidedExploration()
simgr.use_technique(technique)
```

The exploration technique provides:
- **Taint-aware state prioritization**: States processing tainted data are explored first
- **Dynamic scoring**: States receive scores based on taint propagation patterns
- **Exploration depth control**: Prevents excessive depth in non-tainted branches

### Visualization Integration

Schnauzer integration provides interactive analysis visualization:

```python
# Generate visualization data
from scripts.visualize import generate_and_visualize_graph
generate_and_visualize_graph(project, func_info_map, my_logger)
```

The visualization includes:
- Control flow graph with taint annotations
- Function call hierarchy with taint flow
- Execution path exploration tree
- Interactive state inspection
- Real-time analysis progress

### Logging and Debugging

Comprehensive logging system with multiple levels:

```python
# Configure logging in your script
import logging
from scripts.taint_se import my_logger

# Set logging level
my_logger.setLevel(logging.DEBUG)

# Custom log formatting available in constants.py
DEBUG_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
INFO_LOG_FORMAT = "%(levelname)s: %(message)s"
```

## Module Integration

### Using TraceGuard as a Library

The refactored codebase allows easy integration into other projects:

```python
from pathlib import Path
from scripts.taint_se import TraceGuard

def analyze_binary(binary_path: str) -> bool:
    """Example integration function"""
    args = {
        "verbose": False,
        "debug": False,
        "quite": True  # Suppress output for integration
    }
    
    trace_guard = TraceGuard(Path(binary_path), args)
    result = trace_guard.run_analysis()
    
    return result.success and result.vulnerabilities_found > 0

# Usage
if analyze_binary("path/to/binary"):
    print("Vulnerabilities detected!")
```

### Benchmark Integration

The benchmark suite demonstrates advanced integration patterns:

```python
# From benchmark/benchmark_bin.py
from taint_se import TraceGuard

# Create TraceGuard instance with benchmark configuration
args = {
    "verbose": False,
    "debug": False,
    "meta_file": None,
    "show_libc_prints": False,
    "show_syscall_prints": False,
    "quite": True,  # Suppress detailed output
}

trace_guard = TraceGuard(binary_path, args)
result = trace_guard.run_analysis()

# Extract metrics for comparison
metrics = {
    "execution_time": result.analysis_time,
    "states_explored": result.states_explored,
    "vulnerabilities_found": result.vulnerabilities_found,
    "coverage": result.basic_blocks_covered
}
```

## Development Guidelines

### Code Structure

The implementation follows a modular design:

```
scripts/
├── main.py              # Entry point with server orchestration
├── trace_guard.py       # Terminal entry point with visualization
├── taint_se.py          # Core analysis engine (TraceGuard class)
├── taint_exploration.py # Custom Angr exploration technique
├── constants.py         # Configuration and architecture definitions  
├── meta.py             # Meta file parsing utilities
└── visualize.py        # Schnauzer integration
```

### Adding New Features

1. **New Taint Sources**: Add function names to `INPUT_FUNCTION_NAMES` in `constants.py`
2. **Architecture Support**: Extend register mappings in architecture configuration
3. **Custom Hooks**: Implement new SimProcedures and register in `_setup_hooks()`
4. **Exploration Strategies**: Modify `TaintGuidedExploration` class for new prioritization logic
5. **Analysis Metrics**: Extend `AnalysisResult` dataclass for new measurement types

### Testing and Validation

Use the provided example programs for testing:

```bash
# Test basic functionality
python scripts/taint_se.py examples/program1 --debug

# Test complex scenarios with meta files
python scripts/taint_se.py examples/program5 --meta-file examples/program5.meta

# Test visualization integration
python scripts/trace_guard.py examples/program3 --verbose --show-libc-prints

# Benchmark performance
cd benchmark && python benchmark_bin.py ../examples/program1
```

## Implementation Notes

### Known Limitations

- **Taint Granularity**: Currently tracks taint at function parameter level; byte-level tracking within data structures is limited
- **Indirect Calls**: Complex function pointer scenarios may not be fully captured
- **Memory Layout**: Architecture-specific memory layouts may affect taint tracking accuracy
- **Constraint Complexity**: Very complex path conditions may impact solver performance

### Performance Considerations

- **State Explosion**: While reduced compared to standard symbolic execution, complex programs may still generate many states
- **Memory Usage**: Large binaries or deep call stacks can consume significant memory
- **Solver Timeouts**: Complex constraint systems may require timeout adjustments
- **Visualization Overhead**: Schnauzer integration adds minimal performance overhead during analysis

### Error Handling

The codebase includes comprehensive error handling:

```python
class AnalysisSetupError(Exception):
    """Custom exception for errors during TraceGuard setup."""
    pass

# Usage in TraceGuard class
try:
    self.project = angr.Project(self.binary_path, auto_load_libs=False)
except angr.errors.AngrFileNotFoundError as e:
    raise AnalysisSetupError(f"Binary file not found: {self.binary_path}") from e
```

### Future Enhancements

Potential improvements for the implementation:

- **Byte-level Taint Tracking**: More precise taint propagation within data structures
- **Enhanced Indirect Call Resolution**: Better handling of function pointers and virtual calls
- **Additional Architecture Support**: ARM, RISC-V, and other architectures
- **Machine Learning Integration**: ML-guided exploration strategies
- **Distributed Analysis**: Support for parallel analysis across multiple cores
- **Cloud Integration**: Remote analysis capabilities for large-scale evaluations

For project overview, installation instructions, and usage examples, see the [main README](../README.md).
