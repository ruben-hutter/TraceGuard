# Technical Documentation

This directory contains the core implementation of the taint-guided symbolic execution engine. For project overview and quick start instructions, see the [main README](../README.md).

## Implementation Architecture

### Core Components

- **`main.py`**: Orchestrator script that manages Schnauzer visualization server and coordinates analysis execution
- **`taint_se.py`**: Main analysis engine implementing the TaintAnalyzer class and core taint tracking logic  
- **`taint_exploration.py`**: Custom Angr exploration technique for taint-guided state prioritization
- **`constants.py`**: Configuration constants, function databases, and architecture-specific definitions
- **`meta.py`**: Parser for function signature metadata files
- **`visualize.py`**: Integration with Schnauzer for analysis visualization

## Dependencies

See the main [README](../README.md) for installation instructions. Key dependencies include:

- **angr>=9.2.146**: Binary analysis framework
- **claripy>=9.2.146**: Symbolic constraint solver  
- **matplotlib>=3.10.1**: Plotting and visualization
- **schnauzer>=0.1.1**: Interactive analysis visualization

## API Reference

### TaintAnalyzer Class

The main analysis engine class that orchestrates the entire analysis process.

```python
from scripts.taint_se import TaintAnalyzer

analyzer = TaintAnalyzer(binary_path, args)
analyzer.run()
```

#### Initialization Parameters

- `binary_path` (str): Path to the binary file to analyze
- `args` (dict): Configuration dictionary with the following optional keys:
  - `verbose` (bool): Enable verbose logging output
  - `debug` (bool): Enable debug-level logging
  - `meta_file` (str): Path to custom meta file
  - `show_libc_prints` (bool): Show libc function call details
  - `show_syscall_prints` (bool): Show system call details  
  - `viz_output` (str): Output directory for visualization files

#### Key Methods

- `run()`: Execute the complete analysis workflow
- `_load_project()`: Initialize Angr project and load binary
- `_build_cfg_and_function_map()`: Construct control flow graph and function database
- `_setup_hooks()`: Install function hooks for taint tracking
- `_analyze_with_simgr()`: Perform guided symbolic execution

### Command Line Interface

```bash
# Main orchestrator with visualization
python scripts/main.py <binary_path> [options]

# Direct analysis engine
python scripts/taint_se.py <binary_path> [options]
```

#### Available Options

- `--verbose`, `-v`: Enable verbose logging output
- `--debug`, `-d`: Enable debug-level logging with detailed state information  
- `--meta-file <path>`: Specify custom meta file for function parameter counts
- `--show-libc-prints`: Show details for hooked libc function calls
- `--show-syscall-prints`: Show details for hooked system calls
- `--viz-output <path>`: Specify output path for visualization files

#### Example Usage

```bash
# Analyze with full debugging output
python scripts/taint_se.py examples/program1 --debug --verbose

# Use custom meta file
python scripts/taint_se.py /path/to/binary --meta-file custom.meta

# Analysis with visualization
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

To add custom taint sources, modify this set or extend the `_is_input_function()` method in `TaintAnalyzer`.

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

## Advanced Features

### Custom Exploration Techniques

The tool implements a custom Angr exploration technique in `taint_exploration.py`:

```python
from scripts.taint_exploration import TaintGuidedExploration

# Custom state prioritization based on taint density
technique = TaintGuidedExploration()
simgr.use_technique(technique)
```

### Visualization Integration

Schnauzer integration provides interactive analysis visualization:

```python
# Generate visualization data
from scripts.visualize import generate_and_visualize_graph
generate_and_visualize_graph(project, output_dir="viz_output")
```

The visualization includes:
- Control flow graph with taint annotations
- Function call hierarchy
- Execution path exploration tree
- Taint propagation flow diagrams

### Logging and Debugging

Comprehensive logging system with multiple levels:

```python
# Configure logging in your script
import logging
from scripts.taint_se import my_logger

# Set logging level
my_logger.setLevel(logging.DEBUG)

# Custom log formatting
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
```

### Performance Tuning

Key parameters for optimization:

```python
# In constants.py
MAX_TAINT_SIZE_BYTES = 1024      # Maximum size of tainted objects
DEFAULT_BUFFER_SIZE = 256        # Input buffer simulation size
TAINT_SCORE_DECAY_FACTOR = 0.9   # Score decay for distant taint
```

## Development Guidelines

### Code Structure

The implementation follows a modular design:

```
scripts/
├── main.py              # Entry point and orchestration
├── taint_se.py          # Core analysis engine (TaintAnalyzer class)
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

### Testing

Use the provided example programs for testing:

```bash
# Test basic functionality
python scripts/taint_se.py examples/program1 --debug

# Test complex scenarios
python scripts/taint_se.py examples/program3 --verbose --show-libc-prints

# Test with custom meta files
python scripts/taint_se.py examples/program5 --meta-file examples/program5.meta
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

### Future Enhancements

Potential improvements for the implementation:

- Byte-level taint tracking for improved precision
- Enhanced indirect call resolution
- Support for additional architectures (ARM, RISC-V)
- Integration with other analysis frameworks
- Performance optimizations for large-scale binaries
