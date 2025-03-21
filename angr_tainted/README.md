# Angr Tainted Input Analysis

This tool uses symbolic execution with taint tracking to optimize binary analysis by selectively executing only the functions that process tainted input data.

## Features

- Tracks taint from stdin through function calls and data operations
- Dynamically skips functions that don't operate on tainted data
- Always executes essential functions (_start, main, input functions)
- Provides detailed execution logs and statistics
- Temporarily unhooks and executes real functions when tainted data is detected

## How It Works

1. The analyzer hooks all input functions (fgets, gets, read, scanf) to mark their outputs as tainted data
2. All user-defined functions are hooked with a checker that inspects parameters for taint
3. When a function is called:
   - Essential functions (main, _start, input functions) are always executed
   - If any parameter is tainted, the function is temporarily unhooked and executed
   - If no parameters are tainted, the function is skipped and a default return value is used
4. Taint is tracked through variable naming (variables with "stdin" in their name)
5. Detailed logs show which functions were executed vs. skipped and why

## Requirements

- Python 3.6+
- angr
- claripy

Install dependencies:

```bash
make install-deps
```

## Usage

```bash
python simple_taint.py <binary_path> [--quiet]
```

Using the Makefile:

```bash
# Analyze program1 with detailed output
make analyze

# Analyze program1 with minimal output
make analyze-quiet

# Analyze all test programs with detailed output
make analyze-all

# Analyze all test programs with minimal output
make analyze-all-quiet
```

## Test Programs

Three test programs are included:

1. `program1.c`: A simple program with one stdin input feeding into function calls
2. `program2.c`: Program with two stdin inputs and various function call patterns
3. `program3.c`: More complex program with three inputs and deeper function call chains

Build the test programs:

```bash
make
```

## Implementation Details

- Function hooks use SimProcedures to inspect parameters for taint
- When a function needs execution (essential or tainted parameters):
  1. The hook is temporarily removed
  2. The function is executed in a new simulation manager
  3. The return value is captured and returned
  4. The hook is restored for future calls
- Statistics are collected on executed vs. skipped functions
- Verbosity control allows detailed or minimal output

## Limitations

- Taint tracking is based on simple variable name matching
- Taint propagation through complex data structures is limited
- Function execution in a separate simulation manager may not fully propagate state changes
- Loop bounds are set to prevent infinite execution but may limit analysis depth
- Limited tracking of taint through arithmetic operations

## Future Improvements

- More comprehensive taint tracking through memory operations
- Enhanced taint propagation through arithmetic and logical operations
- Better state merging after function execution
- Support for custom taint sources beyond stdin
- More sophisticated return value handling for skipped functions