# Taint Analyzer Explained

This document explains the functionality and implementation of the taint analyzer tool that uses the Angr binary analysis framework to track tainted data flow through binary programs and skip execution of functions that don't receive tainted inputs.

## Table of Contents
1. [Introduction](#introduction)
2. [Core Components](#core-components)
3. [Meta File Parsing](#meta-file-parsing)
4. [Taint Introduction](#taint-introduction)
5. [Taint Checking](#taint-checking)
6. [Parameter Count Estimation](#parameter-count-estimation)
7. [Function Execution Control](#function-execution-control)
8. [Main Analysis Workflow](#main-analysis-workflow)
9. [Command Line Interface](#command-line-interface)

## Introduction

The taint analyzer is a Python tool that performs dynamic taint analysis on binary programs using symbolic execution. It identifies functions that receive user input (tainted data) and only executes those functions, skipping functions that don't operate on user-controlled data. This approach helps focus analysis on security-critical code paths.

Key features of the taint analyzer:

- Uses Angr to perform symbolic execution of binary programs
- Introduces taint through simulated input functions (like `fgets`)
- Tracks taint propagation through registers and memory
- Skips execution of functions that don't receive tainted data
- Supports parameter count estimation through multiple methods
- Parses metadata files to improve function signature information

## Core Components

The analyzer is structured around several core components:

```python
def analyze(binary_path, verbose=True, max_steps=50, param_overrides=None, meta_file=None):
    """Analyze the binary, skipping functions with untainted parameters."""
    # ...
```

The main `analyze` function coordinates the entire analysis process and integrates all components:

1. `parse_meta_file` - Parses metadata containing function prototypes
2. `FgetsTainter` - SimProcedure for introducing tainted data
3. `CheckTaintHook` - SimProcedure for checking parameter taint and controlling execution

## Meta File Parsing

The analyzer can read function parameter information from a metadata file:

```python
def parse_meta_file(meta_path, verbose=True):
    """Parse a meta file with function prototypes to get parameter counts."""
    function_params = {}
    
    with open(meta_path, 'r') as f:
        contents = f.read()
        # ...
        
        for line_num, line in enumerate(contents.splitlines(), 1):
            # Skip empty lines and comments
            line = line.strip()
            if not line or line.startswith(('//','#')):
                continue
                
            # Parse function prototype
            if '(' in line and ')' in line:
                # Extract function name
                func_part = line.split('(')[0].strip()
                func_name = func_part.split()[-1]
                
                # Extract and count parameters
                params_str = line.split('(')[1].split(')')[0].strip()
                param_count = 0 if not params_str or params_str.lower() == 'void' else len(params_str.split(','))
                    
                # Store result
                function_params[func_name] = param_count
    
    return function_params
```

This function:
- Reads a file containing C-style function prototypes
- Parses each line to extract function names and parameter counts
- Returns a dictionary mapping function names to parameter counts

For example, given a meta file with:
```c
void transform_data(const char *data, const char *suffix);
void secondary_process(const char *input);
```

It would produce:
```python
{
    'transform_data': 2,
    'secondary_process': 1
}
```

## Taint Introduction

The analyzer introduces tainted data through a custom implementation of the `fgets` function:

```python
class FgetsTainter(angr.SimProcedure):
    """SimProcedure for tainting input from fgets."""
    def __init__(self, verbose=True, **kwargs):
        super().__init__(**kwargs)
        self.verbose = verbose
        
    def run(self, buf, size, fp):
        """Create tainted buffer with 'stdin' in variable name."""
        # Create symbolic buffer and store in memory
        sym_buf = self.state.solver.BVS("stdin_data", 8 * 100)
        self.state.memory.store(buf, sym_buf)
        self.state.memory.store(buf + 99, self.state.solver.BVV(0, 8))  # Null terminator
        
        if self.verbose:
            print("Added tainted data")
        
        return buf
```

This SimProcedure:
- Replaces calls to the real `fgets` function
- Creates a symbolic buffer with the name "stdin_data"
- Stores this symbolic buffer in the memory location pointed to by `buf`
- Adds a null terminator to ensure the buffer is properly terminated
- Returns the buffer pointer just like the real `fgets` would

The key here is that Angr will track the symbolic values tagged with "stdin_data" as they propagate through the program.

## Taint Checking

The core of the analyzer is the `CheckTaintHook` SimProcedure that inspects function parameters:

```python
def _is_tainted(self, value):
    """Check if value contains tainted data."""
    if not hasattr(value, 'symbolic') or not value.symbolic:
        return False
        
    # Check variable names for 'stdin'
    if hasattr(value, 'variables'):
        return any('stdin' in var for var in value.variables)
            
    return False
```

This method determines if a value is tainted by:
- Checking if the value is symbolic (not a concrete value)
- Looking for "stdin" in the variable names associated with the value

The `_check_parameters` method examines function parameters for taint:

```python
def _check_parameters(self, param_count):
    """Check function parameters for taint."""
    # Get calling convention registers
    cc = self.project.factory.cc()
    param_registers = getattr(cc, 'ARG_REGS', ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'])
    
    # Check parameters in registers
    reg_params_checked = min(param_count, len(param_registers))
    for i in range(reg_params_checked):
        reg = param_registers[i]
        try:
            reg_val = getattr(self.state.regs, reg)
            
            # Check direct taint
            if self._is_tainted(reg_val):
                return True, reg
                
            # Check indirect taint (pointer to tainted data)
            if not reg_val.symbolic and reg_val.concrete:
                try:
                    mem_data = self.state.memory.load(reg_val, 8)
                    if self._is_tainted(mem_data):
                        return True, f"*{reg}"
                except:
                    pass
        except:
            pass
            
    # Additional code for checking stack parameters...
            
    return False, None
```

This method:
- Determines which registers hold parameters according to the calling convention
- Checks each parameter register for tainted values
- Also checks for indirect taint (pointers to tainted data)
- Returns whether any parameter is tainted and, if so, which one

## Parameter Count Estimation

To accurately check function parameters, the analyzer needs to know how many parameters each function expects. It uses multiple methods to estimate this:

```python
def _get_param_count(self):
    """Determine parameter count from various sources."""
    # Check user-provided parameter overrides
    if hasattr(self.project, '_param_overrides') and self.func_name in self.project._param_overrides:
        return self.project._param_overrides[self.func_name]
        
    # Check parameter count from static analysis
    if hasattr(self.project, '_param_counts') and self.func_address in self.project._param_counts:
        static_param_count = self.project._param_counts[self.func_address]
        if 1 <= static_param_count <= 6:
            return static_param_count
            
    # Check prototype info from angr
    func_info = self.project.kb.functions.get(self.func_address)
    if func_info and hasattr(func_info, 'prototype') and func_info.prototype:
        if hasattr(func_info.prototype, 'args') and func_info.prototype.args:
            proto_param_count = len(func_info.prototype.args)
            if 1 <= proto_param_count <= 6:
                return proto_param_count
    
    # Default to 1 parameter for most functions
    return 1
```

The analyzer also performs static analysis on the binary to estimate parameter counts:

```python
# Analyze function calls in the CFG to estimate parameter counts
for func in project.kb.functions.values():
    # Skip external functions
    if func.is_plt or func.is_syscall:
        continue
        
    # Default to the maximum number of register parameters for this arch
    project._param_counts[func.addr] = 6  # x86_64 uses 6 registers for parameters
    
    # Try multiple approaches to estimate parameter count
    max_observed_args = 0
    
    # Look at function's caller instructions for parameter setup
    try:
        for caller_func in cfg.functions.values():
            # ... code that analyzes call sites ...
            # ... counts parameter register assignments before calls ...
    except Exception:
        pass
    
    # Look at function's first blocks for register usage detection
    try:
        # ... code that analyzes function prologue blocks ...
        # ... detects which parameter registers are accessed ...
    except Exception:
        pass
            
    # If we found evidence of parameters, use that count
    if max_observed_args > 0:
        project._param_counts[func.addr] = max_observed_args
```

This approach:
- Analyzes call sites to see how many parameters are set up before calls
- Examines function bodies to see which parameter registers are accessed
- Uses the highest observed parameter count

## Function Execution Control

The analyzer controls which functions are executed based on taint analysis:

```python
def run(self, *args):
    """Check if function should be executed based on parameter taint."""
    # Always execute essential functions
    if self.essential:
        if self.verbose:
            print(f"EXECUTE: {self.func_name} (essential function)")
        try:
            self.project._executed_count += 1
        except:
            pass
        return self._execute_original_function()
    
    # Determine parameter count from various sources
    param_count = self._get_param_count()
    
    # Check for tainted parameters
    tainted, tainted_reg = self._check_parameters(param_count)
        
    if tainted:
        # Execute function normally
        if self.verbose:
            print(f"EXECUTE: {self.func_name} (tainted arg in {tainted_reg})")
        try:
            self.project._executed_count += 1
        except:
            pass
        return self._execute_original_function()
    else:
        # Skip function execution
        if self.verbose:
            print(f"SKIP: {self.func_name} (no tainted args)")
        try:
            self.project._skipped_count += 1
        except:
            pass
        return 0  # Default return value
```

When executing the original function:

```python
def _execute_original_function(self):
    """Execute the original function by temporarily removing the hook."""
    project = self.project
    old_hook = project._sim_procedures.get((self.func_address, None), None)
    
    try:
        # Remove hook temporarily
        project.unhook(self.func_address)
        
        # Create a new simulation state at the function address
        func_state = self.state.copy()
        func_state.ip = self.func_address
        
        # Create simulation manager with the new state
        simgr = project.factory.simulation_manager(func_state)
        
        # Step until function returns or max steps reached
        for _ in range(100):
            if not simgr.active:
                break
            simgr.step()
        
        # Get return value if available
        if simgr.active:
            return simgr.active[0].solver.eval(simgr.active[0].regs.rax)
        return 0
    finally:
        # Always restore the hook
        if old_hook:
            project.hook(self.func_address, old_hook)
```

This method:
- Temporarily removes the hook on the function
- Creates a new simulation state that jumps to the function
- Runs the simulation until the function returns or a limit is reached
- Captures the return value from the RAX register
- Restores the hook before returning

## Main Analysis Workflow

The main analysis workflow ties everything together:

```python
# Hook fgets to taint data
project.hook_symbol('fgets', FgetsTainter(verbose=verbose))

# Find main and _start functions
main_addr = project.loader.main_object.get_symbol("main").rebased_addr
start_addr = project.loader.main_object.get_symbol("_start").rebased_addr

# Build CFG for static analysis
cfg = project.analyses.CFGFast()

# Analyze functions for parameter count
# ... parameter count estimation code ...

# Hook user functions
for func_addr, func in project.kb.functions.items():
    # Skip external functions
    if func.is_plt or func.is_syscall:
        continue
    
    # Only hook functions in main binary
    if project.loader.find_object_containing(func_addr) is not project.loader.main_object:
        continue
    
    # Check if this is an essential function
    is_essential = (func_addr == main_addr or 
                   func_addr == start_addr or 
                   func.name in essential_functions or
                   func.name in input_functions)
    
    # Create a custom hook for this function
    class CustomFunctionHook(CheckTaintHook):
        pass
        
    hook_instance = CustomFunctionHook(
        func_address=func_addr,
        func_name=func.name,
        essential=is_essential,
        verbose=verbose
    )
    project.hook(func_addr, hook_instance)

# Create initial state and simulation manager
state = project.factory.entry_state(add_options={
    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
})

# Run the simulation
simgr = project.factory.simulation_manager(state)
for i in range(1, max_steps + 1):
    if not simgr.active:
        break
    simgr.step()
```

This workflow:
1. Hooks the `fgets` function to introduce tainted data
2. Identifies essential functions like `main` and `_start`
3. Builds a Control Flow Graph (CFG) for static analysis
4. Analyzes functions to estimate parameter counts
5. Hooks all functions in the main binary with taint-checking hooks
6. Creates an initial state and runs the simulation for a specified number of steps

## Command Line Interface

The tool provides a command-line interface for easy use:

```python
if __name__ == "__main__":
    import argparse
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Analyze binary using taint analysis')
    parser.add_argument('binary', help='Path to binary to analyze')
    parser.add_argument('--quiet', action='store_true', help='Reduce output verbosity')
    parser.add_argument('--max-steps', type=int, default=50, help='Maximum number of simulation steps')
    parser.add_argument('--param', action='append', nargs=2, metavar=('FUNCTION', 'COUNT'),
                        help='Override parameter count for a function, e.g. --param helper_function 1')
    parser.add_argument('--meta', metavar='FILE', help='Path to meta file with function prototypes')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    
    args = parser.parse_args()
    verbose = not args.quiet or args.debug
    
    # Process parameter overrides
    param_overrides = {}
    if args.param:
        for func_name, count in args.param:
            try:
                param_overrides[func_name] = int(count)
            except ValueError:
                print(f"Error: parameter count must be an integer: {count}")
                sys.exit(1)
    
    # Run analysis
    analyze(args.binary, 
            verbose=verbose, 
            max_steps=args.max_steps, 
            param_overrides=param_overrides,
            meta_file=args.meta)
```

Example usage:
```
python taint_analyzer.py my_binary --meta my_binary.meta --max-steps 100
```

This would:
- Analyze "my_binary" using the metadata in "my_binary.meta"
- Run for up to 100 simulation steps
- Display verbose output about tainted functions

In conclusion, the taint analyzer is a powerful tool that uses symbolic execution to identify and focus on code paths that process user input, potentially helping to identify security vulnerabilities more efficiently.
