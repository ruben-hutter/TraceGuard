#!/usr/bin/env python3
"""
Simple taint analyzer that uses SimProcedures to implement function skipping.
Functions like _start, main, and input functions are always executed.
"""
from angr.exploration_techniques import LengthLimiter, LoopSeer
import angr
import claripy
import os
import sys

def parse_meta_file(meta_path, verbose=True):
    """Parse a meta file with function prototypes to get parameter counts."""
    if not os.path.exists(meta_path):
        if verbose:
            print(f"Meta file not found: {meta_path}")
        return {}
        
    function_params = {}
    
    try:
        with open(meta_path, 'r') as f:
            contents = f.read()
            if verbose:
                print(f"Parsing meta file: {meta_path}")
                print(f"Meta file contents ({len(contents)} bytes):")
                print("---")
                print(contents)
                print("---")
                
            for line_num, line in enumerate(contents.splitlines(), 1):
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith(('//','#')):
                    continue
                    
                # Remove trailing semicolon
                if line.endswith(';'):
                    line = line[:-1].strip()
                    
                # Parse function prototype
                if '(' in line and ')' in line:
                    try:
                        # Extract function name
                        func_part = line.split('(')[0].strip()
                        func_name = func_part.split()[-1]
                        
                        # Extract and count parameters
                        params_str = line.split('(')[1].split(')')[0].strip()
                        param_count = 0 if not params_str or params_str.lower() == 'void' else len(params_str.split(','))
                            
                        # Store result
                        function_params[func_name] = param_count
                        
                        if verbose:
                            print(f"Meta info: {func_name} has {param_count} parameters")
                    except Exception as e:
                        if verbose:
                            print(f"Error parsing line {line_num}: {line} - {e}")
    except Exception as e:
        if verbose:
            print(f"Error parsing meta file: {e}")
            
    if verbose:
        print(f"Parsed {len(function_params)} functions from meta file")
            
    return function_params

class FgetsTainter(angr.SimProcedure):
    """SimProcedure for tainting input from fgets."""
    def __init__(self, verbose=True, **kwargs):
        super().__init__(**kwargs)
        self.verbose = verbose
        
    def run(self, buf, size, fp):
        """Create tainted buffer with 'stdin' in variable name."""
        # Create symbolic buffer and store in memory
        sym_buf = claripy.BVS("stdin_data", 8 * 100)
        self.state.memory.store(buf, sym_buf)
        self.state.memory.store(buf + 99, claripy.BVV(0, 8))  # Null terminator
        
        if self.verbose:
            print("Added tainted data")
        
        return buf

class CheckTaintHook(angr.SimProcedure):
    """Check function parameters for taint and skip untainted functions."""
    def __init__(self, func_address=None, func_name=None, essential=False, verbose=True, **kwargs):
        super().__init__(**kwargs)
        self.func_address = func_address
        self.func_name = func_name
        self.essential = essential
        self.verbose = verbose
        
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
        if self.verbose:
            print(f"Function {self.func_name} has {param_count} parameters")
            
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
    
    def _check_parameters(self, param_count):
        """Check function parameters for taint."""
        # Get calling convention registers
        cc = self.project.factory.cc()
        param_registers = getattr(cc, 'ARG_REGS', ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'])
        
        if self.verbose:
            print(f"Checking registers for function {self.func_name}: {param_registers[:param_count]}")
        
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
                
        # Check stack parameters if necessary
        if param_count > len(param_registers):
            try:
                stack_pointer = self.state.regs.rsp
                
                for i in range(len(param_registers), param_count):
                    stack_offset = (i - len(param_registers) + 1) * 8
                    try:
                        param_addr = stack_pointer + stack_offset
                        param_val = self.state.memory.load(param_addr, 8)
                        
                        if self._is_tainted(param_val):
                            return True, f"stack+{stack_offset}"
                            
                        if not param_val.symbolic and param_val.concrete:
                            try:
                                ptr_val = self.state.solver.eval(param_val)
                                mem_data = self.state.memory.load(ptr_val, 8)
                                if self._is_tainted(mem_data):
                                    return True, f"*(stack+{stack_offset})"
                            except:
                                pass
                    except:
                        pass
            except:
                pass
                
        return False, None
        
    def _execute_original_function(self):
        """Execute the original function by temporarily removing the hook."""
        project = self.project
        old_hook = project._sim_procedures.get((self.func_address, None), None)
        
        try:
            # Remove hook temporarily
            project.unhook(self.func_address)
            
            # Get current register values to pass to the call state
            regs = {}
            for reg_name in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
                try:
                    regs[reg_name] = getattr(self.state.regs, reg_name)
                except:
                    pass
            
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
        except Exception as e:
            if self.verbose:
                print(f"Error executing original function: {e}")
            return 0
        finally:
            # Always restore the hook
            if old_hook:
                project.hook(self.func_address, old_hook)
                
    def _is_tainted(self, value):
        """Check if value contains tainted data."""
        if not hasattr(value, 'symbolic') or not value.symbolic:
            return False
            
        # Check variable names for 'stdin'
        if hasattr(value, 'variables'):
            return any('stdin' in var for var in value.variables)
                
        return False

def analyze(binary_path, verbose=True, max_steps=50, param_overrides=None, meta_file=None):
    """Analyze the binary, skipping functions with untainted parameters."""
    param_overrides = param_overrides or {}
    
    # Try to find meta file automatically if none provided
    if meta_file is None:
        base_name = os.path.splitext(binary_path)[0]
        potential_meta = f"{base_name}.meta"
        
        if os.path.exists(potential_meta):
            meta_file = potential_meta
            if verbose:
                print(f"Found meta file: {meta_file}")
            
    # Parse meta file if it exists
    if meta_file and os.path.exists(meta_file):
        meta_params = parse_meta_file(meta_file, verbose)
        
        # Add meta params to overrides (don't overwrite existing overrides)
        for func_name, param_count in meta_params.items():
            if func_name not in param_overrides:
                param_overrides[func_name] = param_count
                if verbose:
                    print(f"Using meta file parameter count for {func_name}: {param_count}")
    
    print(f"Analyzing {binary_path}")
    
    # Load the binary
    project = angr.Project(binary_path, auto_load_libs=False)
    
    # Initialize statistics counters
    project._executed_count = 0
    project._skipped_count = 0
    
    # Define lists of essential functions
    essential_functions = ['_start', 'main', 'fgets']
    input_functions = ['fgets', 'gets', 'read', 'scanf']
    
    # Hook fgets to taint data
    try:
        project.hook_symbol('fgets', FgetsTainter(verbose=verbose))
        if verbose:
            print("Hooked fgets")
    except Exception as e:
        print(f"Could not hook fgets: {e}")
    
    # Find main and _start functions
    try:
        main_addr = project.loader.main_object.get_symbol("main").rebased_addr
        if verbose:
            print(f"Found main at {hex(main_addr)}")
    except:
        main_addr = None
        print("Could not find main function")
    
    try:
        start_addr = project.loader.main_object.get_symbol("_start").rebased_addr
        if verbose:
            print(f"Found _start at {hex(start_addr)}")
    except:
        start_addr = None
        print("Could not find _start function")
        
    # Build CFG
    if verbose:
        print("Building CFG...")
    cfg = project.analyses.CFGFast()
    
    # Analyze functions for parameter count
    if verbose:
        print("Analyzing functions for parameter count...")
    
    # Create storage for parameter counts and overrides
    project._param_counts = {}
    project._param_overrides = param_overrides
    
    # Estimate parameter counts for functions
    for func in project.kb.functions.values():
        # Skip external functions
        if func.is_plt or func.is_syscall:
            continue
            
        # Default to 6 parameters (x86_64 uses 6 registers)
        max_observed_args = 0
        
        # Check function's caller instructions for parameter setup
        try:
            for caller_func in cfg.functions.values():
                if caller_func.addr == func.addr:
                    continue
                    
                for block in caller_func.blocks:
                    for insn in block.capstone.insns:
                        if insn.mnemonic == "call" and hasattr(insn, 'operands') and len(insn.operands) > 0:
                            try:
                                target = insn.operands[0].imm
                                if target == func.addr:
                                    # Count parameter registers set before this call
                                    param_setup_count = 0
                                    for setup_insn in block.capstone.insns:
                                        if setup_insn.address == insn.address:
                                            break
                                            
                                        setup_str = setup_insn.mnemonic + " " + setup_insn.op_str
                                        for i, reg in enumerate(['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']):
                                            if reg in setup_str and any(op in setup_str for op in ["mov", "lea", "xor"]):
                                                param_setup_count = max(param_setup_count, i + 1)
                                    
                                    max_observed_args = max(max_observed_args, param_setup_count)
                            except Exception:
                                pass
        except Exception:
            pass
        
        # Use function's first blocks for register usage detection
        try:
            func_blocks = list(func.blocks)
            for block_idx in range(min(2, len(func_blocks))):
                block = func_blocks[block_idx]
                arg_access_count = 0
                
                for insn in block.capstone.insns:
                    insn_str = insn.mnemonic + " " + insn.op_str
                    
                    # Skip prologue instructions
                    if any(x in insn_str for x in ["push rbp", "mov rbp, rsp", "sub rsp"]):
                        continue
                        
                    # Count parameter register accesses
                    for i, reg in enumerate(['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']):
                        if reg in insn_str and not insn_str.startswith(("push", "pop")):
                            arg_access_count = max(arg_access_count, i + 1)
                
                max_observed_args = max(max_observed_args, arg_access_count)
                if arg_access_count > 0:
                    break
        except Exception:
            pass
                
        # If we found evidence of parameters, use that count
        if max_observed_args > 0:
            project._param_counts[func.addr] = max_observed_args
            if verbose and func.name not in ["_start", "main"]:
                print(f"Estimated {func.name} to have {max_observed_args} parameters")
    
    # Hook user functions
    if verbose:
        print("Hooking program functions...")
    hook_count = 0
    
    for func_addr, func in project.kb.functions.items():
        # Skip external functions and those not in main binary
        if (func.is_plt or func.is_syscall or 
            project.loader.find_object_containing(func_addr) is not project.loader.main_object):
            continue
        
        # Check if this is an essential function
        is_essential = (func_addr == main_addr or 
                       func_addr == start_addr or 
                       func.name in essential_functions or
                       func.name in input_functions)
            
        # Create a custom class for this specific function to avoid sharing state
        class CustomFunctionHook(CheckTaintHook):
            pass
            
        # Create hook for this function
        hook_instance = CustomFunctionHook(
            func_address=func_addr,
            func_name=func.name,
            essential=is_essential,
            verbose=verbose
        )
        project.hook(func_addr, hook_instance)
        
        if verbose:
            marker = "(essential)" if is_essential else ""
            print(f"Hooked {func.name} at {hex(func_addr)} {marker}")
        hook_count += 1
        
    if verbose:    
        print(f"Hooked {hook_count} functions")
    
    # Create initial state and simulation manager
    state = project.factory.entry_state(add_options={
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
    })
    
    print("\nStarting symbolic execution...")
    simgr = project.factory.simulation_manager(state)

    # Plug in limiting techniques
    simgr.use_technique(LengthLimiter(max_length=100))
    simgr.use_technique(LoopSeer(bound=3))
    
    # Run for a limited number of steps
    for i in range(1, max_steps + 1):
        if not simgr.active:
            print("No active states remaining.")
            break
            
        if verbose:
            print(f"\nStep {i}")
        simgr.step()
        
    print("\nExecution summary:")
    print(f"- Analyzed {hook_count} functions")
    print(f"- Executed {project._executed_count} functions (including essential functions)")
    print(f"- Skipped {project._skipped_count} functions (untainted parameters)")
    
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
                if verbose:
                    print(f"Parameter override: {func_name} has {count} parameters")
            except ValueError:
                print(f"Error: parameter count must be an integer: {count}")
                sys.exit(1)
    
    # Run analysis
    analyze(args.binary, 
            verbose=verbose, 
            max_steps=args.max_steps, 
            param_overrides=param_overrides,
            meta_file=args.meta)
