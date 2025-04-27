import os
import angr
from angr.exploration_techniques import LengthLimiter, LoopSeer

from meta import parse_meta_file
from taint import CheckTaintHook, FgetsTainter


def _process_meta_file(binary_path, meta_file, verbose):
    """Handle meta file parsing."""

    param_overrides = {}
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
                    print(
                        f"Using meta file parameter count for {func_name}: {param_count}"
                    )
    return param_overrides


def _setup_angr_project(binary_path):
    """Set up the Angr project and initial configurations."""

    print(f"Analyzing {binary_path}")

    # Load the binary
    project = angr.Project(binary_path, auto_load_libs=False)

    # Initialize statistics counters
    project._executed_count = 0
    project._skipped_count = 0

    # Create storage for parameter counts and overrides
    project._param_counts = {}
    return project


def _hook_input_functions(project, verbose):
    """Hook input functions to taint data."""

    # Hook fgets to taint data
    try:
        project.hook_symbol("fgets", FgetsTainter(verbose=verbose))
        if verbose:
            print("Hooked fgets")
    except Exception as e:
        print(f"Could not hook fgets: {e}")


def _find_essential_functions(project, verbose):
    """Find main and _start functions."""

    essential_functions = ["_start", "main", "fgets"]
    input_functions = ["fgets", "gets", "read", "scanf"]
    main_addr = None
    start_addr = None

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

    return main_addr, start_addr, essential_functions, input_functions


def _analyze_function_params(project, cfg, param_overrides, verbose):
    """Analyze functions to estimate parameter counts."""

    if verbose:
        print("Analyzing functions for parameter count...")

    project._param_overrides = param_overrides

    # Estimate parameter counts for functions
    for func in project.kb.functions.values():
        # Skip external functions
        if func.is_plt or func.is_syscall:
            continue

        # Skip functions already overridden by meta file
        if func.name in project._param_overrides:
            if verbose:
                print(
                    f"Using parameter override for {func.name}: {project._param_overrides[func.name]}"
                )
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
                        if (
                            insn.mnemonic == "call"
                            and hasattr(insn, "operands")
                            and len(insn.operands) > 0
                        ):
                            try:
                                target = insn.operands[0].imm
                                if target == func.addr:
                                    # Count parameter registers set before this call
                                    param_setup_count = 0
                                    for setup_insn in block.capstone.insns:
                                        if setup_insn.address == insn.address:
                                            break

                                        setup_str = (
                                            setup_insn.mnemonic
                                            + " "
                                            + setup_insn.op_str
                                        )
                                        for i, reg in enumerate(
                                            ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
                                        ):
                                            if reg in setup_str and any(
                                                op in setup_str
                                                for op in ["mov", "lea", "xor"]
                                            ):
                                                param_setup_count = max(
                                                    param_setup_count, i + 1
                                                )

                                    max_observed_args = max(
                                        max_observed_args, param_setup_count
                                    )
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
                    if any(
                        x in insn_str for x in ["push rbp", "mov rbp, rsp", "sub rsp"]
                    ):
                        continue

                    # Count parameter register accesses
                    for i, reg in enumerate(["rdi", "rsi", "rdx", "rcx", "r8", "r9"]):
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


def _hook_user_functions(
    project,
    cfg,
    main_addr,
    start_addr,
    essential_functions,
    input_functions,
    verbose,
):
    """Hook user-defined functions for taint analysis."""

    if verbose:
        print("Hooking program functions...")
    hook_count = 0

    for func_addr, func in project.kb.functions.items():
        # Skip external functions and those not in main binary
        if (
            func.is_plt
            or func.is_syscall
            or project.loader.find_object_containing(func_addr)
            is not project.loader.main_object
        ):
            continue

        # Check if this is an essential function
        is_essential = (
            func_addr == main_addr
            or func_addr == start_addr
            or func.name in essential_functions
            or func.name in input_functions
        )

        # Create a custom class for this specific function to avoid sharing state
        class CustomFunctionHook(CheckTaintHook):
            pass

        # Create hook for this function
        hook_instance = CustomFunctionHook(
            func_address=func_addr,
            func_name=func.name,
            essential=is_essential,
            verbose=verbose,
        )
        project.hook(func_addr, hook_instance)

        if verbose:
            marker = "(essential)" if is_essential else ""
            print(f"Hooked {func.name} at {hex(func_addr)} {marker}")
        hook_count += 1

    if verbose:
        print(f"Hooked {hook_count} functions")
    return hook_count


def _run_symbolic_execution(project, hook_count, max_steps, verbose):
    """Run symbolic execution of the binary."""

    # Create initial state and simulation manager
    state = project.factory.entry_state(
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

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
    print(
        f"- Executed {project._executed_count} functions (including essential functions)"
    )
    print(f"- Skipped {project._skipped_count} functions (untainted parameters)")


def analyze(
    binary_path, verbose=True, max_steps=50, param_overrides=None, meta_file=None
):
    """Analyze the binary, skipping functions with untainted parameters."""

    param_overrides = _process_meta_file(binary_path, meta_file, verbose)
    project = _setup_angr_project(binary_path)
    _hook_input_functions(project, verbose)
    main_addr, start_addr, essential_functions, input_functions = _find_essential_functions(
        project, verbose
    )
    cfg = project.analyses.CFGFast()
    _analyze_function_params(project, cfg, param_overrides, verbose)
    hook_count = _hook_user_functions(
        project,
        cfg,
        main_addr,
        start_addr,
        essential_functions,
        input_functions,
        verbose,
    )
    _run_symbolic_execution(project, hook_count, max_steps, verbose)
