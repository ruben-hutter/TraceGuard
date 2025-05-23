import angr
import claripy
import logging
import sys
import argparse
import os
from angr.exploration_techniques import DFS

# --- Import from your meta.py ---
try:
    from meta import parse_meta_file
except ImportError:
    my_logger_meta = logging.getLogger(__name__ + ".meta_parser")

    def parse_meta_file(meta_path, verbose=True):
        if not os.path.exists(meta_path):
            if verbose:
                my_logger_meta.warning(f"Meta file not found: {meta_path}")
            return {}
        function_params = {}
        try:
            with open(meta_path, "r") as f:
                contents = f.read()
            if verbose:
                my_logger_meta.info(f"Parsing meta file: {meta_path}")
            for line_num, line in enumerate(contents.splitlines(), 1):
                line = line.strip()
                if not line or line.startswith(("//", "#")):
                    continue
                if line.endswith(";"):
                    line = line[:-1].strip()
                if "(" in line and ")" in line:
                    try:
                        func_part = line.split("(", 1)[0].strip()
                        func_name = func_part.split()[-1].replace("*", "")
                        params_str = line.split("(", 1)[1].rsplit(")", 1)[0].strip()
                        param_count = (
                            0
                            if not params_str or params_str.lower() == "void"
                            else len(params_str.split(","))
                        )
                        function_params[func_name] = param_count
                        if verbose:
                            my_logger_meta.debug(
                                f"Meta info: {func_name} has {param_count} parameters"
                            )
                    except Exception as e:
                        if verbose:
                            my_logger_meta.error(
                                f"Error parsing line {line_num} in meta file '{meta_path}': {line} - {e}"
                            )
        except Exception as e:
            if verbose:
                my_logger_meta.error(f"Error reading meta file '{meta_path}': {e}")
        if verbose:
            my_logger_meta.info(
                f"Parsed {len(function_params)} functions from meta file: {meta_path}"
            )
        return function_params
# --- End of meta.py import/definition ---

# Configure logging for angr
logging.getLogger("angr").setLevel(logging.ERROR)

my_logger = logging.getLogger(__name__)
my_logger.setLevel(logging.INFO)
my_logger.propagate = False
console_handler = logging.StreamHandler(sys.stdout)
info_formatter = logging.Formatter("[%(levelname)s] - %(message)s")
dbg_formatter = logging.Formatter(
    "[%(levelname)s] - %(filename)s:%(lineno)d - %(message)s"
)
formatter = info_formatter if my_logger.level == logging.INFO else dbg_formatter
console_handler.setFormatter(formatter)
my_logger.addHandler(console_handler)

COMMON_LIBC_FUNCTIONS = {
    "printf",
    "scanf",
    "sprintf",
    "sscanf",
    "fprintf",
    "fscanf",
    "malloc",
    "free",
    "calloc",
    "realloc",
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "strcmp",
    "strncmp",
    "strlen",
    "strchr",
    "strrchr",
    "strstr",
    "strtok",
    "memcpy",
    "memmove",
    "memset",
    "memcmp",
    "fopen",
    "fclose",
    "fread",
    "fwrite",
    "fseek",
    "ftell",
    "rewind",
    "exit",
    "abort",
    "puts",
    "gets",
    "fgets",
    "fputs",
}

INPUT_FUNCTION_NAMES = {"fgets", "gets", "scanf", "read", "recv", "fread"}


def is_value_tainted(state, value, project_obj):
    if not hasattr(value, "symbolic") or not value.symbolic:
        return False

    if hasattr(value, "variables"):
        for var_name in value.variables:
            if var_name.startswith("taint_source_"):
                return True

    if not value.symbolic:
        try:
            addr = state.solver.eval_one(value)  # Ensure single solution
            for region_addr, region_size in project_obj.tainted_memory_regions.items():
                if region_addr <= addr < region_addr + region_size:
                    my_logger.debug(
                        f"Taint check: Value {addr:#x} points into known tainted region {region_addr:#x} (size {region_size})."
                    )
                    return True
        except angr.errors.SimSolverError:  # Can happen if value is symbolic but not directly named, or complex constraints
            my_logger.debug(
                f"SimSolverError while checking if value {value} points to tainted memory. Assuming not tainted for this check."
            )
        except Exception as e:
            my_logger.debug(
                f"Exception while checking if value {value} points to tainted memory: {e}. Assuming not tainted."
            )
    return False


def create_and_run_angr_project(config):
    binary_path = config["binary_path"]
    show_libc_prints = config.get("show_libc_prints", False)
    show_syscall_prints = config.get("show_syscall_prints", False)
    try:
        project = angr.Project(binary_path, auto_load_libs=False)
        my_logger.info(f"Successfully loaded binary: {binary_path}")
    except angr.errors.AngrFileNotFoundError:
        my_logger.error(f"Binary file not found at: {binary_path}")
        return
    except Exception as e:
        my_logger.error(f"Failed to load binary {binary_path}: {e}")
        return

    # Initialize taint tracking attributes
    project.tainted_functions = set()
    project.tainted_memory_regions = {}
    project.tainted_edges = set()
    project.hook_call_id_counter = 0  # Initialize hook call counter on project

    # --- Load Meta File ---
    project.meta_param_counts = {}

    # Auto-detect meta file based on binary_path
    binary_dir = os.path.dirname(
        os.path.abspath(binary_path)
    )  # Get absolute directory of binary
    binary_filename_base = os.path.splitext(os.path.basename(binary_path))[0]
    potential_meta_path = os.path.join(binary_dir, binary_filename_base + ".meta")

    actual_meta_file_path = None

    if os.path.exists(potential_meta_path):
        my_logger.info(f"Found auto-detected meta file: {potential_meta_path}")
        actual_meta_file_path = potential_meta_path
    else:
        my_logger.warning(
            f"Auto-detected meta file not found at: {potential_meta_path}. Continuing without meta file."
        )

    if actual_meta_file_path:
        my_logger.info(f"Attempting to parse meta file: {actual_meta_file_path}")
        project.meta_param_counts = parse_meta_file(
            actual_meta_file_path,
            verbose=(my_logger.getEffectiveLevel() <= logging.DEBUG),
        )
    # --- End Load Meta File ---

    project.arch_info = {}
    if project.arch.name == "AMD64":
        project.arch_info["argument_registers"] = [
            "rdi",
            "rsi",
            "rdx",
            "rcx",
            "r8",
            "r9",
        ]
        project.arch_info["return_register"] = "rax"
    # TODO: check old implementation to improve this
    elif project.arch.name == "X86":
        project.arch_info["argument_registers"] = [
            "eax",
            "ecx",
            "edx",
        ]  # Simplified, actual ABI is stack for cdecl
        project.arch_info["return_register"] = "eax"
    else:
        my_logger.warning(
            f"Architecture {project.arch.name} argument registers not fully configured for taint analysis."
        )
        project.arch_info["argument_registers"] = []
        project.arch_info["return_register"] = None

    my_logger.info("Attempting to build CFG to identify functions...")
    try:
        cfg = project.analyses.CFGFast()
        cfg.normalize()
        my_logger.info(
            f"CFG analysis complete. Functions found in kb: {len(project.kb.functions)}"
        )
    except Exception as e:
        my_logger.error(f"Failed to build CFG: {e}")
        my_logger.warning(
            "Proceeding without explicit CFG, function discovery might be limited."
        )

    func_info_map = {}
    if project.kb.functions:
        for func_addr, func_obj in project.kb.functions.items():
            func_info_map[func_addr] = {
                "name": func_obj.name,
                "is_plt": func_obj.is_plt,
                "is_syscall": func_obj.is_syscall,
                "is_simprocedure": func_obj.is_simprocedure,
            }

    if not func_info_map:
        my_logger.warning("No functions found in the binary's knowledge base.")

    main_symbol = project.loader.find_symbol("main")
    if not main_symbol:
        common_mains = ["main", "_main", "start", "_start"]
        for name in common_mains:
            main_symbol = project.loader.find_symbol(name)
            if main_symbol:
                my_logger.info(f"Found entry point '{name}' as main.")
                break

    if not main_symbol:
        my_logger.error(
            "No 'main' function or common alternatives found in the binary."
        )
        if project.entry:
            my_logger.info(
                f"Using project.entry {project.entry:#x} as a fallback entry point."
            )
            main_addr = project.entry
            main_func_details = func_info_map.get(main_addr)
            main_symbol_name = (
                main_func_details["name"]
                if main_func_details
                else f"sub_{main_addr:#x}"
            )
        else:
            my_logger.error("No entry point could be determined.")
            return
    else:
        main_addr = main_symbol.rebased_addr
        main_symbol_name = main_symbol.name

    try:
        initial_state = project.factory.entry_state(addr=main_addr)
    except Exception as e:
        my_logger.error(f"Failed to create initial state at {main_addr:#x}: {e}")
        return

    simgr = project.factory.simulation_manager(initial_state)
    simgr.use_technique(DFS())

    def input_function_hook(state):
        project.hook_call_id_counter += 1

        called_func_addr = state.addr
        func_details = func_info_map.get(called_func_addr)
        called_func_name = (
            func_details["name"] if func_details else f"sub_{called_func_addr:#x}"
        )

        project.tainted_functions.add(called_func_name)
        my_logger.info(
            f"TAINT_SOURCE: Input function {called_func_name} at {called_func_addr:#x} is introducing taint."
        )

        if called_func_name == "fgets" and project.arch.name == "AMD64":
            try:
                buf_ptr_val = state.regs.rdi
                size_val_sym = state.regs.rsi

                # Try to get a concrete size, but have a fallback
                try:
                    size_val = state.solver.eval_one(size_val_sym)
                except angr.errors.SimSolverError:
                    my_logger.warning(
                        f"Could not concretize size for {called_func_name}, using default 128."
                    )
                    size_val = 128  # Default size if symbolic

                buf_addr = state.solver.eval_one(buf_ptr_val)

                taint_size_bytes = min(size_val, 256)
                if taint_size_bytes <= 0:
                    my_logger.warning(
                        f"Invalid or zero size for taint from {called_func_name}: {size_val}"
                    )
                    return

                taint_id = (
                    f"taint_source_{called_func_name}_{project.hook_call_id_counter}"
                )
                symbolic_taint_data = claripy.BVS(taint_id, taint_size_bytes * 8)

                state.memory.store(
                    buf_addr, symbolic_taint_data, endness=project.arch.memory_endness
                )
                project.tainted_memory_regions[buf_addr] = taint_size_bytes
                my_logger.debug(
                    f"TAINTED: Memory at {buf_addr:#x} (size {taint_size_bytes} bytes) by {called_func_name} with BVS '{taint_id}'."
                )

            except angr.errors.SimSolverError as e:
                my_logger.error(
                    f"SimSolverError while tainting buffer for {called_func_name} (likely symbolic pointer/size): {e}"
                )
            except Exception as e:
                my_logger.error(f"Error tainting buffer for {called_func_name}: {e}")
        # Add more input functions here (e.g., read, recv) adapting argument registers and logic

    def generic_function_hook(state):
        project.hook_call_id_counter += 1

        called_func_addr = state.addr
        func_details = func_info_map.get(called_func_addr)
        called_func_name = (
            func_details["name"] if func_details else f"sub_{called_func_addr:#x}"
        )

        # Determine Caller
        caller_name = "N/A (e.g., initial entry or no prior frame)"
        caller_func_address_str = "N/A"
        if state.callstack:  # Check if callstack is not empty
            # The top of the callstack is the current function, so caller is callstack.func_addr if available,
            # or one level down if we want the calling *function* rather than return site.
            # Angr's callstack.func_addr refers to the *current* function's address.
            # To get the *caller's* function address, we look at callstack.call_site_addr (return address)
            # and then try to resolve the function containing that call site if needed, or use callstack_frames[1]
            callstack_frames = list(state.callstack)  # Make a copy to inspect
            if len(callstack_frames) > 0:  # Current frame is callstack_frames[0]
                # The actual caller function address is often best found one level down if available
                if len(callstack_frames) > 1:
                    caller_frame = callstack_frames[1]  # Caller's frame
                    caller_actual_addr_from_frame = caller_frame.func_addr
                    caller_func_address_str = f"0x{caller_actual_addr_from_frame:x}"
                    caller_info = func_info_map.get(caller_actual_addr_from_frame)
                    caller_name = (
                        caller_info["name"]
                        if caller_info
                        else f"sub_{caller_actual_addr_from_frame:#x}"
                    )
                elif (
                    state.callstack.current_function_address != main_addr
                ):  # If it's not main but no deeper callstack
                    # This might be a call from an uninstrumented part or complex scenario
                    caller_name = f"N/A (shallow stack, current: {called_func_name})"

        # Taint Checking Logic
        arguments_are_tainted = False
        arch_arg_regs = project.arch_info.get("argument_registers", [])

        # --- Determine number of arguments to check ---
        num_args_to_check_from_meta = -1  # Flag to indicate not found in meta
        if (
            hasattr(project, "meta_param_counts")
            and called_func_name in project.meta_param_counts
        ):
            num_args_to_check_from_meta = project.meta_param_counts[called_func_name]
            # Ensure we don't check more registers than available for the arch for register arguments
            num_args_to_check = min(num_args_to_check_from_meta, len(arch_arg_regs))
            my_logger.debug(
                f"Meta for {called_func_name}: {num_args_to_check_from_meta} params. Will check {num_args_to_check} registers."
            )
        else:
            # Default: check all configured registers if no meta info
            num_args_to_check = len(arch_arg_regs)
            my_logger.debug(
                f"No meta param count for {called_func_name}, defaulting to check {num_args_to_check} registers."
            )
        # --- End Determine number of arguments ---

        if arch_arg_regs and num_args_to_check > 0:
            for i in range(num_args_to_check):
                try:
                    arg_reg_name = arch_arg_regs[i]
                    arg_value = getattr(state.regs, arg_reg_name)
                    if is_value_tainted(state, arg_value, project):
                        arguments_are_tainted = True
                        my_logger.info(
                            f"TAINT_ARG: Function {called_func_name} (at {state.addr:#x}) called with tainted argument in register {arg_reg_name}."
                        )
                        break
                    if not arg_value.symbolic:
                        try:
                            ptr_addr = state.solver.eval_one(arg_value)
                            if ptr_addr in project.tainted_memory_regions:
                                arguments_are_tainted = True
                                my_logger.info(
                                    f"TAINT_ARG_PTR: Function {called_func_name} called with {arg_reg_name} pointing to base of tainted region {ptr_addr:#x}."
                                )
                                break
                            mem_val_check = state.memory.load(
                                ptr_addr, 1, inspect=False
                            )
                            if is_value_tainted(state, mem_val_check, project):
                                arguments_are_tainted = True
                                my_logger.info(
                                    f"TAINT_ARG_PTR: Function {called_func_name} called with {arg_reg_name} (value {ptr_addr:#x}) pointing to tainted data."
                                )
                                break
                        except (
                            angr.errors.SimMemoryError,
                            angr.errors.SimSegfaultException,
                        ):
                            pass
                        except angr.errors.SimSolverError:
                            my_logger.debug(
                                f"Solver error evaluating arg {arg_reg_name} for {called_func_name} as pointer."
                            )
                except AttributeError:
                    my_logger.warning(
                        f"Register {arch_arg_regs[i]} not found for arch {project.arch.name} checking args for {called_func_name}."
                    )
                except Exception as e:
                    my_logger.error(
                        f"Error checking argument {arch_arg_regs[i]} for {called_func_name}: {e}"
                    )

        taint_status_msg = ""
        if arguments_are_tainted:
            project.tainted_functions.add(called_func_name)
            taint_status_msg = " [RECEIVES_TAINT]"
            if (
                caller_name != "N/A (e.g., initial entry or no prior frame)"
                and caller_name != f"N/A (shallow stack, current: {called_func_name})"
            ):
                project.tainted_edges.add((caller_name, called_func_name))
                my_logger.debug(
                    f"TAINT_EDGE: Added tainted edge from {caller_name} to {called_func_name}"
                )
        elif called_func_name in project.tainted_functions:
            taint_status_msg = " [WAS_TAINTED]"

        # Printing Logic
        do_print = True
        if func_details:
            is_libc = (
                func_details["is_plt"] or called_func_name in COMMON_LIBC_FUNCTIONS
            )
            is_syscall_flag = func_details["is_syscall"]
            if (is_libc and not show_libc_prints) or (
                is_syscall_flag and not show_syscall_prints
            ):
                do_print = False

        if do_print:
            num_active_paths_total = len(simgr.active) if simgr else 0
            my_logger.debug(
                f"HOOK #{project.hook_call_id_counter:03d} :: CALLED: {called_func_name}{taint_status_msg} (at 0x{called_func_addr:x}) :: FROM: {caller_name} (at {caller_func_address_str}) :: StateID: {id(state):#x} :: ActivePaths: {num_active_paths_total}"
            )

    my_logger.info("Hooking functions with taint analysis logic...")
    hooked_count = 0
    for func_addr_hook, func_obj_details_hook in func_info_map.items():
        # Skip SimProcedures unless they are specifically handled input sources
        current_func_name = func_obj_details_hook["name"]
        if (
            func_obj_details_hook["is_simprocedure"]
            and current_func_name not in INPUT_FUNCTION_NAMES
        ):
            my_logger.debug(
                f"Skipping hook for non-input SimProcedure: {current_func_name}"
            )
            continue

        hook_to_use = generic_function_hook
        if current_func_name in INPUT_FUNCTION_NAMES:
            hook_to_use = input_function_hook
            my_logger.info(
                f"Assigning INPUT_FUNCTION_HOOK to {current_func_name} at {func_addr_hook:#x}"
            )

        try:
            project.hook(func_addr_hook, hook_to_use, length=0)
            hooked_count += 1
        except Exception as e:
            my_logger.warning(
                f"Could not hook {current_func_name} at {func_addr_hook:#x}: {e}"
            )

    my_logger.info(f"Hooked {hooked_count} functions for taint analysis.")

    my_logger.info(
        f"Starting symbolic execution from '{main_symbol_name}' at {main_addr:#x}"
    )
    my_logger.info(
        f"Starting simulation with {len(simgr.active)} initial state(s). Using DFS."
    )

    try:
        simgr.run()  # Changed from explore() to run() for typical DFS usage until completion
    except (
        angr.errors.AngrTracerError
    ) as e:  # Should be less common with DFS and no tracing
        my_logger.warning(
            f"AngrTracerError during simulation: {e}. Results may be partial."
        )
    except Exception as e:
        my_logger.error(f"Unexpected error during simulation: {e}")
        import traceback

        traceback.print_exc()

    my_logger.info("Simulation complete.")
    if simgr.deadended:
        my_logger.info(f"{len(simgr.deadended)} states reached a dead end.")
    if simgr.active:  # Should be empty if DFS ran to completion
        my_logger.info(
            f"{len(simgr.active)} states are still active (DFS might have been limited or interrupted)."
        )
    if simgr.errored:
        my_logger.info(f"{len(simgr.errored)} states encountered errors.")
        for i, error_record in enumerate(simgr.errored):
            my_logger.error(
                f"Error {i + 1}: State at {error_record.state.addr:#x} failed with: {error_record.error}"
            )

    if project.tainted_edges:
        my_logger.info("\nTainted call edges (propagation of taint to arguments):")
        for caller, callee in sorted(list(project.tainted_edges)):
            print(f"  {caller} -> {callee}")
    else:
        my_logger.info("\nNo tainted call edges were recorded.")

    my_logger.info("\nFunctions that processed/received tainted data:")
    if project.tainted_functions:
        for func_name in sorted(list(project.tainted_functions)):
            print(f"  - {func_name}")
    else:
        my_logger.info(
            "No functions were identified as processing or receiving tainted data."
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run angr symbolic execution with function call hooking and taint analysis."
    )
    parser.add_argument("binary_path", help="Path to the binary to analyze.")
    parser.add_argument(
        "--show-libc-prints",
        action="store_true",
        help="Show hook prints for common libc functions (default: hidden).",
    )
    parser.add_argument(
        "--show-syscall-prints",
        action="store_true",
        help="Show hook prints for syscalls (default: hidden).",
    )

    args = parser.parse_args()

    if not args.binary_path:
        my_logger.error(
            f"Usage: python {sys.argv[0]} <path_to_binary> [--show-libc-prints] [--show-syscall-prints]"
        )
        sys.exit(1)

    create_and_run_angr_project(vars(args))
