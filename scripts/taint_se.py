import argparse
import logging
import sys
from pathlib import Path

import angr
import claripy
import networkx as nx
from angr.exploration_techniques import DFS
from meta import parse_meta_file
from schnauzer import VisualizationClient

# Logging configuration
logging.getLogger("angr").setLevel(logging.ERROR)

my_logger = logging.getLogger(__name__)
my_logger.setLevel(logging.INFO)
my_logger.propagate = False
console_handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("[%(levelname)s] - %(message)s")
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
    """
    Check if a value is tainted by looking for symbolic variables or
    checking if it points to a known tainted memory region.

    Args:
        state (angr.SimState): The current symbolic state.
        value (angr.SimValue): The value to check for taint.
        project_obj (angr.Project): The angr project object containing taint info.

    Returns:
        bool: True if the value is tainted, False otherwise.
    """
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


def generate_and_visualize_graph(project, func_info_map):
    """
    Builds a call graph and sends it to the Schnauzer client for visualization.
    Tainted nodes and edges are colored red, others are blue.
    """
    my_logger.info("Generating call graph for visualization...")
    G = nx.DiGraph()

    # 1. Define the color map for Schnauzer
    type_color_map = {
        'Tainted': '#FF0000',   # Red
        'Normal': '#0000FF',    # Blue
    }

    # 2. Add all functions found in the binary as nodes
    for func_addr, func_details in func_info_map.items():
        func_name = func_details['name']
        # Determine if the node is tainted and assign its type
        node_type = 'Tainted' if func_name in project.tainted_functions else 'Normal'
        G.add_node(func_name, type=node_type, address=f"{func_addr:#x}")

    # 3. Add all function calls as edges
    # We use the project's knowledge base callgraph for this
    if hasattr(project.kb, 'callgraph'):
        for caller_addr, callee_addr in project.kb.callgraph.edges():
            caller_name = func_info_map.get(caller_addr, {}).get('name')
            callee_name = func_info_map.get(callee_addr, {}).get('name')

            # Ensure we have names for both caller and callee
            if caller_name and callee_name:
                # Determine if the edge is tainted and assign its type
                edge_type = 'Tainted' if (caller_name, callee_name) in project.tainted_edges else 'Normal'
                G.add_edge(caller_name, callee_name, type=edge_type)

    # 4. Send the completed graph to the visualization client
    my_logger.info("Sending graph to Schnauzer visualization client...")
    try:
        viz_client = VisualizationClient()
        viz_client.send_graph(G, 'Taint Analysis Call Graph', type_color_map=type_color_map)
        my_logger.info("Graph successfully sent.")
    except Exception as e:
        my_logger.error(f"Failed to send graph to visualization client: {e}")


def create_and_run_angr_project(args):
    """
    Create and run an angr project with function call hooking and taint analysis.

    Args:
        args (dict): Dictionary containing the arguments for the project.
    """
    binary_path = Path(args["binary_path"]).resolve()

    show_libc_prints = args.get("show_libc_prints", False)
    show_syscall_prints = args.get("show_syscall_prints", False)
    verbose = args.get("verbose", False)
    debug = args.get("debug", False)

    if verbose or debug:
        my_logger.setLevel(logging.DEBUG)
    if debug:
        formatter = logging.Formatter(
            "[%(levelname)s] - %(filename)s:%(lineno)d - %(message)s"
        )
        console_handler.setFormatter(formatter)

    if args.get("meta_file"):
        # Use provided meta file path
        meta_file_path = Path(args["meta_file"]).resolve()
        my_logger.info(f"Using meta file: {meta_file_path}")
    else:
        # Auto-detect meta file path based on binary name
        meta_file_path = binary_path.with_suffix(".meta")
        my_logger.info(f"Auto-detected meta file path: {meta_file_path}")

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

    # Load Meta File
    project.meta_param_counts = {}

    if meta_file_path.exists():
        my_logger.info(f"Found meta file: {meta_file_path}")
        parse_meta_file(meta_file_path, my_logger)
    else:
        my_logger.warning(f"Meta file not found: {meta_file_path}")

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

    # Build CFG and func_info_map
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

    func_info_map = {addr: { "name": f.name, "is_plt": f.is_plt, "is_syscall": f.is_syscall, "is_simprocedure": f.is_simprocedure }
                     for addr, f in project.kb.functions.items() if f.name}

    if not func_info_map:
        my_logger.warning("No functions found in the binary's knowledge base.")

    main_symbol = project.loader.find_symbol("main")
    if main_symbol:
        my_logger.debug(f"Found main function symbol: {main_symbol.name} at {main_symbol.rebased_addr:#x}")
        main_addr = main_symbol.rebased_addr
        # Update func_info_map to ensure 'main' is correctly named if it was initially sub_0x...
        if main_addr in func_info_map:
            my_logger.info(f"Correcting main function name from {func_info_map[main_addr]['name']} to {main_symbol.name}")
            func_info_map[main_addr]['name'] = main_symbol.name
            # Also update project.kb.functions if necessary, though func_info_map is primary here
            if project.kb.functions.contains_addr(main_addr):
                 project.kb.functions[main_addr].name = main_symbol.name
    else:
        # Fallback if main not found
        if project.entry is None:
            my_logger.error("No entry point could be determined.")
            return
        my_logger.warning("Main function symbol not found, using entry point as main.")
        main_addr = project.entry

    main_symbol_name = func_info_map.get(main_addr, {}).get("name", f"sub_{main_addr:#x}")
    my_logger.debug(f"Main function address: {main_addr:#x}, name: {main_symbol_name}")

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

        called_addr = state.addr
        func_details = func_info_map.get(called_addr)
        called_name = (
            func_details["name"] if func_details else f"sub_{called_addr:#x}"
        )

        # Determine Caller
        caller_name = "N/A (e.g., initial entry or no prior frame)"
        caller_func_address_str = "N/A"
        if state.callstack:
            callstack_frames = list(state.callstack)
            if len(callstack_frames) > 1:
                caller_frame = callstack_frames[1]
                caller_addr = caller_frame.func_addr
                caller_info = func_info_map.get(caller_addr)
                caller_name = (
                    caller_info["name"]
                    if caller_info
                    else f"sub_{caller_addr:#x}"
                )
            elif (
                state.callstack.current_function_address == main_addr
            ):
                caller_name = func_info_map[main_addr]["name"]
                caller_func_address_str = f"{main_addr:#x} (main)"
            else:
                caller_name = f"N/A (shallow stack, current: {called_name})"

        # Taint Checking Logic
        arguments_are_tainted = False
        arch_arg_regs = project.arch_info.get("argument_registers", [])

        # TODO: Check this
        # --- Determine number of arguments to check ---
        num_args_to_check_from_meta = -1  # Flag to indicate not found in meta
        if (
            hasattr(project, "meta_param_counts")
            and called_name in project.meta_param_counts
        ):
            num_args_to_check_from_meta = project.meta_param_counts[called_name]
            # Ensure we don't check more registers than available for the arch for register arguments
            num_args_to_check = min(num_args_to_check_from_meta, len(arch_arg_regs))
            my_logger.debug(
                f"Meta for {called_name}: {num_args_to_check_from_meta} params. Will check {num_args_to_check} registers."
            )
        else:
            # Default: check all configured registers if no meta info
            num_args_to_check = len(arch_arg_regs)
            my_logger.debug(
                f"No meta param count for {called_name}, defaulting to check {num_args_to_check} registers."
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
                            f"TAINT_ARG: Function {called_name} (at {state.addr:#x}) called with tainted argument in register {arg_reg_name}."
                        )
                        break
                    if not arg_value.symbolic:
                        try:
                            ptr_addr = state.solver.eval_one(arg_value)
                            if ptr_addr in project.tainted_memory_regions:
                                arguments_are_tainted = True
                                my_logger.info(
                                    f"TAINT_ARG_PTR: Function {called_name} called with {arg_reg_name} pointing to base of tainted region {ptr_addr:#x}."
                                )
                                break
                            mem_val_check = state.memory.load(
                                ptr_addr, 1, inspect=False
                            )
                            if is_value_tainted(state, mem_val_check, project):
                                arguments_are_tainted = True
                                my_logger.info(
                                    f"TAINT_ARG_PTR: Function {called_name} called with {arg_reg_name} (value {ptr_addr:#x}) pointing to tainted data."
                                )
                                break
                        except (
                            angr.errors.SimMemoryError,
                            angr.errors.SimSegfaultException,
                        ):
                            pass
                        except angr.errors.SimSolverError:
                            my_logger.debug(
                                f"Solver error evaluating arg {arg_reg_name} for {called_name} as pointer."
                            )
                except AttributeError:
                    my_logger.warning(
                        f"Register {arch_arg_regs[i]} not found for arch {project.arch.name} checking args for {called_name}."
                    )
                except Exception as e:
                    my_logger.error(
                        f"Error checking argument {arch_arg_regs[i]} for {called_name}: {e}"
                    )

        taint_status_msg = " [TAINTED]" if arguments_are_tainted else ""
        if arguments_are_tainted:
            project.tainted_functions.add(called_name)
            if not caller_name.startswith("N/A"):
                project.tainted_edges.add((caller_name, called_name))

        # Printing Logic
        do_print = True
        if func_details:
            is_libc = (
                func_details["is_plt"] or called_name in COMMON_LIBC_FUNCTIONS
            )
            is_syscall_flag = func_details["is_syscall"]
            if (is_libc and not show_libc_prints) or (
                is_syscall_flag and not show_syscall_prints
            ):
                do_print = False

        if do_print:
            num_active_paths_total = len(simgr.active) if simgr else 0
            my_logger.debug(
                f"HOOK #{project.hook_call_id_counter:03d} :: CALLED: {called_name}{taint_status_msg} (at 0x{called_addr:x}) :: FROM: {caller_name} (at {caller_func_address_str}) :: StateID: {id(state):#x} :: ActivePaths: {num_active_paths_total}"
            )

    my_logger.info("Hooking functions with taint analysis logic...")
    # TODO: Check this count. Where it is increased. Double increase input and generic hooks?
    hooked_count = 0
    for func_addr, func_details in func_info_map.items():
        hook = input_function_hook if func_details["name"] in INPUT_FUNCTION_NAMES else generic_function_hook

        try:
            project.hook(func_addr, hook, length=0)
            hooked_count += 1
        except Exception as e:
            my_logger.warning(
                    f"Could not hook {func_details['name']} at {func_addr:#x}: {e}"
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
            # TODO: Problem of angr... just ignore
            my_logger.error(
                f"Error {i + 1}: State at {error_record.state.addr:#x} failed with: {error_record.error}"
            )

    # TODO: Maybe remove this output
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

    # Generate and visualize the call graph
    generate_and_visualize_graph(project, func_info_map)


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
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging.",
    )
    parser.add_argument(
        "--meta-file",
        type=str,
        default=None,
        help="Path to the meta file containing function parameter counts (optional).",
    )

    args = parser.parse_args()

    if not args.binary_path:
        my_logger.error(
            f"Usage: python {sys.argv[0]} <path_to_binary> [--show-libc-prints] [--show-syscall-prints]"
        )
        sys.exit(1)

    create_and_run_angr_project(vars(args))
