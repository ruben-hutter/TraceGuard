import angr
import logging
import sys
import argparse # Added for command-line arguments
from angr.exploration_techniques import DFS # Import DFS

# Configure logging for angr
# To see INFO and WARNING: logging.getLogger('angr').setLevel(logging.INFO)
# To see DEBUG (very verbose): logging.getLogger('angr').setLevel(logging.DEBUG)
# To suppress INFO and WARNING, showing only ERROR and CRITICAL:
logging.getLogger("angr").setLevel(logging.ERROR)

my_logger = logging.getLogger(__name__)
my_logger.setLevel(logging.DEBUG)
my_logger.propagate = False
console_handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("[%(levelname)s] - %(message)s")
console_handler.setFormatter(formatter)

# Add the handler to your script's logger
my_logger.addHandler(console_handler)

# Define common libc functions to help identify them
COMMON_LIBC_FUNCTIONS = {
    "printf", "scanf", "sprintf", "sscanf", "fprintf", "fscanf",
    "malloc", "free", "calloc", "realloc",
    "strcpy", "strncpy", "strcat", "strncat", "strcmp", "strncmp",
    "strlen", "strchr", "strrchr", "strstr", "strtok",
    "memcpy", "memmove", "memset", "memcmp",
    "fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "rewind",
    "exit", "abort", "puts", "gets", "fgets", "fputs",
    # Add more common libc function names as needed
}

def create_and_run_angr_project(binary_path, show_libc_prints, show_syscall_prints): # Added args
    """
    Loads a binary, hooks all its functions to print caller/callee information
    (with flags to control libc/syscall printing), and starts symbolic execution from 'main'.
    Uses DFS exploration strategy.
    """
    try:
        project = angr.Project(binary_path, auto_load_libs=False)
        my_logger.info(f"Successfully loaded binary: {binary_path}")
    except angr.errors.AngrFileNotFoundError:
        my_logger.error(f"Binary file not found at: {binary_path}")
        return
    except Exception as e:
        my_logger.error(f"Failed to load binary {binary_path}: {e}")
        return

    my_logger.info("Attempting to build CFG to identify functions...")
    try:
        cfg = project.analyses.CFGFast()
        cfg.normalize()
        my_logger.info(f"CFG analysis complete. Functions found in kb: {len(project.kb.functions)}")
        if not project.kb.functions:
            my_logger.warning("No functions found in the binary.")
    except Exception as e:
        my_logger.error(f"Failed to build CFG: {e}")
        my_logger.warning("Proceeding without explicit CFG, function discovery might be limited.")

    # Build a map of function addresses to their details
    func_info_map = {}
    for func_addr, func_obj in project.kb.functions.items():
        func_info_map[func_addr] = {
            "name": func_obj.name,
            "is_plt": func_obj.is_plt,
            "is_syscall": func_obj.is_syscall,
            "is_simprocedure": func_obj.is_simprocedure
        }
    
    if not func_info_map:
        my_logger.warning("No functions found in the binary.")

    main_symbol = project.loader.find_symbol("main")
    if not main_symbol:
        common_mains = ['main', '_main', 'start', '_start']
        for name in common_mains:
            main_symbol = project.loader.find_symbol(name)
            if main_symbol:
                my_logger.info(f"Found entry point '{name}' as main.")
                break
    
    if not main_symbol:
        my_logger.error("No 'main' function or common alternatives found in the binary.")
        return
    main_addr = main_symbol.rebased_addr

    # Create initial state and simulation manager BEFORE defining/setting hooks
    # so simgr is available in the hook's closure.
    try:
        initial_state = project.factory.entry_state(addr=main_addr)
    except Exception as e:
        my_logger.error(f"Failed to create initial state at {main_addr:#x}: {e}")
        return
    
    simgr = project.factory.simulation_manager(initial_state)
    simgr.use_technique(DFS()) # Add DFS exploration technique
    
    # Counter for hook calls
    hook_call_id_counter = 0

    def generic_function_hook(state):
        """
        This hook is called before a function's execution.
        It prints the called function's name and its caller's name,
        respecting flags for libc and syscall print suppression.
        All functions are allowed to execute.
        Includes state ID, call number, and active path count.
        """
        nonlocal hook_call_id_counter # Allow modification of outer scope variable
        hook_call_id_counter += 1
        
        called_func_addr = state.addr
        func_details = func_info_map.get(called_func_addr)

        do_print = True # Default to printing

        if func_details:
            called_func_name = func_details["name"]
            is_libc = func_details["is_plt"] or called_func_name in COMMON_LIBC_FUNCTIONS
            is_syscall_flag = func_details["is_syscall"]

            if is_libc and not show_libc_prints:
                do_print = False
            elif is_syscall_flag and not show_syscall_prints:
                do_print = False
        else:
            called_func_name = f"sub_{called_func_addr:#x}"

        if do_print:
            caller_name = "N/A (e.g., initial entry or no prior frame)"
            caller_func_address_str = "N/A"
            callstack_frames = list(state.callstack)

            if len(callstack_frames) > 1:
                caller_frame = callstack_frames[1]
                caller_actual_addr_from_frame = caller_frame.func_addr
                caller_func_address_str = f"0x{caller_actual_addr_from_frame:x}"
                if main_addr and caller_actual_addr_from_frame == main_addr:
                    main_info = func_info_map.get(main_addr)
                    caller_name = main_info["name"] if main_info else "main"
                else:
                    caller_info = func_info_map.get(caller_actual_addr_from_frame)
                    if caller_info:
                        caller_name = caller_info["name"]
                    else:
                        if caller_actual_addr_from_frame == 0:
                            caller_name = "N/A (entry or uninstrumented caller, e.g. from loader)"
                        else:
                            caller_name = f"sub_{caller_actual_addr_from_frame:#x} (unmapped in KB or external)"
            elif called_func_addr == main_addr and len(callstack_frames) <= 1:
                    caller_name = "N/A (Initial entry to main)"
            
            # Get total active paths
            num_active_paths_total = 0
            if simgr: # Ensure simgr is available
                num_active_paths_total = len(simgr.active)
            
            my_logger.debug(f"HOOK #{hook_call_id_counter:03d} :: CALLED: {called_func_name} (at 0x{called_func_addr:x}) :: FROM: {caller_name} (at {caller_func_address_str}) :: StateID: {id(state):#x} :: ActivePaths: {num_active_paths_total}")

        # Taint logic and creation of nx.Digraph for visualization

        # Angr will automatically execute the original instructions after this hook.

    my_logger.info("Hooking functions...")
    hooked_count = 0
    for func_addr_hook, func_obj_details_hook in func_info_map.items():
        if func_obj_details_hook["is_simprocedure"]:
            continue
        try:
            project.hook(func_addr_hook, generic_function_hook, length=0)
            hooked_count += 1
        except Exception as e:
            my_logger.warning(f"Could not hook {func_obj_details_hook['name']} at {func_addr_hook:#x}: {e}")
            
    my_logger.info(f"Hooked {hooked_count} functions.")

    my_logger.info(f"Starting symbolic execution from '{main_symbol.name}' at {main_addr:#x}")
    # initial_state and simgr are already created above

    my_logger.info(f"Starting simulation with {len(simgr.active)} initial state(s).")
    try:
        simgr.explore()
    except angr.errors.AngrTracerError as e:
        my_logger.warning(f"AngrTracerError during simulation: {e}. Results may be partial.")
    except Exception as e:
        my_logger.error(f"Unexpected error during simulation: {e}")
        import traceback
        traceback.print_exc()

    my_logger.info("Simulation complete.")
    if simgr.deadended:
        my_logger.info(f"{len(simgr.deadended)} states reached a dead end.")
    if simgr.active:
        my_logger.info(f"{len(simgr.active)} states are still active.")
    if simgr.errored:
        my_logger.info(f"{len(simgr.errored)} states encountered errors.")
        for i, error_record in enumerate(simgr.errored):
            my_logger.error(f"Error {i+1}: State at {error_record.state.addr:#x} failed with: {error_record.error}")
    if not simgr.deadended and not simgr.active and not simgr.errored:
        my_logger.warning("No states were processed or all states were pruned/merged early.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run angr symbolic execution with function call hooking.")
    parser.add_argument("binary_path", help="Path to the binary to analyze.")
    parser.add_argument("--show-libc-prints", action="store_true",
                        help="Show hook prints for common libc functions (default: hidden).")
    parser.add_argument("--show-syscall-prints", action="store_true",
                        help="Show hook prints for syscalls (default: hidden).")
    
    args = parser.parse_args()

    if not args.binary_path:
        print(f"Usage: python {sys.argv[0]} <path_to_binary> [--show-libc-prints] [--show-syscall-prints]")
        sys.exit(1)
            
    create_and_run_angr_project(args.binary_path, args.show_libc_prints, args.show_syscall_prints)

