import argparse
import logging
import sys
from pathlib import Path

import angr
import claripy
from angr.exploration_techniques import DFS
from constants import (
    INPUT_FUNCTION_NAMES,
    COMMON_LIBC_FUNCTIONS,
    DEBUG_LOG_FORMAT,
    INFO_LOG_FORMAT,
    DEFAULT_BUFFER_SIZE,
    MAX_TAINT_SIZE_BYTES,
    TAINT_SCORE_INPUT_FUNCTION,
    TAINT_SCORE_TAINTED_CALL,
    TAINT_SCORE_FUNCTION_CALL,
    TAINT_SCORE_DECAY_FACTOR,
    TAINT_SCORE_MINIMUM_TAINTED,
    AMD64_ARGUMENT_REGISTERS,
    AMD64_RETURN_REGISTER,
    X86_ARGUMENT_REGISTERS,
    X86_RETURN_REGISTER,
)
from meta import parse_meta_file
from taint_exploration import TaintGuidedExploration
from visualize import generate_and_visualize_graph

# Logging configuration
logging.getLogger("angr").setLevel(logging.ERROR)
my_logger = logging.getLogger(__name__)


class AnalysisSetupError(Exception):
    """Custom exception for errors during TaintAnalyzer setup."""

    pass


class TaintAnalyzer:
    """
    A class to encapsulate the Angr project setup, taint analysis logic,
    and simulation management.

    Attributes:
        binary_path (Path): The path to the binary file to analyze.
        args (dict): A dictionary of arguments passed to the analyzer.
        project (angr.Project): The Angr project instance.
        func_info_map (dict): A dictionary mapping function addresses to their details.
        main_addr (int): The rebased address of the main function.
        main_symbol_name (str): The name of the main function.
        simgr (angr.SimulationManager): The Angr simulation manager.
    """

    def __init__(self, binary_path, args):
        """
        Initializes the TaintAnalyzer.

        Args:
            binary_path (str): Path to the binary to analyze.
            args (dict): Dictionary of arguments for the analysis (e.g., verbose, debug, meta_file).

        Raises:
            AnalysisSetupError: If there's an issue loading the project or identifying the main function.
        """
        self.binary_path = Path(binary_path).resolve()
        self.args = args
        self.project = None
        self.func_info_map = {}
        self.main_addr = None
        self.main_symbol_name = None
        self.simgr = None
        self.cfg = None
        self.taint_exploration = None

        self._configure_logging()

        self._load_project()
        self._initialize_project_taint_attributes()
        self._load_meta_file()
        self._configure_architecture_info()
        self._build_cfg_and_function_map()
        self._identify_main_function()

    def _configure_logging(self):
        """Configures the logger based on verbose/debug arguments."""
        if my_logger.handlers:
            my_logger.handlers.clear()

        console_handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(INFO_LOG_FORMAT)
        console_handler.setFormatter(formatter)
        my_logger.addHandler(console_handler)

        my_logger.setLevel(logging.INFO)

        if self.args.get("verbose") or self.args.get("debug"):
            my_logger.setLevel(logging.DEBUG)
        if self.args.get("debug"):
            debug_formatter = logging.Formatter(DEBUG_LOG_FORMAT)
            console_handler.setFormatter(debug_formatter)

        my_logger.propagate = False

    def _load_project(self):
        """
        Loads the binary into an Angr project.

        Raises:
            AnalysisSetupError: If the binary file is not found or loading fails.
        """
        try:
            self.project = angr.Project(self.binary_path, auto_load_libs=False)
            my_logger.info(f"Successfully loaded binary: {self.binary_path}")
        except angr.errors.AngrFileNotFoundError as e:
            my_logger.error(f"Binary file not found at: {self.binary_path}")
            raise AnalysisSetupError(
                f"Binary file not found: {self.binary_path}"
            ) from e
        except Exception as e:
            my_logger.error(f"Failed to load binary {self.binary_path}: {e}")
            raise AnalysisSetupError(
                f"Failed to load binary {self.binary_path}: {e}"
            ) from e

    def _initialize_project_taint_attributes(self):
        """
        Initializes custom attributes on the project for taint tracking.
        These attributes include:
        - `project.tainted_functions`: A set of function names identified as processing tainted data.
        - `project.tainted_memory_regions`: A dictionary mapping addresses to sizes of tainted memory regions.
        - `project.tainted_edges`: A set of (caller, callee) tuples representing tainted call edges.
        - `project.hook_call_id_counter`: A counter for unique hook call IDs.
        """
        self.project.tainted_functions = set()
        self.project.tainted_memory_regions = {}
        self.project.tainted_edges = set()
        self.project.hook_call_id_counter = 0

    def _load_meta_file(self):
        """
        Loads the meta file for function parameter counts.
        If `meta_file` argument is provided, it uses that path. Otherwise, it attempts
        to auto-detect a `.meta` file alongside the binary.
        """
        meta_file_path = self.args.get("meta_file")
        if meta_file_path:
            meta_file_path = Path(meta_file_path).resolve()
            my_logger.info(f"Using meta file: {meta_file_path}")
        else:
            meta_file_path = self.binary_path.with_suffix(".meta")
            my_logger.info(f"Auto-detected meta file path: {meta_file_path}")

        if meta_file_path.exists():
            my_logger.info(f"Found meta file: {meta_file_path}")
            self.project.meta_param_counts = parse_meta_file(meta_file_path, my_logger)
        else:
            my_logger.warning(f"Meta file not found: {meta_file_path}")
            self.project.meta_param_counts = {}

    def _configure_architecture_info(self):
        """
        Configures architecture-specific information for argument and return registers.
        Currently supports AMD64 and X86.
        """
        self.project.arch_info = {}
        if self.project.arch.name == "AMD64":
            self.project.arch_info["argument_registers"] = AMD64_ARGUMENT_REGISTERS
            self.project.arch_info["return_register"] = AMD64_RETURN_REGISTER
        elif self.project.arch.name == "X86":
            self.project.arch_info["argument_registers"] = X86_ARGUMENT_REGISTERS
            self.project.arch_info["return_register"] = X86_RETURN_REGISTER
        else:
            my_logger.warning(
                f"Architecture {self.project.arch.name} argument registers not fully configured for taint analysis."
            )
            self.project.arch_info["argument_registers"] = []
            self.project.arch_info["return_register"] = ""

    def _build_cfg_and_function_map(self):
        """
        Builds the Control Flow Graph (CFG) and populates the function information map.
        The `func_info_map` stores details like function name, whether it's PLT, syscall, or SimProcedure.
        """
        my_logger.info("Attempting to build CFG to identify functions...")
        try:
            self.cfg = self.project.analyses.CFGFast()
            self.cfg.normalize()
            my_logger.info(
                f"CFG analysis complete. Functions found in kb: {len(self.project.kb.functions)}"
            )
        except Exception as e:
            my_logger.error(f"Failed to build CFG: {e}")
            my_logger.warning(
                "Proceeding without explicit CFG, function discovery might be limited."
            )

        self.func_info_map = {
            addr: {
                "name": f.name,
                "is_plt": f.is_plt,
                "is_syscall": f.is_syscall,
                "is_simprocedure": f.is_simprocedure,
            }
            for addr, f in self.project.kb.functions.items()
            if f.name
        }

        if not self.func_info_map:
            my_logger.warning("No functions found in the binary's knowledge base.")

    def _identify_main_function(self):
        """
        Identifies the main function, sets the initial state for symbolic execution, and initializes the simulation manager.

        Raises:
            AnalysisSetupError: If the main function or entry point cannot be determined,
                                or if the initial simulation state cannot be created.
        """
        main_symbol = self.project.loader.find_symbol("main")
        if main_symbol:
            my_logger.debug(
                f"Found main function symbol: {main_symbol.name} at {main_symbol.rebased_addr:#x}"
            )
            self.main_addr = main_symbol.rebased_addr
            if self.main_addr in self.func_info_map:
                my_logger.info(
                    f"Correcting main function name from {self.func_info_map[self.main_addr]['name']} to {main_symbol.name}"
                )
                self.func_info_map[self.main_addr]["name"] = main_symbol.name
                if self.project.kb.functions.contains_addr(self.main_addr):
                    self.project.kb.functions[self.main_addr].name = main_symbol.name
        else:
            if self.project.entry is None:
                my_logger.error("No entry point could be determined.")
                raise AnalysisSetupError(
                    "No entry point could be determined for the binary."
                )
            my_logger.warning(
                "Main function symbol not found, using entry point as main."
            )
            self.main_addr = self.project.entry

        self.main_symbol_name = self.func_info_map.get(self.main_addr, {}).get(
            "name", f"sub_{self.main_addr:#x}"
        )
        my_logger.debug(
            f"Main function address: {self.main_addr:#x}, name: {self.main_symbol_name}"
        )

        try:
            initial_state = self.project.factory.full_init_state(addr=self.main_addr)
            self.simgr = self.project.factory.simulation_manager(initial_state, save_unconstrained=True)

            self.simgr.use_technique(angr.exploration_techniques.LengthLimiter(1000))
            if self.cfg:
                self.simgr.use_technique(
                    angr.exploration_techniques.LoopSeer(cfg=self.cfg)
                )
            else:
                my_logger.warning("No CFG found for LoopSeer, proceeding without it.")
            self.simgr.use_technique(DFS())

            self.taint_exploration = TaintGuidedExploration(
                logger=my_logger, project=self.project
            )
            self.simgr.use_technique(self.taint_exploration)

        except Exception as e:
            my_logger.error(
                f"Failed to create initial state at {self.main_addr:#x}: {e}"
            )
            raise AnalysisSetupError(
                f"Failed to create initial simulation state: {e}"
            ) from e

    def _is_value_tainted(self, state, value):
        """
        Check if a value is tainted by looking for symbolic variables or
        checking if it points to a known tainted memory region.

        Args:
            state (angr.sim_state.SimState): The current simulation state.
            value (claripy.ast.Base): The value to check for taint.

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
                addr = state.solver.eval_one(value)
                for (
                    region_addr,
                    region_size,
                ) in self.project.tainted_memory_regions.items():
                    if region_addr <= addr < region_addr + region_size:
                        my_logger.debug(
                            f"Taint check: Value {addr:#x} points into known tainted region {region_addr:#x} (size {region_size})."
                        )
                        return True
            except angr.errors.SimSolverError:
                my_logger.debug(
                    f"SimSolverError while checking if value {value} points to tainted memory. Assuming not tainted for this check."
                )
            except Exception as e:
                my_logger.debug(
                    f"Exception while checking if value {value} points to tainted memory: {e}. Assuming not tainted."
                )
        return False

    def _taint_fgets_buffer(self, state, called_func_name):
        """
        Handles tainting the buffer for fgets specifically.
        It creates a symbolic variable representing the tainted input and stores it
        in the memory region pointed to by the buffer argument.

        Args:
            state (angr.sim_state.SimState): The current simulation state.
            called_func_name (str): The name of the function that was called (e.g., "fgets").
        """
        if self.project.arch.name != "AMD64":
            my_logger.warning(
                f"fgets tainting not implemented for arch {self.project.arch.name}"
            )
            return

        try:
            buf_ptr_val = state.regs.rdi
            size_val_sym = state.regs.rsi

            try:
                size_val = state.solver.eval_one(size_val_sym)
            except angr.errors.SimSolverError:
                my_logger.warning(
                    f"Could not concretize size for {called_func_name}, using default 128."
                )
                size_val = DEFAULT_BUFFER_SIZE

            buf_addr = state.solver.eval_one(buf_ptr_val)

            taint_size_bytes = min(size_val, MAX_TAINT_SIZE_BYTES)
            if taint_size_bytes <= 0:
                my_logger.warning(
                    f"Invalid or zero size for taint from {called_func_name}: {size_val}"
                )
                return

            taint_id = (
                f"taint_source_{called_func_name}_{self.project.hook_call_id_counter}"
            )
            symbolic_taint_data = claripy.BVS(taint_id, taint_size_bytes * 8)

            state.memory.store(
                buf_addr, symbolic_taint_data, endness=self.project.arch.memory_endness
            )
            self.project.tainted_memory_regions[buf_addr] = taint_size_bytes
            my_logger.debug(
                f"TAINTED: Memory at {buf_addr:#x} (size {taint_size_bytes} bytes) by {called_func_name} with BVS '{taint_id}'."
            )

        except angr.errors.SimSolverError as e:
            my_logger.error(
                f"SimSolverError while tainting buffer for {called_func_name} (likely symbolic pointer/size): {e}"
            )
        except Exception as e:
            my_logger.error(f"Error tainting buffer for {called_func_name}: {e}")

    def _input_function_hook(self, state):
        """
        Hook for input functions to mark their outputs as tainted.
        This function increments the hook call counter, adds the called function
        to the set of tainted functions, and specifically handles fgets buffer tainting.

        Args:
            state (angr.sim_state.SimState): The current simulation state.
        """
        self.project.hook_call_id_counter += 1

        called_func_addr = state.addr
        func_details = self.func_info_map.get(called_func_addr)
        called_func_name = (
            func_details["name"] if func_details else f"sub_{called_func_addr:#x}"
        )

        self.project.tainted_functions.add(called_func_name)
        my_logger.info(
            f"TAINT_SOURCE: Input function {called_func_name} at {called_func_addr:#x} is introducing taint."
        )

        self._update_state_taint_score(state, called_func_name, True)

        current_score = state.globals.get("taint_score", 0)
        state.globals["taint_score"] = current_score + 5.0

        if called_func_name == "fgets":
            self._taint_fgets_buffer(state, called_func_name)
        # TODO: Add more input functions here (e.g., read, recv) adapting argument registers and logic

    def _check_pointer_for_taint(self, state, ptr_value, called_name, arg_reg_name):
        """
        Helper to check if a pointer value points to a tainted memory region or tainted data.

        Args:
            state (angr.sim_state.SimState): The current simulation state.
            ptr_value (claripy.ast.Base): The pointer value to check.
            called_name (str): The name of the function being called.
            arg_reg_name (str): The name of the register holding the pointer argument.

        Returns:
            bool: True if the pointer or the data it points to is tainted, False otherwise.
        """
        try:
            ptr_addr = state.solver.eval_one(ptr_value)
            if ptr_addr in self.project.tainted_memory_regions:
                my_logger.info(
                    f"TAINT_ARG_PTR: Function {called_name} called with {arg_reg_name} pointing to base of tainted region {ptr_addr:#x}."
                )
                return True

            mem_val_check = state.memory.load(ptr_addr, 1, inspect=False)
            if self._is_value_tainted(state, mem_val_check):
                my_logger.info(
                    f"TAINT_ARG_PTR: Function {called_name} called with {arg_reg_name} (value {ptr_addr:#x}) pointing to tainted data."
                )
                return True
        except (
            angr.errors.SimMemoryError,
            angr.errors.SimSegfaultException,
        ):
            # Ignore memory errors, likely invalid or unmapped pointers
            pass
        except angr.errors.SimSolverError:
            my_logger.debug(
                f"Solver error evaluating arg {arg_reg_name} for {called_name} as pointer."
            )
        except Exception as e:
            my_logger.debug(
                f"Error checking pointer arg {arg_reg_name} for {called_name}: {e}"
            )
        return False

    def _check_arg_for_taint(self, state, arg_reg_name, called_name):
        """
        Helper method to check if a single argument (direct value or pointed-to memory) is tainted.

        Args:
            state (angr.sim_state.SimState): The current simulation state.
            arg_reg_name (str): The name of the register holding the argument.
            called_name (str): The name of the function being called.

        Returns:
            bool: True if the argument is tainted, False otherwise.
        """
        try:
            arg_value = getattr(state.regs, arg_reg_name)

            if self._is_value_tainted(state, arg_value):
                my_logger.info(
                    f"TAINT_ARG: Function {called_name} (at {state.addr:#x}) called with tainted argument in register {arg_reg_name}."
                )
                return True

            if not arg_value.symbolic:
                if self._check_pointer_for_taint(
                    state, arg_value, called_name, arg_reg_name
                ):
                    return True

        except AttributeError:
            my_logger.warning(
                f"Register {arg_reg_name} not found for arch {self.project.arch.name} checking args for {called_name}."
            )
        except Exception as e:
            my_logger.error(
                f"Error checking argument {arg_reg_name} for {called_name}: {e}"
            )
        return False

    def _get_caller_info(self, state, called_name):
        """
        Determines the caller's name and address from the callstack.

        Args:
            state (angr.sim_state.SimState): The current simulation state.
            called_name (str): The name of the currently called function.

        Returns:
            tuple: A tuple containing (caller_name, caller_func_address_str).
        """
        caller_name = "N/A (e.g., initial entry or no prior frame)"
        caller_func_address_str = "N/A"

        if not state.callstack:
            my_logger.debug(
                f"State {id(state):#x} has no callstack, cannot determine caller for {called_name}."
            )
            return caller_name, caller_func_address_str

        callstack_frames = list(state.callstack)
        if len(callstack_frames) > 1:
            caller_frame = callstack_frames[1]
            caller_addr = caller_frame.func_addr
            caller_info = self.func_info_map.get(caller_addr)
            caller_name = (
                caller_info["name"] if caller_info else f"sub_{caller_addr:#x}"
            )
            caller_func_address_str = f"{caller_addr:#x}"
        elif state.callstack.current_function_address == self.main_addr:
            caller_name = self.func_info_map[self.main_addr]["name"]
            caller_func_address_str = f"{self.main_addr:#x} (main)"
        else:
            caller_name = f"N/A (shallow stack, current: {called_name})"

        return caller_name, caller_func_address_str

    def _determine_num_args_to_check(self, called_name, arch_arg_regs):
        """
        Determines how many arguments to check based on meta file or default.

        Args:
            called_name (str): The name of the function being called.
            arch_arg_regs (list): A list of architecture-specific argument registers.

        Returns:
            int: The number of arguments to check for taint.
        """
        if called_name in self.project.meta_param_counts:
            num_args_to_check_from_meta = self.project.meta_param_counts[called_name]
            num_args_to_check = min(num_args_to_check_from_meta, len(arch_arg_regs))
            my_logger.debug(
                f"Meta for {called_name}: {num_args_to_check_from_meta} params. Will check {num_args_to_check} registers."
            )
        else:
            num_args_to_check = len(arch_arg_regs)
            my_logger.debug(
                f"No meta param count for {called_name}, defaulting to check {num_args_to_check} registers."
            )
        return num_args_to_check

    def _should_log_hook(self, func_details, called_name):
        """
        Determines if the hook details should be logged based on user print settings
        (e.g., `--show-libc-prints`, `--show-syscall-prints`).

        Args:
            func_details (dict): Details about the hooked function.
            called_name (str): The name of the called function.

        Returns:
            bool: True if logging is enabled for this function, False otherwise.
        """
        if not func_details:
            return True

        is_libc = func_details["is_plt"] or called_name in COMMON_LIBC_FUNCTIONS
        is_syscall_flag = func_details["is_syscall"]

        if (is_libc and not self.args.get("show_libc_prints")) or (
            is_syscall_flag and not self.args.get("show_syscall_prints")
        ):
            return False
        return True

    def _generic_function_hook(self, state):
        """
        Hook for general functions to check arguments for taint.
        This hook is applied to all user-defined and non-input library functions.
        It identifies if any arguments are tainted and updates `project.tainted_functions`
        and `project.tainted_edges` accordingly.

        Args:
            state (angr.sim_state.SimState): The current simulation state.
        """
        self.project.hook_call_id_counter += 1

        called_addr = state.addr
        func_details = self.func_info_map.get(called_addr)
        called_name = func_details["name"] if func_details else f"sub_{called_addr:#x}"

        caller_name, caller_func_address_str = self._get_caller_info(state, called_name)

        arguments_are_tainted = False
        arch_arg_regs = self.project.arch_info.get("argument_registers", [])
        num_args_to_check = self._determine_num_args_to_check(
            called_name, arch_arg_regs
        )

        if arch_arg_regs and num_args_to_check > 0:
            for i in range(num_args_to_check):
                arg_reg_name = arch_arg_regs[i]
                if self._check_arg_for_taint(state, arg_reg_name, called_name):
                    arguments_are_tainted = True
                    break

        taint_status_msg = " [TAINTED]" if arguments_are_tainted else ""
        if arguments_are_tainted:
            self.project.tainted_functions.add(called_name)
            if not caller_name.startswith("N/A"):
                self.project.tainted_edges.add((caller_name, called_name))

        self._update_state_taint_score(state, called_name, arguments_are_tainted)

        if self._should_log_hook(func_details, called_name):
            num_active_paths_total = len(self.simgr.active) if self.simgr else 0
            my_logger.debug(
                f"HOOK #{self.project.hook_call_id_counter:03d} :: CALLED: {called_name}{taint_status_msg} (at 0x{called_addr:x}) :: FROM: {caller_name} (at {caller_func_address_str}) :: StateID: {id(state):#x} :: ActivePaths: {num_active_paths_total}"
            )

    def _hook_functions(self):
        """
        Hooks all identified functions with appropriate taint analysis hooks.
        Input functions get a special hook to mark their outputs as tainted,
        while other functions get a generic hook to check for tainted arguments.
        """
        my_logger.info("Hooking functions with taint analysis logic...")
        hooked_count = 0
        for func_addr, func_details in self.func_info_map.items():
            hook = (
                self._input_function_hook
                if func_details["name"] in INPUT_FUNCTION_NAMES
                else self._generic_function_hook
            )

            try:
                self.project.hook(func_addr, hook, length=0)
                hooked_count += 1
            except Exception as e:
                my_logger.warning(
                    f"Could not hook {func_details['name']} at {func_addr:#x}: {e}"
                )
        my_logger.info(f"Hooked {hooked_count} functions for taint analysis.")

    def run_analysis(self):
        """
        Executes the symbolic analysis by hooking functions and running the simulation manager.
        It also reports the simulation results and visualizes the call graph.
        """
        self._hook_functions()

        my_logger.info(
            f"Starting symbolic execution from '{self.main_symbol_name}' at {self.main_addr:#x}"
        )
        my_logger.info(
            f"Starting simulation with {len(self.simgr.active)} initial state(s)."
        )

        try:
            self.simgr.run()

        except angr.errors.AngrTracerError as e:
            my_logger.warning(
                f"AngrTracerError during simulation: {e}. Results may be partial."
            )
        except Exception as e:
            my_logger.error(f"Unexpected error during simulation: {e}")
            import traceback

            traceback.print_exc()

        my_logger.info("Simulation complete.")
        self._report_simulation_results()

        if self._is_server_running():
            self._visualize_graph()

    def _is_server_running(self):
        """
        Checks if the Schnauzer visualization server is running.
        This is a placeholder function; actual implementation may vary.
        """
        try:
            # You can add actual server checking logic here later
            # For now, return False to disable visualization
            return False
        except Exception:
            return False

    def _report_simulation_results(self):
        """
        Reports the outcome of the symbolic simulation, including information about
        deadended, active, and errored states.
        If verbose mode is enabled, it also prints tainted call edges and functions
        that processed tainted data.
        """
        if self.simgr:
            if self.simgr.deadended:
                """
                my_logger.info(
                    f"{len(self.simgr.deadended)} states reached a dead end."
                )
                """
                pass
            if self.simgr.active:
                my_logger.info(f"{len(self.simgr.active)} states are still active.")
            if self.simgr.errored:
                my_logger.info(f"{len(self.simgr.errored)} states encountered errors.")
                for i, error_record in enumerate(self.simgr.errored):
                    my_logger.error(
                        f"Error {i + 1}: State at {error_record.state.addr:#x} failed with: {error_record.error}"
                    )
            if self.simgr.unconstrained:
                # TODO: Check if this is good
                my_logger.info(
                    f"{len(self.simgr.unconstrained)} states are unconstrained."
                )
                for i, unconstrained_state in enumerate(self.simgr.unconstrained):
                    my_logger.info(
                        f"Unconstrained State {i + 1}: {unconstrained_state}"
                    )

        if self.taint_exploration:
            self.taint_exploration.print_metrics()

        if self.args.get("verbose"):
            if self.project and self.project.tainted_edges:
                my_logger.info(
                    "Tainted call edges (propagation of taint to arguments):"
                )
                for caller, callee in sorted(list(self.project.tainted_edges)):
                    print(f"  {caller} -> {callee}")
            else:
                my_logger.info("No tainted call edges were recorded.")

            my_logger.info("Functions that processed/received tainted data:")
            if self.project and self.project.tainted_functions:
                for func_name in sorted(list(self.project.tainted_functions)):
                    print(f"  - {func_name}")
            else:
                my_logger.info(
                    "No functions were identified as processing or receiving tainted data."
                )

    def _update_state_taint_score(self, state, called_name, is_tainted):
        """
        Update the taint score for a state based on function call analysis.
        This integrates with TaintGuidedExploration for prioritization.
        """
        current_score = state.globals.get("taint_score", 0)

        if is_tainted:
            # Increase score for tainted interactions
            if called_name in INPUT_FUNCTION_NAMES:
                current_score += TAINT_SCORE_INPUT_FUNCTION
            else:
                current_score += TAINT_SCORE_TAINTED_CALL
        else:
            # Small boost just for function calls (exploration progress)
            current_score += TAINT_SCORE_FUNCTION_CALL

        # Apply decay to prevent infinite score growth
        current_score *= TAINT_SCORE_DECAY_FACTOR
        if is_tainted:
            current_score = max(current_score, TAINT_SCORE_MINIMUM_TAINTED)

        state.globals["taint_score"] = max(current_score, 0.0)

    def _visualize_graph(self):
        """
        Generates and visualizes the call graph using the Schnauzer visualization client.
        Tainted nodes and edges are colored red, others are blue.
        """
        if self.project and self.func_info_map:
            generate_and_visualize_graph(self.project, self.func_info_map, my_logger)
        else:
            my_logger.warning(
                "Cannot visualize graph: Project or function map not available."
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

    try:
        analyzer = TaintAnalyzer(args.binary_path, vars(args))
        analyzer.run_analysis()
    except AnalysisSetupError as e:
        my_logger.critical(f"Analysis setup failed: {e}")
        sys.exit(1)
