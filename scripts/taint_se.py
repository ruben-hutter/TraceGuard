import argparse
import logging
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import angr
import claripy
from angr.exploration_techniques import DFS
from constants import (
    AMD64_ARGUMENT_REGISTERS,
    AMD64_RETURN_REGISTER,
    COMMON_LIBC_FUNCTIONS,
    DEBUG_LOG_FORMAT,
    DEFAULT_BUFFER_SIZE,
    INFO_LOG_FORMAT,
    INPUT_FUNCTION_NAMES,
    MAX_TAINT_SIZE_BYTES,
    TAINT_SCORE_DECAY_FACTOR,
    TAINT_SCORE_FUNCTION_CALL,
    TAINT_SCORE_INPUT_FUNCTION,
    TAINT_SCORE_INPUT_HOOK_BONUS,
    TAINT_SCORE_MINIMUM_TAINTED,
    TAINT_SCORE_TAINTED_CALL,
    X86_ARGUMENT_REGISTERS,
    X86_RETURN_REGISTER,
)
from meta import parse_meta_file
from taint_exploration import TaintGuidedExploration
from visualize import generate_and_visualize_graph

# Logging configuration
logging.getLogger("angr").setLevel(logging.ERROR)
my_logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """
    Data class to hold all analysis results in a structured way.
    This replaces the need for output parsing and makes the module properly importable.
    """

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

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "success": self.success,
            "analysis_time": self.analysis_time,
            "active_states": self.active_states,
            "deadended_states": self.deadended_states,
            "errored_states": self.errored_states,
            "unconstrained_states": self.unconstrained_states,
            "functions_analyzed": self.functions_analyzed,
            "functions_executed": self.functions_executed,
            "functions_skipped": self.functions_skipped,
            "taint_sources_found": self.taint_sources_found,
            "tainted_functions": self.tainted_functions,
            "tainted_edges": self.tainted_edges,
            "vulnerabilities_found": self.vulnerabilities_found,
            "time_to_first_vuln": self.time_to_first_vuln,
            "vulnerability_details": self.vulnerability_details,
            "basic_blocks_covered": self.basic_blocks_covered,
            "states_explored": self.states_explored,
            "memory_usage_mb": self.memory_usage_mb,
            "error_message": self.error_message,
        }


class AnalysisSetupError(Exception):
    """Custom exception for errors during TaintAnalyzer setup."""

    pass


class TraceGuard:
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

        # TODO: move inside metrics??
        self.first_vuln_time = None
        self.metrics = {
            "functions_executed": 0,
            "functions_skipped": 0,
            "taint_sources_found": 0,
            "vulnerabilities_found": 0,
            "vulnerability_details": [],
            "basic_blocks_covered": set(),
            "states_explored": 0,
        }

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

        # Quiet mode for benchmarks
        if self.args.get("quite", False):
            my_logger.setLevel(logging.CRITICAL)

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
            self.simgr = self.project.factory.simulation_manager(
                initial_state, save_unconstrained=True
            )

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
        """More aggressive taint detection"""
        if not hasattr(value, "symbolic") or not value.symbolic:
            return False

        # Check for ANY symbolic variables - be much more permissive
        if hasattr(value, "variables"):
            for var_name in value.variables:
                var_str = str(var_name)
                # Any of these patterns = tainted
                if any(pattern in var_str for pattern in [
                    "taint_source_", "stdin", "symbolic", "unconstrained", "input"
                ]):
                    return True

        # Check string representation
        value_str = str(value)
        if any(pattern in value_str for pattern in [
            "taint_source_", "stdin", "symbolic", "unconstrained"
        ]):
            return True

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

    def _taint_scanf_buffer(self, state, called_func_name):
        """Handle scanf taint properly"""
        if self.project.arch.name != "AMD64":
            return

        try:
            # Get the variable address (second parameter)
            var_ptr_val = state.regs.rsi
            var_addr = state.solver.eval_one(var_ptr_val)
            
            # Create a symbolic integer with clear taint marking
            taint_id = f"taint_source_{called_func_name}_{self.project.hook_call_id_counter}"
            # Use 32-bit BVS for integer
            tainted_int = claripy.BVS(taint_id, 32)
            
            # Store the tainted integer at the variable location
            state.memory.store(var_addr, tainted_int, endness=self.project.arch.memory_endness)
            self.project.tainted_memory_regions[var_addr] = 4  # 4 bytes for int
            
            my_logger.debug(f"TAINTED: Integer at {var_addr:#x} with {taint_id}")
            
        except Exception as e:
            my_logger.error(f"Error in scanf taint: {e}")

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

        self._track_taint_source()
        self._track_function_execution(True)
        self._track_basic_block(called_func_addr)

        self._update_state_taint_score(state, called_func_name, True)

        current_score = state.globals.get("taint_score", 0)
        state.globals["taint_score"] = current_score + TAINT_SCORE_INPUT_HOOK_BONUS

        if called_func_name == "fgets":
            self._taint_fgets_buffer(state, called_func_name)
        elif called_func_name == "scanf":
            self._taint_scanf_buffer(state, called_func_name)
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

        self._track_basic_block(called_addr)

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

        self._track_function_execution(arguments_are_tainted)

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
            is_input_function = any(
                input_func in func_details["name"]
                for input_func in INPUT_FUNCTION_NAMES
            )

            hook = (
                self._input_function_hook
                if is_input_function
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

    def run_analysis(self, timeout=None) -> AnalysisResult:
        """
        Executes the symbolic analysis by hooking functions and running the simulation manager.
        It also reports the simulation results.
        """
        analysis_start_time = time.time()
        self._hook_functions()

        my_logger.info(
            f"Starting symbolic execution from '{self.main_symbol_name}' at {self.main_addr:#x}"
        )
        my_logger.info(
            f"Starting simulation with {len(self.simgr.active)} initial state(s)."
        )

        try:
            # Track first vulnerability timing
            first_vuln_found = False
            
            # Create a custom step function to track vulnerabilities
            def step_with_vuln_check(simgr):
                nonlocal first_vuln_found
                
                # Perform the actual step
                simgr.step()
                
                # Check for first vulnerability after each step
                if not first_vuln_found:
                    new_vulnerabilities = 0

                    # Check unconstrained states
                    if simgr.unconstrained:
                        new_vulnerabilities += len(simgr.unconstrained)

                    # Check errored states for vulnerabilities
                    if simgr.errored:
                        for error_record in simgr.errored:
                            if self._is_vulnerability_state(error_record):
                                new_vulnerabilities += 1

                    # Record time to first vulnerability
                    if new_vulnerabilities > 0:
                        self.first_vuln_time = time.time() - analysis_start_time
                        first_vuln_found = True
                        my_logger.info(
                            f"First vulnerability found at {self.first_vuln_time:.3f}s"
                        )
                
                return simgr

            # Run simulation with proper timeout using angr's built-in mechanism
            my_logger.info(f"Running simulation with {timeout}s timeout" if timeout else "Running simulation without timeout")
            
            self.simgr.run(
                step_func=step_with_vuln_check,
                timeout=timeout,
                step_limit=500
            )
            
            success = True
            error_message = None
            
            my_logger.info("Simulation completed successfully")

        except angr.errors.AngrTimeoutError:
            my_logger.warning(f"TIMEOUT: Analysis stopped after {timeout}s")
            success = True
            error_message = f"Timeout after {timeout}s"
            
        except angr.errors.AngrTracerError as e:
            my_logger.warning(
                f"AngrTracerError during simulation: {e}. Results may be partial."
            )
            success = False
            error_message = f"AngrTracerError: {e}"
            
        except Exception as e:
            my_logger.error(f"Unexpected error during simulation: {e}")
            import traceback
            traceback.print_exc()
            success = False
            error_message = f"Unexpected error: {e}"

        analysis_time = time.time() - analysis_start_time

        result = self._collect_analysis_result(
            success=success,
            analysis_time=analysis_time,
            error_message=error_message,
        )

        self._log_analysis_result(result)

        if self._is_server_running():
            self._visualize_graph()

        return result

    def _is_server_running(self):
        """
        Check if Schnauzer server is running on the default address and port.

        Returns:
            bool: True if server is accessible, False otherwise
        """
        import socket
        import urllib.request
        import urllib.error

        # Default Schnauzer server configuration
        server_host = "127.0.0.1"
        server_port = 8080
        server_url = f"http://{server_host}:{server_port}"

        try:
            # First, try a simple socket connection to check if port is open
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.0)  # 1 second timeout
                result = sock.connect_ex((server_host, server_port))
                if result != 0:
                    return False

            # If port is open, try an HTTP request to verify it's actually Schnauzer
            try:
                with urllib.request.urlopen(server_url, timeout=2.0) as response:
                    # If we get any HTTP response, assume the server is running
                    return response.getcode() < 500
            except urllib.error.HTTPError as e:
                # Even HTTP errors (like 404) indicate a server is running
                return e.code < 500
            except urllib.error.URLError:
                # URL errors typically mean connection issues
                return False

        except (socket.error, OSError, Exception) as e:
            my_logger.debug(f"Server check failed: {e}")
            return False

    def _is_vulnerability_state(self, error_record):
        """Check if an errored state represents a vulnerability"""
        if not hasattr(error_record, "error"):
            return False

        error_str = str(error_record.error).lower()
        vulnerability_indicators = [
            "segmentation fault",
            "segfault",
            "buffer overflow",
            "stack overflow",
            "heap overflow",
            "access violation",
            "memory error",
            "sigsegv",
            "simmemorylimitexception",
            "simstateerror",
            "simcallstackpopexception",
        ]

        return any(indicator in error_str for indicator in vulnerability_indicators)

    def _get_memory_usage(self):
        """Get current memory usage in MB"""
        try:
            import psutil

            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024
        except ImportError:
            return 0.0

    def _track_function_execution(self, executed: bool):
        """Track function execution for metrics"""
        if executed:
            self.metrics["functions_executed"] += 1
        else:
            self.metrics["functions_skipped"] += 1

    def _track_taint_source(self):
        """Track taint source discovery"""
        self.metrics["taint_sources_found"] += 1

    def _track_basic_block(self, address: int):
        """Track basic block coverage"""
        self.metrics["basic_blocks_covered"].add(address)

    def _collect_analysis_result(
        self,
        success: bool,
        analysis_time: float,
        error_message: Optional[str] = None,
    ) -> AnalysisResult:
        """
        Collect all analysis results into a structured AnalysisResult object.
        """
        # Get state counts
        active_states = len(self.simgr.active) if self.simgr else 0
        deadended_states = len(self.simgr.deadended) if self.simgr else 0
        errored_states = len(self.simgr.errored) if self.simgr else 0
        unconstrained_states = len(self.simgr.unconstrained) if self.simgr else 0

        # Calculate total states explored
        total_states = (
            active_states + deadended_states + errored_states + unconstrained_states
        )

        # Analyze vulnerabilities from simulation states
        vulnerability_details = []
        vulnerabilities_found = self.metrics["vulnerabilities_found"]

        if self.simgr:
            # Check errored states for vulnerabilities
            for i, error_record in enumerate(self.simgr.errored):
                if self._is_vulnerability_state(error_record):
                    vulnerabilities_found += 1

                    vulnerability_details.append(
                        {
                            "type": "errored_state",
                            "address": error_record.state.addr,
                            "error": str(error_record.error),
                            "index": i,
                        }
                    )

            # Check unconstrained states (potential vulnerabilities)
            for i, unconstrained_state in enumerate(self.simgr.unconstrained):
                vulnerabilities_found += 1

                address = None
                try:
                    possible_addrs = unconstrained_state.solver.eval_upto(
                        unconstrained_state.regs._ip, 2
                    )
                    if len(possible_addrs) == 1:
                        address = possible_addrs[0]
                    elif len(possible_addrs) > 1:
                        # TODO: Handle multiple possible addresses
                        address = possible_addrs[0]  # Just take the first one
                except Exception:
                    # If we can't get any address, that's fine - leave it as None
                    pass

                vulnerability_details.append(
                    {
                        "type": "unconstrained_state",
                        "address": address,
                        "index": i,
                    }
                )

        # Get taint-specific metrics
        tainted_functions = (
            list(self.project.tainted_functions)
            if hasattr(self.project, "tainted_functions")
            and self.project.tainted_functions
            else []
        )
        tainted_edges = (
            list(self.project.tainted_edges)
            if hasattr(self.project, "tainted_edges") and self.project.tainted_edges
            else []
        )

        # Get memory usage
        memory_usage = self._get_memory_usage()

        return AnalysisResult(
            success=success,
            analysis_time=analysis_time,
            active_states=active_states,
            deadended_states=deadended_states,
            errored_states=errored_states,
            unconstrained_states=unconstrained_states,
            functions_analyzed=len(self.func_info_map),
            functions_executed=self.metrics["functions_executed"],
            functions_skipped=self.metrics["functions_skipped"],
            taint_sources_found=self.metrics["taint_sources_found"],
            tainted_functions=tainted_functions,
            tainted_edges=tainted_edges,
            vulnerabilities_found=vulnerabilities_found,
            time_to_first_vuln=self.first_vuln_time,
            vulnerability_details=vulnerability_details,
            basic_blocks_covered=len(self.metrics["basic_blocks_covered"]),
            states_explored=total_states,
            memory_usage_mb=memory_usage,
            error_message=error_message,
        )

    def _log_analysis_result(self, result: AnalysisResult):
        """
        Log analysis result in the traditional format for CLI usage.
        """
        if self.args.get("verbose"):
            my_logger.info("Functions that processed/received tainted data:")
            if result.tainted_functions:
                for func_name in sorted(result.tainted_functions):
                    print(f"  - {func_name}")
            else:
                my_logger.info(
                    "No functions were identified as processing or receiving tainted data."
                )

            if result.tainted_edges:
                my_logger.info(
                    "Tainted call edges (propagation of taint to arguments):"
                )
                for caller, callee in sorted(result.tainted_edges):
                    print(f"  {caller} -> {callee}")
            else:
                my_logger.info("No tainted call edges were recorded.")

        my_logger.info("=== TAINT ANALYSIS RESULTS ===")

        # Basic execution info
        my_logger.info(f"Analysis successful: {result.success}")
        my_logger.info(f"Analysis time: {result.analysis_time:.3f}s")

        # State information
        if result.active_states > 0:
            my_logger.info(f"{result.active_states} states are still active.")
        if result.deadended_states > 0:
            my_logger.info(f"{result.deadended_states} states reached a dead end.")
        if result.errored_states > 0:
            my_logger.info(f"{result.errored_states} states encountered errors.")
            for vuln in result.vulnerability_details:
                if vuln["type"] == "errored_state":
                    my_logger.error(
                        f"Error {vuln['index'] + 1}: State at {vuln['address']:#x} failed with: {vuln['error']}"
                    )
        if result.unconstrained_states > 0:
            my_logger.info(f"{result.unconstrained_states} states are unconstrained.")
            for vuln in result.vulnerability_details:
                if vuln["type"] == "unconstrained_state":
                    addr_str = f" at {vuln['address']:#x}" if vuln["address"] else ""
                    my_logger.info(f"Unconstrained State {vuln['index'] + 1}{addr_str}")

        # Function execution analysis
        total_discovered = result.functions_analyzed
        total_called = result.functions_executed + result.functions_skipped
        uncalled_functions = total_discovered - total_called

        my_logger.info(f"Functions discovered: {total_discovered}")
        my_logger.info(
            f"Functions called: {total_called} ({result.functions_executed} executed, {result.functions_skipped} skipped)"
        )
        if uncalled_functions > 0:
            my_logger.info(f"Functions not reached: {uncalled_functions}")

        # Vulnerabilities
        if result.vulnerabilities_found > 0:
            my_logger.info(f"Vulnerabilities found: {result.vulnerabilities_found}")
            if result.time_to_first_vuln:
                my_logger.info(
                    f"Time to first vulnerability: {result.time_to_first_vuln:.3f}s"
                )

        # Taint-specific information
        if self.taint_exploration:
            metrics = self.taint_exploration.get_exploration_metrics()

            my_logger.info(f"Taint sources found: {result.taint_sources_found}")
            my_logger.info(
                f"Taint propagation paths: {metrics['taint_propagation_paths']}"
            )

            # Input sources
            if metrics["input_sources_found"] > 0:
                sources_str = ", ".join(metrics["input_source_names"])
                my_logger.info(
                    f"Input sources: {metrics['input_sources_found']} ({sources_str})"
                )
            else:
                my_logger.info("Input sources: None detected")

            # Security-relevant sinks
            if metrics["critical_sinks_found"] > 0:
                sinks_str = ", ".join(metrics["critical_sink_names"])
                my_logger.info(
                    f"Critical sinks: {metrics['critical_sinks_found']} ({sinks_str})"
                )
            else:
                my_logger.info("Critical sinks: None detected")

        my_logger.info("=== END ANALYSIS RESULTS ===")

    def _update_state_taint_score(self, state, called_name, is_tainted):
        """Enhanced taint scoring using configurable constants"""
        current_score = state.globals.get("taint_score", 0)
        
        if is_tainted:
            if called_name in INPUT_FUNCTION_NAMES:
                current_score += TAINT_SCORE_INPUT_FUNCTION
            else:
                current_score += TAINT_SCORE_TAINTED_CALL
        else:
            current_score += TAINT_SCORE_FUNCTION_CALL

        # Apply decay factor
        current_score *= TAINT_SCORE_DECAY_FACTOR
        
        # Apply minimum score for tainted states
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

    trace_guard = TraceGuard(binary_path=args.binary_path, args=vars(args))
    result = trace_guard.run_analysis()

    if not result.success:
        my_logger.critical(f"Analysis failed: {result.error_message}")
        sys.exit(1)

    sys.exit(0)
