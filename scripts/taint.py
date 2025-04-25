import angr
import claripy

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

    def __init__(
        self, func_address=None, func_name=None, essential=False, verbose=True, **kwargs
    ):
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
        if (
            hasattr(self.project, "_param_overrides")
            and self.func_name in self.project._param_overrides
        ):
            return self.project._param_overrides[self.func_name]

        # Check parameter count from static analysis
        if (
            hasattr(self.project, "_param_counts")
            and self.func_address in self.project._param_counts
        ):
            static_param_count = self.project._param_counts[self.func_address]
            if 1 <= static_param_count <= 6:
                return static_param_count

        # Check prototype info from angr
        func_info = self.project.kb.functions.get(self.func_address)
        if func_info and hasattr(func_info, "prototype") and func_info.prototype:
            if hasattr(func_info.prototype, "args") and func_info.prototype.args:
                proto_param_count = len(func_info.prototype.args)
                if 1 <= proto_param_count <= 6:
                    return proto_param_count

        # Default to 1 parameter for most functions
        return 1

    def _check_parameters(self, param_count):
        """Check function parameters for taint."""
        # Get calling convention registers
        cc = self.project.factory.cc()
        param_registers = getattr(
            cc, "ARG_REGS", ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        )

        if self.verbose:
            print(
                f"Checking registers for function {self.func_name}: {param_registers[:param_count]}"
            )

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
            for reg_name in [
                "rax",
                "rbx",
                "rcx",
                "rdx",
                "rsi",
                "rdi",
                "rbp",
                "rsp",
                "r8",
                "r9",
                "r10",
                "r11",
                "r12",
                "r13",
                "r14",
                "r15",
            ]:
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
        if not hasattr(value, "symbolic") or not value.symbolic:
            return False

        # Check variable names for 'stdin'
        if hasattr(value, "variables"):
            return any("stdin" in var for var in value.variables)

        return False
