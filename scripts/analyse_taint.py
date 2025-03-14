import angr
import claripy
from pathlib import Path

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"
BIN_TO_ANALYZE = "tainted_vs_untainted_branching"
MAX_DEPTH = 100


def check_unconstrained(state):
    """
    This callback is triggered before every function call.
    It checks if a specific register (e.g., RAX) is unconstrained, meaning it may have multiple possible values.
    """
    rax_val = state.regs.rax
    possible_values = state.solver.eval_upto(rax_val, 2)
    if len(possible_values) > 1:
        print(f"Unconstrained value in RAX at 0x{state.addr}: {possible_values}")


def main():
    bin_path = EXAMPLES_DIR / BIN_TO_ANALYZE
    proj = angr.Project(bin_path, auto_load_libs=False)
    sym_arg = claripy.BVS("sym_arg", 8 * 10)
    state = proj.factory.full_init_state(args=[str(bin_path), sym_arg])
    state.inspect.b("call", when=angr.BP_BEFORE, action=check_unconstrained)
    simgr = proj.factory.simulation_manager(state)

    while simgr.active:
        simgr.active = [s for s in simgr.active if s.history.depth <= MAX_DEPTH]
        if not simgr.active:
            break
        simgr.step()


if __name__ == "__main__":
    main()
