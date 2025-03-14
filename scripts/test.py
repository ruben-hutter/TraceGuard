import angr
from pathlib import Path
import networkx as nx

def extract_vars(expr):
    """
    Recursively extract variable dependencies from a VEX expression.
    This function looks for read-from-temporary expressions (Iex_RdTmp).
    """
    uses = []
    if hasattr(expr, "tag"):
        # Check if the expression is a read from a temporary (e.g. Iex_RdTmp)
        if expr.tag == "Iex_RdTmp":
            uses.append("tmp_{}".format(expr.tmp))
    # Recursively check for child expressions (if available)
    if hasattr(expr, "child_expressions"):
        for child in expr.child_expressions:
            uses.extend(extract_vars(child))
    # Also check for args (another way of nesting)
    if hasattr(expr, "args"):
        for child in expr.args:
            uses.extend(extract_vars(child))
    return uses

# Set the binary path to the tainted_vs_untainted_branching binary
BIN_PATH = (
    Path(__file__).resolve().parent.parent
    / "examples"
    / "tainted_vs_untainted_branching"
)

# Load the binary without auto-loading libraries for a focused analysis
proj = angr.Project(BIN_PATH, auto_load_libs=False)

# Create an initial state with options to avoid unconstrained values
state = proj.factory.entry_state(
    options={
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
    }
)

# Generate a normalized control flow graph (CFG)
cfg = proj.analyses.CFGFast(normalize=True)

# Locate the 'main' function in the binary
main_func = cfg.kb.functions.get("main")
if main_func is None:
    raise Exception("Could not locate 'main' in the binary.")

# Create a Data Dependency Graph (DDG) using NetworkX
ddg_graph = nx.DiGraph()

# Iterate over each block in the main function
for block in main_func.blocks:
    # Iterate over each VEX statement in the block
    for stmt in block.vex.statements:
        # Process temporary writes (WrTmp)
        if stmt.tag == "Ist_WrTmp":
            lhs = "tmp_{}".format(stmt.tmp)
            ddg_graph.add_node(lhs)
            uses = extract_vars(stmt.data)
            for u in uses:
                ddg_graph.add_node(u)
                ddg_graph.add_edge(u, lhs)
        # Process register writes (Put)
        elif stmt.tag == "Ist_Put":
            lhs = "reg_{:x}".format(stmt.offset)
            ddg_graph.add_node(lhs)
            uses = extract_vars(stmt.data)
            for u in uses:
                ddg_graph.add_node(u)
                ddg_graph.add_edge(u, lhs)

print("Data Dependency Graph (DDG) edges:")
for edge in ddg_graph.edges():
    print(edge)

