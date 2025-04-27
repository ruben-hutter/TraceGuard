import networkx as nx
import matplotlib.pyplot as plt


def save_call_graph(call_graph, output_path="call_graph.png"):
    """
    Save the call graph to a file.
    """
    G = nx.DiGraph()

    for caller, callee, tainted in call_graph:
        if caller is None:
            caller = "ENTRY"
        G.add_node(caller)
        G.add_node(callee)
        G.add_edge(caller, callee, tainted=tainted)

    tainted_nodes = set()

    for u, v, d in G.edges(data=True):
        if d["tainted"]:
            tainted_nodes.add(u)

    changed = True
    while changed:
        changed = False
        for u, v, d in G.edges(data=True):
            if u in tainted_nodes and d["tainted"] and v not in tainted_nodes:
                tainted_nodes.add(v)
                changed = True

    node_colors = []
    for node in G.nodes():
        color = "red" if node in tainted_nodes else "lightblue"
        node_colors.append(color)

    plt.figure(figsize=(12, 8))
    pos = nx.nx_pydot.graphviz_layout(G, prog="dot")
    nx.draw(
        G,
        pos,
        with_labels=True,
        node_color=node_colors,
        node_size=2000,
        font_size=10,
        font_color="black",
        font_weight="bold",
        arrows=True,
    )
    plt.title("Call Graph with Tainted Nodes")
    plt.savefig(output_path)
    plt.close()
