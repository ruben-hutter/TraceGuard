import networkx as nx
from schnauzer import VisualizationClient


def generate_and_visualize_graph(project, func_info_map, my_logger):
    """
    Builds a call graph and sends it to the Schnauzer client for visualization.
    Tainted nodes and edges are colored red, others are blue.
    """
    my_logger.info("Generating call graph for visualization...")
    G = nx.DiGraph()

    type_color_map = {
        "Tainted": "#FF0000",  # Red
        "Normal": "#0000FF",  # Blue
    }

    def add_node_to_graph(node_name, node_address=None):
        if node_name not in added_nodes:
            node_type = "Tainted" if node_name in tainted_functions else "Normal"
            G.add_node(
                node_name,
                type=node_type,
                address=node_address if node_address else "N/A",
            )
            added_nodes.add(node_name)

    added_nodes = set()

    tainted_functions = project.tainted_functions
    for caller, callee in project.tainted_edges:
        tainted_functions.add(caller)
        tainted_functions.add(callee)

    for func_addr, func_details in func_info_map.items():
        func_name = func_details["name"]
        add_node_to_graph(func_name, f"{func_addr:#x}")

    if hasattr(project.kb, "callgraph"):
        for caller_addr, callee_addr in project.kb.callgraph.edges():
            caller_name = func_info_map.get(caller_addr, {}).get(
                "name", f"sub_{caller_addr:#x}"
            )
            callee_name = func_info_map.get(callee_addr, {}).get(
                "name", f"sub_{callee_addr:#x}"
            )

            # Filtering Logic to clean up Graph
            if caller_name == callee_name:
                continue
            if "Unresolvable" in caller_name or "Unresolvable" in callee_name:
                continue

            add_node_to_graph(caller_name, f"{caller_addr:#x}")
            add_node_to_graph(callee_name, f"{callee_addr:#x}")

            edge_type = (
                "Tainted"
                if (caller_name, callee_name) in project.tainted_edges
                else "Normal"
            )
            G.add_edge(caller_name, callee_name, type=edge_type)

    
    # Filtering Logic for Disconnected Components
    main_node_name = func_info_map.get(project.entry, {}).get("name", "main")
    if not G.has_node(main_node_name):
        my_logger.warning(f"Main node '{main_node_name}' not found in the graph. Cannot filter by main component.")
    else:
        # Find the weakly connected components
        components = list(nx.weakly_connected_components(G))
        main_component_nodes = None
        for component in components:
            if main_node_name in component:
                main_component_nodes = component
                break
        
        if main_component_nodes:
            # Create a subgraph containing only the main component
            filtered_G = G.subgraph(main_component_nodes).copy()
            my_logger.debug(f"Filtered graph to show only the main component (containing '{main_node_name}'). Original nodes: {len(G.nodes)}, Filtered nodes: {len(filtered_G.nodes)}")
            G = filtered_G # Replace the original graph with the filtered one
        else:
            my_logger.warning(f"Could not find a connected component containing '{main_node_name}'. No filtering applied.")

    my_logger.debug("Sending graph to Schnauzer visualization client...")
    try:
        viz_client = VisualizationClient()
        viz_client.send_graph(
            G, "Taint Analysis Call Graph", type_color_map=type_color_map
        )
        my_logger.info("Graph successfully sent.")
    except Exception as e:
        my_logger.error(f"Failed to send graph to visualization client: {e}")
