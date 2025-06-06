import networkx as nx
from schnauzer import VisualizationClient

G = nx.DiGraph()

type_color_map = {
    'standard': '#FFD700',
    'Blue Path': '#0000FF',
    'Red Path': '#FF0000',
}

nodes = [
    ('Entry', {
        'description': 'Here the program starts',
        'type': 'standard'
    }),
    ('Condition', {
        'description': 'Take red if you are brave',
        'type': 'standard'
    }),
    ('If Block', {
        'description': 'good choice',
        'type': 'Red Path'
    }),
    ('Red Pill', {
        'description': 'very nice',
        'type': 'Red Path'
    }),
    ('Else Block', {
        'description': 'bad choice',
        'type': 'Blue Path'
    }),
    ('Blue Pill', {
        'description': 'not cool',
        'type': 'Blue Path'
    }),
    ('Exit', {
        'description': 'Goodbye',
        'type': 'standard'
    })
]

edges = [
    ('Entry', 'Condition', {
        'description': 'Edges can also have attributes'
    }),
    ('Condition', 'If Block', {
        'description': 'Add any attribute you want',
        'type': 'Red Path'
    }),
    ('Condition', 'Else Block', {
        'description': 'Some attributes',
        'type': 'Blue Path'
    }),
    ('If Block', 'Red Pill', {
        'description': 'They will all appear in the details panel',
        'type': 'Red Path'
    }),
    ('Else Block', 'Blue Pill', {
        'description': "like 'description', 'name' or 'type'",
        'type': 'Blue Path'
    }),
    ('Red Pill', 'Exit', {
        'description': 'but are hidden in the graph for clarity',
        'type': 'Red Path'
    }),
    ('Blue Pill', 'Exit', {
        'description': 'have special rendering',
        'type': 'Blue Path'
    }),
]

G.add_nodes_from(nodes)
G.add_edges_from(edges)

viz_client = VisualizationClient()
viz_client.send_graph(G, 'Custom Coloring!', type_color_map=type_color_map)
