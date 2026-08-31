"""Entity Behaviour Graph Engine (Member 3).

Maintains a directed temporal graph representing relationships between
entities (Hosts, IPs, Domains), protocol events, detection signals, and incidents.
Supports subgraph queries, incident tracing, and D3.js-compatible export.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Any, Union
from enum import Enum


class NodeType(str, Enum):
    HOST_IP = "HOST_IP"
    EXTERNAL_IP = "EXTERNAL_IP"
    DOMAIN = "DOMAIN"
    SIGNAL = "SIGNAL"
    INCIDENT = "INCIDENT"


class EdgeType(str, Enum):
    COMMUNICATES_WITH = "COMMUNICATES_WITH"
    RESOLVED_DOMAIN = "RESOLVED_DOMAIN"
    GENERATED_SIGNAL = "GENERATED_SIGNAL"
    TARGETED_BY = "TARGETED_BY"
    PART_OF_INCIDENT = "PART_OF_INCIDENT"


class GraphNode:
    """Represents a vertex in the Entity Behaviour Graph."""

    def __init__(self, node_id: str, node_type: Union[NodeType, str], properties: Optional[Dict[str, Any]] = None):
        self.id = node_id
        self.type = node_type.value if hasattr(node_type, "value") else str(node_type)
        self.properties = properties or {}
        self.created_iso = datetime.now(timezone.utc).isoformat()
        self.updated_iso = self.created_iso

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "properties": self.properties,
            "created_iso": self.created_iso,
            "updated_iso": self.updated_iso,
        }


class GraphEdge:
    """Represents a directed relationship between two graph nodes."""

    def __init__(
        self,
        source_id: str,
        target_id: str,
        edge_type: Union[EdgeType, str],
        weight: float = 1.0,
        properties: Optional[Dict[str, Any]] = None,
    ):
        self.source = source_id
        self.target = target_id
        self.type = edge_type.value if hasattr(edge_type, "value") else str(edge_type)
        self.weight = weight
        self.properties = properties or {}
        self.timestamp_iso = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.type,
            "weight": self.weight,
            "properties": self.properties,
            "timestamp_iso": self.timestamp_iso,
        }


class EntityBehaviourGraph:
    """Directed temporal graph engine for multi-signal correlation and entity investigation."""

    def __init__(self, max_nodes: int = 5000):
        self.max_nodes = max_nodes
        self.nodes: Dict[str, GraphNode] = {}
        self.out_edges: Dict[str, List[GraphEdge]] = defaultdict(list)
        self.in_edges: Dict[str, List[GraphEdge]] = defaultdict(list)

    def add_node(self, node_id: str, node_type: Union[NodeType, str], properties: Optional[Dict[str, Any]] = None) -> GraphNode:
        """Add or update a node in the graph."""
        if node_id in self.nodes:
            node = self.nodes[node_id]
            if properties:
                node.properties.update(properties)
            node.updated_iso = datetime.now(timezone.utc).isoformat()
            return node

        if len(self.nodes) >= self.max_nodes:
            # Prune oldest node
            oldest_id = min(self.nodes, key=lambda k: self.nodes[k].updated_iso)
            self.remove_node(oldest_id)

        node = GraphNode(node_id, node_type, properties)
        self.nodes[node_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: Union[EdgeType, str],
        weight: float = 1.0,
        properties: Optional[Dict[str, Any]] = None,
    ) -> GraphEdge:
        """Add a directed edge between two nodes. Creates nodes if they do not exist."""
        if source_id not in self.nodes:
            self.add_node(source_id, NodeType.HOST_IP)
        if target_id not in self.nodes:
            self.add_node(target_id, NodeType.EXTERNAL_IP)

        edge = GraphEdge(source_id, target_id, edge_type, weight, properties)
        self.out_edges[source_id].append(edge)
        self.in_edges[target_id].append(edge)
        return edge

    def remove_node(self, node_id: str) -> None:
        """Remove a node and its incident edges."""
        if node_id in self.nodes:
            del self.nodes[node_id]
            self.out_edges.pop(node_id, None)
            self.in_edges.pop(node_id, None)
            # Remove any edges referencing this node
            for src in list(self.out_edges.keys()):
                self.out_edges[src] = [e for e in self.out_edges[src] if e.target != node_id]
            for tgt in list(self.in_edges.keys()):
                self.in_edges[tgt] = [e for e in self.in_edges[tgt] if e.source != node_id]

    def get_entity_subgraph(self, entity_id: str, max_depth: int = 2) -> Dict[str, Any]:
        """Extract neighborhood subgraph for an entity up to max_depth hops."""
        visited_nodes: Set[str] = set()
        seen_edges: Set[tuple[str, str, str]] = set()
        subgraph_edges: List[GraphEdge] = []

        queue = [(entity_id, 0)]
        visited_nodes.add(entity_id)

        while queue:
            curr_id, depth = queue.pop(0)
            if depth >= max_depth:
                continue

            for edge in self.out_edges.get(curr_id, []):
                edge_key = (edge.source, edge.target, edge.type)
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    subgraph_edges.append(edge)
                if edge.target not in visited_nodes:
                    visited_nodes.add(edge.target)
                    queue.append((edge.target, depth + 1))

            for edge in self.in_edges.get(curr_id, []):
                edge_key = (edge.source, edge.target, edge.type)
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    subgraph_edges.append(edge)
                if edge.source not in visited_nodes:
                    visited_nodes.add(edge.source)
                    queue.append((edge.source, depth + 1))

        nodes_list = [self.nodes[n_id].to_dict() for n_id in visited_nodes if n_id in self.nodes]
        edges_list = [e.to_dict() for e in subgraph_edges]

        return {"nodes": nodes_list, "edges": edges_list}

    def export_d3_format(self) -> Dict[str, Any]:
        """Export complete graph in standard D3 force-directed graph JSON schema."""
        nodes = [node.to_dict() for node in self.nodes.values()]
        edges = []
        for src, edge_list in self.out_edges.items():
            for e in edge_list:
                edges.append(e.to_dict())
        return {"nodes": nodes, "links": edges}
