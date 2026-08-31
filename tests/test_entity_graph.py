"""Unit tests for Entity Behaviour Graph Engine (Member 3)."""

import unittest
from entity.graph import EntityBehaviourGraph, NodeType, EdgeType


class TestEntityGraph(unittest.TestCase):
    def setUp(self):
        self.graph = EntityBehaviourGraph(max_nodes=50)

    def test_add_nodes_and_edges(self):
        node_src = self.graph.add_node("10.0.0.10", NodeType.HOST_IP, {"hostname": "workstation-10"})
        node_dst = self.graph.add_node("198.51.100.5", NodeType.EXTERNAL_IP)

        self.assertEqual(node_src.id, "10.0.0.10")
        self.assertEqual(node_src.type, NodeType.HOST_IP)

        edge = self.graph.add_edge("10.0.0.10", "198.51.100.5", EdgeType.COMMUNICATES_WITH, weight=2.5)
        self.assertEqual(edge.source, "10.0.0.10")
        self.assertEqual(edge.target, "198.51.100.5")
        self.assertEqual(edge.type, EdgeType.COMMUNICATES_WITH)

    def test_subgraph_extraction(self):
        # 10.0.0.20 -> sig-01 -> 198.51.100.99
        self.graph.add_node("10.0.0.20", NodeType.HOST_IP)
        self.graph.add_node("sig-01", NodeType.SIGNAL)
        self.graph.add_node("198.51.100.99", NodeType.EXTERNAL_IP)

        self.graph.add_edge("10.0.0.20", "sig-01", EdgeType.GENERATED_SIGNAL)
        self.graph.add_edge("sig-01", "198.51.100.99", EdgeType.TARGETED_BY)

        subgraph = self.graph.get_entity_subgraph("10.0.0.20", max_depth=2)
        node_ids = {n["id"] for n in subgraph["nodes"]}

        self.assertIn("10.0.0.20", node_ids)
        self.assertIn("sig-01", node_ids)
        self.assertIn("198.51.100.99", node_ids)
        self.assertEqual(len(subgraph["edges"]), 2)

    def test_d3_export_format(self):
        self.graph.add_edge("host-1", "host-2", EdgeType.COMMUNICATES_WITH)
        d3_data = self.graph.export_d3_format()

        self.assertIn("nodes", d3_data)
        self.assertIn("links", d3_data)
        self.assertEqual(len(d3_data["nodes"]), 2)
        self.assertEqual(len(d3_data["links"]), 1)


if __name__ == "__main__":
    unittest.main()
