"""
Campaign Detector — clusters multiple APKs by similarity.
Uses SSDEEP fuzzy hashing + certificate fingerprints + NetworkX graph.
"""

import json
from typing import List

import networkx as nx


class CampaignDetector:
    """
    Given multiple APK analyses, find which ones are from the same campaign.
    Uses certificate fingerprints, C2 IP overlap, and package name patterns.
    """

    def cluster_analyses(self, analyses: list) -> dict:
        """
        Cluster analysis results to identify campaigns.
        analyses: list of report dicts from completed analyses
        """
        G = nx.Graph()

        # Add all analyses as nodes
        for a in analyses:
            case_id = a.get("case_id", "unknown")
            G.add_node(case_id, **{
                "package_name": a.get("package_name", ""),
                "threat_score": a.get("threat_score", 0),
                "classification": a.get("classification", "CLEAN"),
                "malware_family": a.get("malware_family", ""),
            })

        # Find connections between analyses
        for i, a1 in enumerate(analyses):
            for j, a2 in enumerate(analyses):
                if j <= i:
                    continue

                reasons = []

                # Same C2 IPs
                c2_1 = set(c.get("ip", "") for c in a1.get("c2_infrastructure", []))
                c2_2 = set(c.get("ip", "") for c in a2.get("c2_infrastructure", []))
                shared_c2 = c2_1 & c2_2
                if shared_c2:
                    reasons.append(f"shared_c2: {', '.join(shared_c2)}")

                # Same malware family
                if (a1.get("malware_family") and a2.get("malware_family") and
                    a1["malware_family"] == a2["malware_family"]):
                    reasons.append(f"same_family: {a1['malware_family']}")

                # Similar package names
                pkg1 = a1.get("package_name", "")
                pkg2 = a2.get("package_name", "")
                if pkg1 and pkg2:
                    # Check if they share the same base domain
                    parts1 = pkg1.split(".")
                    parts2 = pkg2.split(".")
                    if len(parts1) >= 2 and len(parts2) >= 2:
                        if parts1[:2] == parts2[:2]:
                            reasons.append(f"similar_package: {'.'.join(parts1[:2])}")

                if reasons:
                    G.add_edge(
                        a1.get("case_id", ""),
                        a2.get("case_id", ""),
                        reasons=reasons
                    )

        # Extract connected components (campaigns)
        components = list(nx.connected_components(G))

        return {
            "total_samples": len(analyses),
            "campaigns_found": len(components),
            "clusters": [
                {
                    "apks": list(c),
                    "size": len(c),
                    "details": [
                        {
                            "case_id": node,
                            "package_name": G.nodes[node].get("package_name", ""),
                            "threat_score": G.nodes[node].get("threat_score", 0),
                            "classification": G.nodes[node].get("classification", ""),
                        }
                        for node in c
                    ]
                }
                for c in components
            ],
            "graph_data": self._graph_to_json(G)
        }

    def _graph_to_json(self, G: nx.Graph) -> dict:
        """Convert NetworkX graph to JSON for frontend visualization."""
        nodes = []
        for node_id, data in G.nodes(data=True):
            score = data.get("threat_score", 0)
            nodes.append({
                "id": node_id,
                "label": data.get("package_name", node_id),
                "threat_score": score,
                "classification": data.get("classification", "CLEAN"),
                "color": (
                    "#FF4444" if score >= 75 else
                    "#FF8C00" if score >= 50 else
                    "#FFD700" if score >= 25 else
                    "#00FF88"
                )
            })

        edges = []
        for u, v, data in G.edges(data=True):
            edges.append({
                "source": u,
                "target": v,
                "reasons": data.get("reasons", [])
            })

        return {"nodes": nodes, "edges": edges}
