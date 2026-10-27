"""
graph_service.py
----------------
Builds and analyzes scam syndicate entity networks using NetworkX.
Connects companies, phone numbers, UPI IDs, and email domains across scam reports.
Identifies syndicate clusters using connected components and flags nexus nodes.
"""
from typing import Dict, List, Any
import networkx as nx


def build_network_graph(reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Constructs a graph of interconnected fraud entities (vis-network format).
    """
    G = nx.Graph()
    for rep in reports:
        company = (rep.get("company_name") or "").strip()
        phone = (rep.get("phone") or "").strip()
        email = (rep.get("email") or "").strip()
        upi = (rep.get("upi_id") or "").strip()
        domain = (rep.get("domain") or "").strip()

        entities = []
        if company:
            G.add_node(company, label=company, group="company", title=f"Company: {company}")
            entities.append(company)
        if phone:
            G.add_node(phone, label=phone, group="phone", title=f"Phone: {phone}")
            entities.append(phone)
        if email:
            G.add_node(email, label=email, group="email", title=f"Email: {email}")
            entities.append(email)
        if upi:
            G.add_node(upi, label=upi, group="upi", title=f"UPI ID: {upi}")
            entities.append(upi)
        if domain:
            G.add_node(domain, label=domain, group="domain", title=f"Domain: {domain}")
            entities.append(domain)

        # Interconnect all entities in the report
        for i in range(len(entities)):
            for j in range(i + 1, len(entities)):
                G.add_edge(entities[i], entities[j])

    nodes = []
    for node, data in G.nodes(data=True):
        degree = G.degree[node]
        nodes.append({
            "id": node,
            "label": data.get("label", node),
            "group": data.get("group", "entity"),
            "title": data.get("title", node),
            "value": degree,
            "degree": degree
        })

    edges = []
    for u, v in G.edges():
        edges.append({
            "from": u,
            "to": v
        })

    return {"nodes": nodes, "edges": edges}


def get_syndicate_clusters(reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extracts connected syndicate clusters using NetworkX connected components.
    """
    G = nx.Graph()
    for rep in reports:
        company = (rep.get("company_name") or "").strip()
        phone = (rep.get("phone") or "").strip()
        email = (rep.get("email") or "").strip()
        upi = (rep.get("upi_id") or "").strip()
        domain = (rep.get("domain") or "").strip()

        entities = [e for e in [company, phone, email, upi, domain] if e]
        for e in entities:
            G.add_node(e)
        for i in range(len(entities)):
            for j in range(i + 1, len(entities)):
                G.add_edge(entities[i], entities[j])

    syndicates = []
    components = sorted(nx.connected_components(G), key=len, reverse=True)
    for idx, comp in enumerate(components, start=1):
        if len(comp) < 2:
            continue
        members = list(comp)
        kingpin = max(members, key=lambda n: G.degree[n]) if members else ""
        syndicates.append({
            "syndicate_id": f"SYN-{idx:03d}",
            "name": f"Syndicate Cluster #{idx}",
            "nodes_count": len(members),
            "members": members,
            "kingpin_node": kingpin,
            "threat_level": "High" if len(members) >= 5 else "Medium"
        })

    return syndicates
