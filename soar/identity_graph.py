"""
Active Directory Identity Blast Radius & Path Analysis Engine
Inspired by BloodHound, designed for CyberPulse.
"""

import json
from collections import deque
from datetime import datetime, timezone

# 1. Simulated enterprise AD topology
ENTERPRISE_AD_TOPOLOGY = {
    "Administrator": {
        "display_name": "Domain Administrator",
        "groups": ["Domain Admins"],
        "admin_of": ["DC01", "DC02", "EXCH01", "FS01"],
        "can_rdp_to": ["DC01", "DC02", "EXCH01", "FS01", "SQL01"],
        "delegation_type": None,
        "spn": [],
        "password_last_set": "2023-01-01T00:00:00Z",
        "enabled": True,
        "can_reset_password_of": []
    },
    "j.doe": {
        "display_name": "John Doe",
        "groups": ["Domain Users", "Finance Users"],
        "admin_of": ["WKSTN-101"],
        "can_rdp_to": ["WKSTN-101"],
        "delegation_type": None,
        "spn": [],
        "password_last_set": "2023-08-15T09:00:00Z",
        "enabled": True,
        "can_reset_password_of": []
    },
    "m.worker": {
        "display_name": "Mary Worker",
        "groups": ["Domain Users", "Helpdesk Admins"],
        "admin_of": ["WKSTN-102"],
        "can_rdp_to": ["WKSTN-102"],
        "delegation_type": None,
        "spn": [],
        "password_last_set": "2023-09-01T10:00:00Z",
        "enabled": True,
        "can_reset_password_of": ["Finance Users"]
    },
    "finance_admin": {
        "display_name": "Finance Administrator",
        "groups": ["Domain Users", "Finance Users"],
        "admin_of": ["FINAPP01"],
        "can_rdp_to": ["FINAPP01"],
        "delegation_type": None,
        "spn": [],
        "password_last_set": "2023-05-12T11:00:00Z",
        "enabled": True,
        "can_reset_password_of": []
    },
    "svc_mssql_prod": {
        "display_name": "MSSQL Service Account",
        "groups": ["Domain Users", "SQL Service Accounts"],
        "admin_of": ["SQL01", "SQL02"],
        "can_rdp_to": [],
        "delegation_type": "constrained",
        "spn": ["MSSQLSvc/SQL01.cyberpulse.local:1433", "MSSQLSvc/SQL02.cyberpulse.local:1433"],
        "password_last_set": "2021-01-01T00:00:00Z",
        "enabled": True,
        "can_reset_password_of": []
    },
    "compromised_admin": {
        "display_name": "Compromised Admin",
        "groups": ["Domain Users", "Server Operators"],
        "admin_of": ["WEB01", "WEB02"],
        "can_rdp_to": ["WEB01", "WEB02"],
        "delegation_type": "unconstrained",
        "spn": [],
        "password_last_set": "2023-06-20T14:00:00Z",
        "enabled": True,
        "can_reset_password_of": []
    },
    "soc_analyst": {
        "display_name": "SOC Analyst",
        "groups": ["Domain Users"],
        "admin_of": ["SIEM01"],
        "can_rdp_to": ["SIEM01"],
        "delegation_type": None,
        "spn": [],
        "password_last_set": "2023-09-08T08:00:00Z",
        "enabled": True,
        "can_reset_password_of": []
    },
    "backup_operator": {
        "display_name": "Backup Operator",
        "groups": ["Domain Users", "Backup Operators"],
        "admin_of": ["BACKUP01"],
        "can_rdp_to": ["BACKUP01", "DC01", "DC02"],
        "delegation_type": None,
        "spn": [],
        "password_last_set": "2023-02-15T10:00:00Z",
        "enabled": True,
        "can_reset_password_of": []
    }
}

GROUP_NESTING = {
    "Domain Admins": [],
    "Server Operators": ["Domain Admins"], # Let's say Server Ops can escalate to Domain Admins for the sake of interesting paths
    "Helpdesk Admins": [],
    "Finance Users": [],
    "Backup Operators": ["Server Operators"],
    "SQL Service Accounts": [],
    "Domain Users": []
}


class IdentityBlastRadiusEngine:
    def __init__(self, topology=ENTERPRISE_AD_TOPOLOGY, group_nesting=GROUP_NESTING):
        self.topology = topology
        self.group_nesting = group_nesting

    def get_all_nested_groups(self, start_groups):
        """Recursively find all groups a user belongs to."""
        visited = set()
        queue = deque(start_groups)
        while queue:
            current = queue.popleft()
            if current not in visited:
                visited.add(current)
                # Add nested groups if they exist in our group mapping
                for nested_group in self.group_nesting.get(current, []):
                    queue.append(nested_group)
        return list(visited)

    def get_shortest_path_to_domain_admin(self, username):
        """Find the shortest path from a user to Domain Admins using BFS."""
        if username not in self.topology:
            return None
        
        user_groups = self.topology[username].get("groups", [])
        
        if "Domain Admins" in user_groups:
            return ["Domain Admins"]

        # Queue items are (current_node, path_so_far)
        queue = deque()
        visited = set()

        for group in user_groups:
            queue.append((group, [username, group]))
            visited.add(group)
            
        # We also check if user can reset password of someone who is domain admin or can lead to it
        for target_group in self.topology[username].get("can_reset_password_of", []):
            queue.append((target_group, [username, f"ResetPassword({target_group})", target_group]))
            visited.add(target_group)

        while queue:
            current, path = queue.popleft()
            if current == "Domain Admins":
                return path

            for neighbor in self.group_nesting.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
                    
        return None

    def analyze_compromised_identity(self, username: str) -> dict:
        """Analyze the blast radius of a compromised identity."""
        if username not in self.topology:
            return {
                "compromised_user": username,
                "status": "USER_NOT_IN_TOPOLOGY",
                "direct_groups": [],
                "admin_of_hosts": [],
                "rdp_targets": [],
                "delegation_risks": None,
                "nested_group_escalation": [],
                "shortest_path_to_domain_admin": [],
                "blast_radius_score": 15,
                "affected_assets_count": 0,
                "recommended_containment": [
                    f"Investigate unknown account '{username}' for potential rogue/orphan status",
                    "Verify account origin in Active Directory",
                    "Consider disabling account pending investigation"
                ]
            }

        user_data = self.topology[username]
        direct_groups = user_data.get("groups", [])
        all_groups = self.get_all_nested_groups(direct_groups)
        
        admin_of_hosts = user_data.get("admin_of", [])
        rdp_targets = user_data.get("can_rdp_to", [])
        delegation_risks = user_data.get("delegation_type")
        
        shortest_path = self.get_shortest_path_to_domain_admin(username)
        
        # Calculate Blast Radius Score (0-100)
        score = 0
        score += len(admin_of_hosts) * 5
        score += len(rdp_targets) * 2
        
        if user_data.get("spn"):
            score += 20  # Kerberoastable
            
        if delegation_risks == "constrained":
            score += 30
        elif delegation_risks == "unconstrained":
            score += 50
            
        if shortest_path:
            # The shorter the path, the higher the risk
            path_len = len(shortest_path)
            if path_len <= 1:
                score += 100
            elif path_len == 2:
                score += 60
            elif path_len == 3:
                score += 40
            else:
                score += 20
                
        score = min(100, score) # Cap at 100
        
        affected_assets_count = len(admin_of_hosts) + len(rdp_targets)
        
        recommended_containment = [
            f"Disable account {username} immediately.",
            f"Rotate credentials for {username}.",
            f"Review logins on hosts: {', '.join(admin_of_hosts + rdp_targets)}."
        ]
        if user_data.get("spn"):
            recommended_containment.append("Investigate potential Kerberoasting activity.")
        if delegation_risks:
            recommended_containment.append(f"Review {delegation_risks} delegation usage.")

        return {
            "compromised_user": username,
            "direct_groups": direct_groups,
            "admin_of_hosts": admin_of_hosts,
            "rdp_targets": rdp_targets,
            "delegation_risks": delegation_risks,
            "nested_group_escalation": all_groups,
            "shortest_path_to_domain_admin": shortest_path,
            "blast_radius_score": score,
            "affected_assets_count": affected_assets_count,
            "recommended_containment": recommended_containment
        }

    def get_kerberos_delegation_risks(self) -> list:
        """Find all accounts with unconstrained/constrained delegation."""
        risks = []
        for username, data in self.topology.items():
            delegation = data.get("delegation_type")
            if delegation in ["constrained", "unconstrained"]:
                risks.append({
                    "username": username,
                    "delegation_type": delegation,
                    "spns": data.get("spn", []),
                    "risk_description": f"{username} has {delegation} delegation, making it a high-value target for identity theft."
                })
        return risks

    def get_shortest_path(self, from_user, to_user) -> dict:
        """Find the path from one identity to another."""
        if from_user not in self.topology or to_user not in self.topology:
            return {"error": "Source or destination user not found."}

        target_groups = self.topology[to_user].get("groups", [])
        
        # We will do a basic BFS from from_user to see if they can reach any of to_user's groups
        queue = deque()
        visited = set()
        
        for group in self.topology[from_user].get("groups", []):
            queue.append((group, [from_user, group]))
            visited.add(group)
            
        for reset_tgt in self.topology[from_user].get("can_reset_password_of", []):
            queue.append((reset_tgt, [from_user, f"ResetPassword({reset_tgt})", reset_tgt]))
            visited.add(reset_tgt)

        while queue:
            current, path = queue.popleft()
            
            if current in target_groups:
                # Path found to target user's group, meaning they can reach the user's privilege level
                path.append(to_user)
                return {"path": path, "steps": len(path) - 1}

            for neighbor in self.group_nesting.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
                    
        return {"path": None, "message": "No path found."}

    def generate_identity_graph_data(self) -> dict:
        """Generate Cytoscape.js/Vis.js compatible node and edge data."""
        nodes = []
        edges = []
        
        for username, data in self.topology.items():
            nodes.append({
                "data": {
                    "id": username,
                    "label": data.get("display_name", username),
                    "type": "User"
                }
            })
            for group in data.get("groups", []):
                edges.append({
                    "data": {
                        "source": username,
                        "target": group,
                        "label": "MemberOf"
                    }
                })
            for host in data.get("admin_of", []):
                nodes.append({"data": {"id": host, "label": host, "type": "Computer"}})
                edges.append({
                    "data": {
                        "source": username,
                        "target": host,
                        "label": "AdminTo"
                    }
                })
                
        for group, parents in self.group_nesting.items():
            nodes.append({"data": {"id": group, "label": group, "type": "Group"}})
            for parent in parents:
                edges.append({
                    "data": {
                        "source": group,
                        "target": parent,
                        "label": "MemberOf"
                    }
                })
                
        # Remove duplicates from nodes
        unique_nodes = {node["data"]["id"]: node for node in nodes}.values()
                
        return {
            "nodes": list(unique_nodes),
            "edges": edges
        }


if __name__ == '__main__':
    engine = IdentityBlastRadiusEngine()
    
    print("=== Compromised Admin Analysis ===")
    analysis = engine.analyze_compromised_identity("compromised_admin")
    print(json.dumps(analysis, indent=2))
    
    print("\n=== Kerberos Delegation Risks ===")
    risks = engine.get_kerberos_delegation_risks()
    print(json.dumps(risks, indent=2))
    
    print("\n=== Shortest Path: m.worker -> Administrator ===")
    path = engine.get_shortest_path("m.worker", "Administrator")
    print(json.dumps(path, indent=2))
    
    print("\n=== Identity Graph Data ===")
    graph_data = engine.generate_identity_graph_data()
    print(f"Generated {len(graph_data['nodes'])} nodes and {len(graph_data['edges'])} edges.")
