import json
from datetime import datetime, timezone

class BlastRadiusAnalyzer:
    """
    Analyzes the potential impact and lateral movement paths
    from a compromised host and user.
    """
    def __init__(self):
        pass

    def analyze(self, host: str, user: str) -> dict:
        """
        Given a compromised host and user, calculates the blast radius.
        """
        # In a real environment, this would query active directory, network segments, etc.
        # This is a basic simulation of blast radius generation.
        return {
            "affected_hosts": [f"{host}-lateral-1", f"{host}-lateral-2"],
            "affected_users": [user, f"{user}_admin"],
            "lateral_paths": [f"{host} -> {host}-lateral-1", f"{host} -> {host}-lateral-2"],
            "blast_radius_score": 85.0
        }

class AttackGraphEngine:
    """
    Builds a directed attack graph and analyzes blast radius for incidents.
    Output is compatible with graph visualization libraries like Cytoscape.js.
    """
    def __init__(self):
        self.blast_analyzer = BlastRadiusAnalyzer()

    def build_attack_graph(self, incident: dict) -> dict:
        """
        Builds a directed graph of the attack chain from an incident record.
        """
        nodes = []
        edges = []
        
        telemetry = incident.get('telemetry', {})
        containment = incident.get('containment_action', {})
        observables_list = incident.get('observables', [])
        risk = incident.get('risk_assessment', {})
        details = telemetry.get('details', {})
        
        # Extract entities from actual CyberPulse incident schema
        attacker_ip = telemetry.get('source_ip', 'unknown_ip')
        target_host = telemetry.get('computer_name', 'unknown_host')
        parent_process = details.get('ParentImage', details.get('ParentCommandLine', ''))
        child_process = details.get('SourceImage', details.get('Image', ''))
        target_process = details.get('TargetImage', '')
        user_account = telemetry.get('user', 'unknown_user')
        containment_act = containment.get('action_type', 'none')
        
        base_risk = risk.get('final_score', 0.0)

        # Helper to add node
        def add_node(node_id: str, label: str, n_type: str, metadata: dict = None, score: float = 0.0):
            if not node_id or node_id == 'none':
                return
            nodes.append({
                'id': node_id,
                'label': label,
                'type': n_type,
                'metadata': metadata or {},
                'risk_score': score
            })
            
        # Helper to add edge
        def add_edge(source: str, target: str):
            if not source or not target or source == 'none' or target == 'none':
                return
            edges.append({
                'id': f"{source}->{target}",
                'source': source,
                'target': target
            })
            
        # Create nodes
        add_node(attacker_ip, f"Attacker: {attacker_ip}", 'attacker', {}, base_risk)
        add_node(target_host, f"Host: {target_host}", 'host', {}, base_risk)
        add_node(user_account, f"User: {user_account}", 'user', {}, base_risk)
        
        if parent_process:
            add_node(f"parent:{parent_process}", parent_process.split('\\')[-1] if '\\' in parent_process else parent_process, 'process', {}, base_risk)
        
        if child_process:
            add_node(f"child:{child_process}", child_process.split('\\')[-1] if '\\' in child_process else child_process, 'process', {}, base_risk)
        
        if target_process:
            add_node(f"target:{target_process}", target_process.split('\\')[-1] if '\\' in target_process else target_process, 'process', {}, base_risk)
            
        if containment_act and containment_act != 'none':
            add_node(f"contain:{containment_act}", containment_act, 'containment', {}, base_risk)

        # Add observable nodes
        for obs in observables_list:
            add_node(f"obs:{obs.get('value', '')}", f"{obs.get('type', '')}: {obs.get('value', '')}", 'observable', obs, base_risk)
        
        # Create edges: attacker_ip -> target_host -> parent -> child -> target -> containment
        add_edge(attacker_ip, target_host)
        add_edge(target_host, user_account)
        
        if parent_process:
            add_edge(user_account, f"parent:{parent_process}")
            if child_process:
                add_edge(f"parent:{parent_process}", f"child:{child_process}")
                if target_process:
                    add_edge(f"child:{child_process}", f"target:{target_process}")
                    add_edge(f"target:{target_process}", f"contain:{containment_act}")
                else:
                    add_edge(f"child:{child_process}", f"contain:{containment_act}")
            else:
                add_edge(f"parent:{parent_process}", f"contain:{containment_act}")
        elif child_process:
            add_edge(user_account, f"child:{child_process}")
            if target_process:
                add_edge(f"child:{child_process}", f"target:{target_process}")
                add_edge(f"target:{target_process}", f"contain:{containment_act}")
            else:
                add_edge(f"child:{child_process}", f"contain:{containment_act}")
        else:
            add_edge(user_account, f"contain:{containment_act}")
            
        return {
            'nodes': nodes,
            'edges': edges
        }

    def analyze_blast_radius(self, incident: dict) -> dict:
        """
        Calculates the blast radius for a given incident.
        """
        telemetry = incident.get('telemetry', {})
        host = telemetry.get('host', 'unknown_host')
        user = telemetry.get('user', 'unknown_user')
        return self.blast_analyzer.analyze(host, user)

if __name__ == '__main__':
    sample_incident = {
        'telemetry': {
            'host': 'WIN-SRV-01',
            'parent_process': 'explorer.exe',
            'process': 'cmd.exe',
            'target_process': 'lsass.exe',
            'user': 'jsmith'
        },
        'rule': {'name': 'LSASS Memory Dump'},
        'threat_intel': {'apt': 'APT29'},
        'containment_action': {'action': 'Isolate Host'},
        'observables': {'attacker_ip': '198.51.100.4'},
        'risk_assessment': {'risk_score': 95}
    }
    
    engine = AttackGraphEngine()
    
    print("=== Attack Graph ===")
    graph = engine.build_attack_graph(sample_incident)
    print(json.dumps(graph, indent=2))
    
    print("\n=== Blast Radius ===")
    blast_radius = engine.analyze_blast_radius(sample_incident)
    print(json.dumps(blast_radius, indent=2))
