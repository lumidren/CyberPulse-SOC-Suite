"""
BloodHound CE / SharpHound Schema Exporter for CyberPulse SOC Suite
Transforms the simulated Active Directory topology into BloodHound CE (v4.x/v5.x)
compatible JSON graph export files (users.json, groups.json, computers.json).
"""

import json
from datetime import datetime, timezone
from soar.identity_graph import ENTERPRISE_AD_TOPOLOGY

class BloodHoundExporter:
    """
    Exports Active Directory objects in standard SharpHound/BloodHound CE JSON schemas.
    """
    def __init__(self, topology=None):
        self.topology = topology or ENTERPRISE_AD_TOPOLOGY

    def export_users(self) -> dict:
        """Generates BloodHound-compatible users.json structure."""
        users_data = []
        domain = "CORP.LOCAL"

        for username, u in self.topology.items():
            user_entry = {
                "ObjectIdentifier": f"S-1-5-21-3829103810-1829301928-1928391829-{1000 + len(users_data)}",
                "Properties": {
                    "domain": domain,
                    "name": f"{username.upper()}@{domain}",
                    "distinguishedname": f"CN={username},CN=Users,DC=CORP,DC=LOCAL",
                    "displayname": u.get("display_name", username),
                    "enabled": u.get("enabled", True),
                    "pwdlastset": int(datetime.fromisoformat(u.get("password_last_set", "2026-01-01T00:00:00+00:00")).timestamp()),
                    "dontreqpreauth": False,
                    "hasspn": len(u.get("spn", [])) > 0,
                    "serviceprincipalnames": u.get("spn", []),
                    "unconstraineddelegation": u.get("delegation_type") == "unconstrained",
                    "trustedtoauth": u.get("delegation_type") == "constrained"
                },
                "PrimaryGroupSID": "S-1-5-21-3829103810-1829301928-1928391829-513",
                "AllowedToDelegate": [],
                "Aces": []
            }

            # Map Admin Rights as BloodHound AdminTo ACEs
            for host in u.get("admin_of", []):
                user_entry["Aces"].append({
                    "RightName": "AdminTo",
                    "PrincipalType": "Computer",
                    "PrincipalSID": f"COMP-{host}"
                })

            users_data.append(user_entry)

        return {
            "data": users_data,
            "meta": {
                "type": "users",
                "count": len(users_data),
                "version": 5
            }
        }

    def export_groups(self) -> dict:
        """Generates BloodHound-compatible groups.json structure."""
        domain = "CORP.LOCAL"
        group_members = {}

        # Collect members per group
        for username, u in self.topology.items():
            for g in u.get("groups", []):
                if g not in group_members:
                    group_members[g] = []
                group_members[g].append(f"{username.upper()}@{domain}")

        groups_data = []
        for idx, (grp_name, members) in enumerate(group_members.items()):
            group_entry = {
                "ObjectIdentifier": f"S-1-5-21-3829103810-1829301928-1928391829-{500 + idx}",
                "Properties": {
                    "domain": domain,
                    "name": f"{grp_name.upper()}@{domain}",
                    "distinguishedname": f"CN={grp_name},CN=Builtin,DC=CORP,DC=LOCAL",
                    "admincount": grp_name in ["Domain Admins", "Server Operators"]
                },
                "Members": [
                    {
                        "ObjectIdentifier": f"MEMBER-{m}",
                        "ObjectType": "User"
                    } for m in members
                ],
                "Aces": []
            }
            groups_data.append(group_entry)

        return {
            "data": groups_data,
            "meta": {
                "type": "groups",
                "count": len(groups_data),
                "version": 5
            }
        }

    def export_computers(self) -> dict:
        """Generates BloodHound-compatible computers.json structure."""
        domain = "CORP.LOCAL"
        hosts = [
            {"name": "WIN-DC01.CORP.LOCAL", "os": "Windows Server 2022 Datacenter", "critical": True},
            {"name": "WIN-WORKSTATION09.CORP.LOCAL", "os": "Windows 11 Enterprise", "critical": False},
            {"name": "CORP-FINANCE-02.CORP.LOCAL", "os": "Windows 11 Enterprise", "critical": True},
            {"name": "CORP-RDP-GW01.CORP.LOCAL", "os": "Windows Server 2022 Datacenter", "critical": True}
        ]

        computers_data = []
        for idx, h in enumerate(hosts):
            comp_entry = {
                "ObjectIdentifier": f"S-1-5-21-3829103810-1829301928-1928391829-{1100 + idx}",
                "Properties": {
                    "domain": domain,
                    "name": h["name"],
                    "distinguishedname": f"CN={h['name'].split('.')[0]},OU=Domain Controllers,DC=CORP,DC=LOCAL",
                    "operatingsystem": h["os"],
                    "enabled": True,
                    "unconstraineddelegation": h["critical"] and "DC" in h["name"]
                },
                "PrimaryGroupSID": "S-1-5-21-3829103810-1829301928-1928391829-516",
                "AllowedToDelegate": [],
                "LocalAdmins": [],
                "Sessions": []
            }
            computers_data.append(comp_entry)

        return {
            "data": computers_data,
            "meta": {
                "type": "computers",
                "count": len(computers_data),
                "version": 5
            }
        }

    def export_all(self) -> dict:
        """Generates full BloodHound CE multi-file export bundle."""
        return {
            "users": self.export_users(),
            "groups": self.export_groups(),
            "computers": self.export_computers(),
            "export_metadata": {
                "generator": "CyberPulse SOC Suite - BloodHound CE Exporter v1.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "compatible_schema": "BloodHound CE v5.x / SharpHound v4"
            }
        }

if __name__ == "__main__":
    exporter = BloodHoundExporter()
    bundle = exporter.export_all()
    print(f"[*] Exported {bundle['users']['meta']['count']} users, {bundle['groups']['meta']['count']} groups, {bundle['computers']['meta']['count']} computers.")
