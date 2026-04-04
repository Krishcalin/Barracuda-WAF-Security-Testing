"""Network configuration security checks."""

import logging
from utils.config_helper import safe_int, deep_get, extract_config

logger = logging.getLogger(__name__)


class NetworkChecker:
    """Assess network configuration — management access, HA, VLANs,
    interface security."""

    def __init__(self, api_client):
        self.api = api_client
        self.findings = []

    def run_all(self):
        logger.info("Running network configuration checks...")
        interfaces = self.api.get_network_interfaces()
        vlans = self.api.get_vlans()
        cluster = self.api.get_cluster_config()
        admin_cfg = self.api.get_admin_config()
        cfg = extract_config(admin_cfg) if isinstance(admin_cfg, dict) else {}

        self._check_management_interface(interfaces, cfg)
        self._check_vlan_separation(vlans)
        self._check_ha_configuration(cluster)
        self._check_management_protocols(cfg)
        self._check_snmp_security(cfg)
        self._check_dns_config(cfg)
        self._check_ntp_config(cfg)
        self._check_interface_security(interfaces)

        return self.findings

    def _check_management_interface(self, interfaces, cfg):
        mgmt_port = cfg.get("management-port", cfg.get("web-interface-port", ""))
        if isinstance(mgmt_port, str) and mgmt_port in ("80", "8080"):
            self.findings.append({
                "id": "NET-001",
                "title": f"Management interface on unencrypted port {mgmt_port}",
                "severity": "CRITICAL",
                "category": "Network",
                "resource": "Management Interface",
                "actual": f"HTTP port {mgmt_port}",
                "expected": "HTTPS port 8443",
                "recommendation": "Configure the management interface to use HTTPS (port 8443) only",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin -H 'Authorization: Basic <token>' -d \"{'management-port':'8443'}'''"
            })
        mgmt_iface = cfg.get("management-interface", "")
        if not mgmt_iface or mgmt_iface == "WAN":
            self.findings.append({
                "id": "NET-002",
                "title": "Management interface accessible on WAN/data interface",
                "severity": "HIGH",
                "category": "Network",
                "resource": "Management Interface",
                "actual": mgmt_iface or "Default (WAN)",
                "expected": "Dedicated management interface or VLAN",
                "recommendation": "Bind management interface to a dedicated management network or VLAN, not the WAN/data interface",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin -H 'Authorization: Basic <token>' -d \"{'management-interface':'MGMT'}'''"
            })

    def _check_vlan_separation(self, vlans):
        if not vlans:
            self.findings.append({
                "id": "NET-003",
                "title": "No VLAN segmentation configured",
                "severity": "MEDIUM",
                "category": "Network",
                "resource": "VLANs",
                "actual": "No VLANs",
                "expected": "VLAN segmentation for management, data, and HA traffic",
                "recommendation": "Implement VLAN segmentation to separate management, data, and HA traffic",
                "remediation_cmd": "Configure VLANs via WAF management console: BASIC > IP Configuration > VLANs"
            })

    def _check_ha_configuration(self, cluster):
        if isinstance(cluster, dict):
            data = extract_config(cluster)
            enabled = data.get("status", data.get("ha-mode", data.get("enabled", "")))
            if isinstance(enabled, str) and enabled.lower() in ("off", "disabled", "standalone", ""):
                self.findings.append({
                    "id": "NET-004",
                    "title": "High Availability (HA) not configured",
                    "severity": "MEDIUM",
                    "category": "Network",
                    "resource": "HA/Cluster",
                    "actual": "Standalone mode",
                    "expected": "Active-Passive or Active-Active HA",
                    "recommendation": "Configure HA clustering for redundancy to prevent single point of failure",
                    "remediation_cmd": "Configure HA via WAF management console: ADVANCED > High Availability"
                })
            else:
                heartbeat_enc = data.get("heartbeat-encryption", data.get("cluster-encryption", ""))
                if isinstance(heartbeat_enc, str) and heartbeat_enc.lower() in ("off", "no", "disabled", ""):
                    self.findings.append({
                        "id": "NET-005",
                        "title": "HA heartbeat communication not encrypted",
                        "severity": "HIGH",
                        "category": "Network",
                        "resource": "HA/Cluster",
                        "actual": "Heartbeat unencrypted",
                        "expected": "Encrypted heartbeat",
                        "recommendation": "Enable encryption for HA heartbeat traffic to prevent cluster hijacking",
                        "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/cluster -H 'Authorization: Basic <token>' -d \"{'heartbeat-encryption':'on'}'''"
                    })
        else:
            self.findings.append({
                "id": "NET-004",
                "title": "HA configuration not found",
                "severity": "MEDIUM",
                "category": "Network",
                "resource": "HA/Cluster",
                "actual": "No HA configuration",
                "expected": "HA clustering configured",
                "recommendation": "Configure HA for production environments to ensure availability",
                "remediation_cmd": "Configure HA via WAF management console: ADVANCED > High Availability"
            })

    def _check_management_protocols(self, cfg):
        ssh = cfg.get("ssh-enabled", cfg.get("ssh", ""))
        if isinstance(ssh, str) and ssh.lower() in ("on", "yes", "enabled"):
            ssh_port = cfg.get("ssh-port", "22")
            if str(ssh_port) == "22":
                self.findings.append({
                    "id": "NET-006",
                    "title": "SSH running on default port 22",
                    "severity": "LOW",
                    "category": "Network",
                    "resource": "SSH",
                    "actual": "Port 22",
                    "expected": "Non-standard SSH port",
                    "recommendation": "Change SSH to a non-standard port to reduce automated scanning exposure",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin -H 'Authorization: Basic <token>' -d \"{'ssh-port':'2222'}'''"
                })

        telnet = cfg.get("telnet-enabled", cfg.get("telnet", ""))
        if isinstance(telnet, str) and telnet.lower() in ("on", "yes", "enabled"):
            self.findings.append({
                "id": "NET-007",
                "title": "Telnet management access enabled",
                "severity": "CRITICAL",
                "category": "Network",
                "resource": "Telnet",
                "actual": "Telnet enabled",
                "expected": "Telnet disabled",
                "recommendation": "Disable Telnet immediately — it transmits credentials in plaintext. Use SSH instead",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin -H 'Authorization: Basic <token>' -d \"{'telnet-enabled':'off'}'''"
            })

    def _check_snmp_security(self, cfg):
        snmp = cfg.get("snmp", cfg.get("snmp-configuration", {}))
        if isinstance(snmp, dict) and snmp:
            version = snmp.get("version", "")
            if isinstance(version, str) and version in ("v1", "v2", "v2c", "1", "2"):
                self.findings.append({
                    "id": "NET-008",
                    "title": f"Insecure SNMP version: {version}",
                    "severity": "HIGH",
                    "category": "Network",
                    "resource": "SNMP",
                    "actual": f"SNMP {version}",
                    "expected": "SNMP v3 with authentication and encryption",
                    "recommendation": "Upgrade to SNMPv3 with authentication (SHA) and encryption (AES) for secure monitoring",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin/snmp -H 'Authorization: Basic <token>' -d \"{'version':'v3'}'''"
                })
            community = snmp.get("community", snmp.get("community-string", ""))
            if isinstance(community, str) and community.lower() in ("public", "private", "community"):
                self.findings.append({
                    "id": "NET-009",
                    "title": f"Default SNMP community string: '{community}'",
                    "severity": "HIGH",
                    "category": "Network",
                    "resource": "SNMP",
                    "actual": f"Community: {community}",
                    "expected": "Strong, unique community string",
                    "recommendation": "Change the SNMP community string from default to a complex, unique value",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin/snmp -H 'Authorization: Basic <token>' -d \"{'community':'<STRONG_STRING>'}'''"
                })

    def _check_dns_config(self, cfg):
        dns = cfg.get("dns-servers", cfg.get("name-servers", []))
        if isinstance(dns, list) and len(dns) < 2:
            self.findings.append({
                "id": "NET-010",
                "title": f"Only {len(dns)} DNS server configured",
                "severity": "LOW",
                "category": "Network",
                "resource": "DNS",
                "actual": f"{len(dns)} DNS server(s)",
                "expected": "At least 2 DNS servers for redundancy",
                "recommendation": "Configure at least two DNS servers for redundancy",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin -H 'Authorization: Basic <token>' -d \"{'ntp-servers':['pool.ntp.org','time.nist.gov']}'''"
            })

    def _check_ntp_config(self, cfg):
        ntp = cfg.get("ntp-servers", cfg.get("ntp", []))
        if not ntp:
            self.findings.append({
                "id": "NET-010",
                "title": "NTP not configured",
                "severity": "MEDIUM",
                "category": "Network",
                "resource": "NTP",
                "actual": "No NTP servers configured",
                "expected": "NTP configured for accurate timestamps",
                "recommendation": "Configure NTP servers for accurate time synchronization — critical for log correlation and certificate validation",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin -H 'Authorization: Basic <token>' -d \"{'ntp-servers':['pool.ntp.org','time.nist.gov']}'''"
            })

    def _check_interface_security(self, interfaces):
        for iface in interfaces:
            name = iface.get("name", iface.get("interface-name", "unknown"))
            status = iface.get("status", iface.get("link-state", ""))
            if isinstance(status, str) and status.lower() in ("up", "active"):
                mtu = iface.get("mtu", 0)
                try:
                    mtu = int(mtu)
                except (ValueError, TypeError):
                    mtu = 0
                if mtu > 9000:
                    self.findings.append({
                        "id": "NET-010",
                        "title": f"Jumbo frames enabled on {name} (MTU: {mtu})",
                        "severity": "INFO",
                        "category": "Network",
                        "resource": name,
                        "actual": f"MTU {mtu}",
                        "expected": "Standard MTU 1500 unless jumbo frames required",
                        "recommendation": "Verify jumbo frames are intentional — they can cause fragmentation issues and potential security risks",
                        "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin -H 'Authorization: Basic <token>' -d \"{'ntp-servers':['pool.ntp.org','time.nist.gov']}'''"
                    })
