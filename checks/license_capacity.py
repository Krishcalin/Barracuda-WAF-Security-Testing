"""License utilization and capacity checks."""

import logging
from utils.config_helper import safe_int, deep_get, extract_config

logger = logging.getLogger(__name__)


class LicenseCapacityChecker:
    """Assess license status, subscription features, throughput capacity,
    service limits, and feature entitlements."""

    def __init__(self, api_client):
        self.api = api_client
        self.findings = []

    def run_all(self):
        logger.info("Running license and capacity checks...")
        sys_info = self.api.get_system_info()
        cfg = extract_config(sys_info, fallback={}) if isinstance(sys_info, dict) else {}
        license_info = self.api.get_license_info()
        license_data = extract_config(license_info, fallback={}) if isinstance(license_info, dict) else {}
        if license_data and "license" not in cfg:
            cfg["license"] = license_data
        services = self.api.get_services()

        self._check_license_status(cfg)
        self._check_throughput_capacity(cfg, services)
        self._check_feature_modules(cfg)
        self._check_service_count(cfg, services)
        self._check_advanced_threat_protection(cfg)
        self._check_vulnerability_scanner(cfg)
        self._check_active_ddos_prevention(cfg)
        self._check_ssl_offloading_capacity(cfg, services)

        return self.findings

    def _check_license_status(self, cfg):
        license_info = cfg.get("license", cfg.get("license-status", cfg.get("subscription", {})))
        if isinstance(license_info, dict):
            status = license_info.get("status", license_info.get("state", ""))
            if isinstance(status, str) and status.lower() in ("expired", "inactive", "unlicensed", "trial-expired"):
                self.findings.append({
                    "id": "LIC-001",
                    "title": f"WAF license status: {status}",
                    "severity": "CRITICAL",
                    "category": "License & Capacity",
                    "resource": "License",
                    "actual": status,
                    "expected": "Active, valid license",
                    "recommendation": "Renew the WAF license immediately — expired licenses may disable security features and leave applications unprotected",
                    "remediation_cmd": "Renew license via Barracuda Cloud Control portal or contact Barracuda support"
                })
            elif isinstance(status, str) and status.lower() == "trial":
                self.findings.append({
                    "id": "LIC-002",
                    "title": "WAF running on trial license",
                    "severity": "MEDIUM",
                    "category": "License & Capacity",
                    "resource": "License",
                    "actual": "Trial license active",
                    "expected": "Production license",
                    "recommendation": "Upgrade from trial to full production license before trial period expires to prevent service disruption",
                    "remediation_cmd": "Upgrade to production license via Barracuda Cloud Control portal"
                })
            expiry = license_info.get("expiry", license_info.get("expiry-date", license_info.get("valid-until", "")))
            if expiry:
                self.findings.append({
                    "id": "LIC-003",
                    "title": f"License expiry date: {expiry}",
                    "severity": "INFO",
                    "category": "License & Capacity",
                    "resource": "License",
                    "actual": f"License expires: {expiry}",
                    "expected": "Monitor renewal timeline",
                    "recommendation": "Plan for license renewal before expiry to avoid protection gaps",
                    "remediation_cmd": "Monitor renewal timeline via Barracuda Cloud Control portal"
                })
        elif not license_info:
            self.findings.append({
                "id": "LIC-001",
                "title": "Unable to determine license status",
                "severity": "MEDIUM",
                "category": "License & Capacity",
                "resource": "License",
                "actual": "License status unavailable",
                "expected": "Active license with valid subscription",
                "recommendation": "Verify license status in the WAF management console",
                "remediation_cmd": "Renew license via Barracuda Cloud Control portal or contact Barracuda support"
            })

    def _check_throughput_capacity(self, cfg, services):
        capacity = cfg.get("throughput", cfg.get("performance", cfg.get("bandwidth", {})))
        if isinstance(capacity, dict):
            max_throughput = capacity.get("max-throughput", capacity.get("licensed-bandwidth", 0))
            current = capacity.get("current-throughput", capacity.get("current-bandwidth", 0))
            try:
                max_t = float(max_throughput)
                curr_t = float(current)
            except (ValueError, TypeError):
                max_t = curr_t = 0
            if max_t > 0 and curr_t > 0:
                utilization = (curr_t / max_t) * 100
                if utilization > 80:
                    self.findings.append({
                        "id": "LIC-004",
                        "title": f"Throughput utilization at {utilization:.0f}%",
                        "severity": "HIGH" if utilization > 90 else "MEDIUM",
                        "category": "License & Capacity",
                        "resource": "Throughput",
                        "actual": f"{curr_t:.0f} / {max_t:.0f} Mbps ({utilization:.0f}%)",
                        "expected": "< 80% utilization for headroom",
                        "recommendation": "Throughput approaching licensed capacity — consider upgrading the WAF model or license tier to handle traffic spikes",
                        "remediation_cmd": "Upgrade WAF model or license tier via Barracuda sales"
                    })

    def _check_feature_modules(self, cfg):
        features = cfg.get("licensed-features", cfg.get("feature-modules", cfg.get("modules", {})))
        if isinstance(features, dict):
            critical_features = {
                "advanced-threat-protection": "Advanced Threat Protection (ATP)",
                "ip-reputation": "IP Reputation Database",
                "virus-scanning": "Virus Scanning / Antimalware",
                "vulnerability-remediation": "Vulnerability Remediation",
            }
            for key, label in critical_features.items():
                val = features.get(key, "")
                if isinstance(val, str) and val.lower() in ("off", "disabled", "not-licensed", "no", ""):
                    self.findings.append({
                        "id": "LIC-005",
                        "title": f"Feature not licensed: {label}",
                        "severity": "MEDIUM",
                        "category": "License & Capacity",
                        "resource": label,
                        "actual": f"{label}: {val or 'not licensed'}",
                        "expected": f"{label} licensed and active",
                        "recommendation": f"Consider licensing {label} to enhance WAF security capabilities",
                        "remediation_cmd": "License additional features via Barracuda Cloud Control portal"
                    })

    def _check_service_count(self, cfg, services):
        license_info = cfg.get("license", cfg.get("license-status", {}))
        if isinstance(license_info, dict):
            max_services = license_info.get("max-services", license_info.get("service-limit", 0))
            try:
                max_svc = int(max_services)
            except (ValueError, TypeError):
                max_svc = 0
            active_count = len(services)
            if max_svc > 0 and active_count > 0:
                utilization = (active_count / max_svc) * 100
                if utilization > 80:
                    self.findings.append({
                        "id": "LIC-006",
                        "title": f"Service count approaching license limit: {active_count}/{max_svc}",
                        "severity": "MEDIUM",
                        "category": "License & Capacity",
                        "resource": "Service Capacity",
                        "actual": f"{active_count} of {max_svc} services ({utilization:.0f}%)",
                        "expected": "< 80% of licensed service limit",
                        "recommendation": "Service count is approaching the license limit — plan for license upgrade or consolidate services",
                        "remediation_cmd": "Upgrade license tier to increase service limit"
                    })

    def _check_advanced_threat_protection(self, cfg):
        atp = cfg.get("advanced-threat-protection", cfg.get("atp", {}))
        if isinstance(atp, dict):
            enabled = atp.get("status", atp.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "LIC-007",
                    "title": "Advanced Threat Protection (ATP) disabled",
                    "severity": "HIGH",
                    "category": "License & Capacity",
                    "resource": "ATP",
                    "actual": "ATP disabled",
                    "expected": "ATP enabled for file upload scanning",
                    "recommendation": "Enable Advanced Threat Protection to scan file uploads in a cloud sandbox for zero-day malware detection",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/advanced-threat-protection -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''"
                })
        elif not atp:
            self.findings.append({
                "id": "LIC-007",
                "title": "Advanced Threat Protection not configured",
                "severity": "MEDIUM",
                "category": "License & Capacity",
                "resource": "ATP",
                "actual": "ATP not configured",
                "expected": "ATP enabled for file upload sandboxing",
                "recommendation": "Configure Advanced Threat Protection if licensed — it provides cloud-based sandboxing for uploaded files",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/advanced-threat-protection -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''"
            })

    def _check_vulnerability_scanner(self, cfg):
        vuln = cfg.get("vulnerability-scanner", cfg.get("vulnerability-remediation", {}))
        if isinstance(vuln, dict):
            enabled = vuln.get("status", vuln.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "LIC-008",
                    "title": "Built-in vulnerability scanner disabled",
                    "severity": "LOW",
                    "category": "License & Capacity",
                    "resource": "Vulnerability Scanner",
                    "actual": "Scanner disabled",
                    "expected": "Periodic vulnerability scanning",
                    "recommendation": "Enable the built-in vulnerability scanner for periodic assessment of protected web applications",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/vulnerability-scanner -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''"
                })

    def _check_active_ddos_prevention(self, cfg):
        addp = cfg.get("active-ddos-prevention", cfg.get("ddos-prevention", {}))
        if isinstance(addp, dict):
            enabled = addp.get("status", addp.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "LIC-009",
                    "title": "Active DDoS Prevention service disabled",
                    "severity": "MEDIUM",
                    "category": "License & Capacity",
                    "resource": "Active DDoS Prevention",
                    "actual": "Cloud DDoS prevention disabled",
                    "expected": "Active DDoS Prevention enabled if licensed",
                    "recommendation": "Enable Active DDoS Prevention for cloud-based volumetric DDoS mitigation if included in your license",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/active-ddos-prevention -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''"
                })

    def _check_ssl_offloading_capacity(self, cfg, services):
        ssl_perf = cfg.get("ssl-performance", cfg.get("ssl-throughput", {}))
        if isinstance(ssl_perf, dict):
            max_tps = ssl_perf.get("max-tps", ssl_perf.get("max-ssl-tps", 0))
            current_tps = ssl_perf.get("current-tps", ssl_perf.get("ssl-tps", 0))
            try:
                max_t = int(max_tps)
                curr_t = int(current_tps)
            except (ValueError, TypeError):
                max_t = curr_t = 0
            if max_t > 0 and curr_t > 0:
                utilization = (curr_t / max_t) * 100
                if utilization > 80:
                    self.findings.append({
                        "id": "LIC-010",
                        "title": f"SSL TPS approaching capacity: {utilization:.0f}%",
                        "severity": "MEDIUM",
                        "category": "License & Capacity",
                        "resource": "SSL Performance",
                        "actual": f"{curr_t} / {max_t} SSL TPS ({utilization:.0f}%)",
                        "expected": "< 80% SSL TPS utilization",
                        "recommendation": "SSL transactions per second approaching hardware limit — consider upgrading WAF model for higher SSL throughput",
                        "remediation_cmd": "Upgrade WAF model for higher SSL throughput capacity"
                    })
