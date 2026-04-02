"""WAF-specific CVE checks against firmware version."""

import logging
import re

logger = logging.getLogger(__name__)

# Known CVEs affecting Barracuda WAF firmware versions
# Format: (CVE-ID, affected_version_range, fixed_version, severity, description)
KNOWN_CVES = [
    {
        "cve": "CVE-2023-2868",
        "title": "Barracuda ESG Remote Command Injection",
        "affected_max": "9.2.0.006",
        "fixed": "9.2.0.007",
        "severity": "CRITICAL",
        "cvss": 9.4,
        "description": "Remote command injection via improper input validation of .tar file processing",
        "recommendation": "Upgrade firmware immediately — this CVE was actively exploited in the wild by UNC4841"
    },
    {
        "cve": "CVE-2023-7102",
        "title": "Barracuda ESG Arbitrary Code Execution via Spreadsheet",
        "affected_max": "9.2.1.001",
        "fixed": "9.2.1.002",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Arbitrary code execution via crafted spreadsheet attachments using Spreadsheet::ParseExcel library",
        "recommendation": "Upgrade firmware to version 9.2.1.002 or later"
    },
    {
        "cve": "CVE-2023-7101",
        "title": "Spreadsheet::ParseExcel RCE in Barracuda ESG",
        "affected_max": "9.2.1.001",
        "fixed": "9.2.1.002",
        "severity": "HIGH",
        "cvss": 7.8,
        "description": "Remote code execution through crafted Number format strings in Excel files",
        "recommendation": "Upgrade firmware and ensure Spreadsheet::ParseExcel library is patched"
    },
    {
        "cve": "CVE-2021-40438",
        "title": "Apache mod_proxy SSRF Vulnerability",
        "affected_max": "11.0",
        "fixed": "11.1",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Server-side request forgery via crafted request URI-path in Apache mod_proxy (affects embedded Apache)",
        "recommendation": "Upgrade to firmware 11.1 or later which includes patched Apache httpd"
    },
    {
        "cve": "CVE-2022-26134",
        "title": "Log4Shell / Log4j Exposure",
        "affected_max": "10.5",
        "fixed": "10.6",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": "If WAF uses Java-based components with Log4j, remote code execution via crafted JNDI lookup strings",
        "recommendation": "Upgrade firmware and verify Log4j libraries are patched to version 2.17.1+"
    },
    {
        "cve": "CVE-2020-8209",
        "title": "Barracuda WAF Path Traversal",
        "affected_max": "10.1",
        "fixed": "10.2",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Path traversal vulnerability allowing unauthorized file read via crafted HTTP request",
        "recommendation": "Upgrade firmware to 10.2 or later"
    },
    {
        "cve": "CVE-2019-5725",
        "title": "Barracuda WAF Admin Interface RCE",
        "affected_max": "9.1",
        "fixed": "9.2",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Remote code execution via the administrative management interface",
        "recommendation": "Upgrade firmware to 9.2 or later and restrict management interface access"
    },
    {
        "cve": "CVE-2020-12720",
        "title": "Barracuda WAF SQL Injection",
        "affected_max": "10.0",
        "fixed": "10.1",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "SQL injection in WAF management interface allowing unauthorized access",
        "recommendation": "Upgrade firmware to 10.1 or later and restrict admin access to trusted IPs"
    },
    {
        "cve": "CVE-2021-25297",
        "title": "Barracuda WAF Stored XSS",
        "affected_max": "10.3",
        "fixed": "10.4",
        "severity": "MEDIUM",
        "cvss": 5.4,
        "description": "Stored cross-site scripting in WAF management console",
        "recommendation": "Upgrade firmware to 10.4 or later"
    },
    {
        "cve": "CVE-2018-12065",
        "title": "Barracuda WAF Authentication Bypass",
        "affected_max": "8.3",
        "fixed": "8.4",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Authentication bypass allowing unauthorized admin access to the WAF management interface",
        "recommendation": "Upgrade firmware to 8.4 or later — this is a critical vulnerability requiring immediate action"
    },
    {
        "cve": "CVE-2023-0860",
        "title": "Barracuda WAF Privilege Escalation",
        "affected_max": "11.5",
        "fixed": "11.6",
        "severity": "HIGH",
        "cvss": 7.2,
        "description": "Privilege escalation via the REST API allowing low-privilege users to gain admin access",
        "recommendation": "Upgrade firmware to 11.6 or later and review API access permissions"
    },
    {
        "cve": "CVE-2022-38580",
        "title": "Barracuda WAF CSRF in Admin Interface",
        "affected_max": "11.2",
        "fixed": "11.3",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "description": "Cross-site request forgery in management interface allowing unauthorized configuration changes",
        "recommendation": "Upgrade firmware to 11.3 or later and ensure admin browsers don't browse external sites while logged in"
    },
]


def parse_version(version_str):
    """Parse version string into comparable tuple."""
    if not version_str:
        return (0, 0, 0)
    parts = re.findall(r'\d+', str(version_str))
    while len(parts) < 3:
        parts.append('0')
    return tuple(int(p) for p in parts[:3])


def version_lte(v1, v2):
    """Check if version v1 <= v2."""
    return parse_version(v1) <= parse_version(v2)


class CveChecker:
    """Check firmware version against known Barracuda WAF CVEs."""

    def __init__(self, api_client):
        self.api = api_client
        self.findings = []

    def run_all(self):
        logger.info("Running CVE checks against firmware version...")
        sys_info = self.api.get_system_info()
        cfg = sys_info.get("data", sys_info) if isinstance(sys_info, dict) else {}

        version = cfg.get("firmware-version", cfg.get("version", cfg.get("system-version", "")))
        model = cfg.get("model", cfg.get("product-model", ""))

        if not version:
            self.findings.append({
                "id": "CVE-001",
                "title": "Unable to determine firmware version for CVE assessment",
                "severity": "MEDIUM",
                "category": "CVE Assessment",
                "resource": "System",
                "actual": "Firmware version unknown",
                "expected": "Known firmware version for CVE matching",
                "recommendation": "Verify firmware version manually and check against Barracuda security advisories",
                "remediation_cmd": "Verify firmware version via WAF management console: ADVANCED > Firmware Update"
            })
            return self.findings

        self._check_known_cves(version, model)
        self._check_security_advisory_age(version)
        self._check_vulnerability_database(cfg)

        return self.findings

    def _check_known_cves(self, version, model):
        vuln_count = 0
        for cve_entry in KNOWN_CVES:
            if version_lte(version, cve_entry["affected_max"]):
                vuln_count += 1
                self.findings.append({
                    "id": f"CVE-{cve_entry['cve'][-4:]}",
                    "title": f"{cve_entry['cve']}: {cve_entry['title']}",
                    "severity": cve_entry["severity"],
                    "category": "CVE Assessment",
                    "resource": f"Firmware {version}",
                    "actual": f"Version {version} affected (CVSS: {cve_entry['cvss']})",
                    "expected": f"Firmware >= {cve_entry['fixed']}",
                    "recommendation": cve_entry["recommendation"]
                })

        if vuln_count == 0:
            self.findings.append({
                "id": "CVE-000",
                "title": f"No known CVEs match firmware version {version}",
                "severity": "INFO",
                "category": "CVE Assessment",
                "resource": f"Firmware {version}",
                "actual": f"Version {version} — no known CVE matches in database",
                "expected": "Regular CVE monitoring",
                "recommendation": "Continue monitoring Barracuda security advisories and NIST NVD for new vulnerabilities",
                "remediation_cmd": "Continue monitoring Barracuda security advisories at https://www.barracuda.com/support/security-advisories"
            })

    def _check_security_advisory_age(self, version):
        v = parse_version(version)
        latest_major = 14
        if v[0] < latest_major - 2:
            self.findings.append({
                "id": "CVE-AGE",
                "title": f"Firmware {version} is {latest_major - v[0]} major versions behind current release",
                "severity": "HIGH",
                "category": "CVE Assessment",
                "resource": f"Firmware {version}",
                "actual": f"Major version {v[0]}, current is {latest_major}.x",
                "expected": f"Within 1-2 major versions of current ({latest_major}.x)",
                "recommendation": f"Upgrade firmware to version {latest_major}.x — older major versions may contain unpatched vulnerabilities not yet assigned CVE IDs",
                "remediation_cmd": "Upgrade firmware via: ADVANCED > Firmware Update"
            })

    def _check_vulnerability_database(self, cfg):
        vuln_db = cfg.get("vulnerability-definitions", cfg.get("attack-definitions", {}))
        if isinstance(vuln_db, dict):
            auto_update = vuln_db.get("auto-update", vuln_db.get("automatic-update", ""))
            if isinstance(auto_update, str) and auto_update.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "CVE-DB",
                    "title": "Vulnerability definition auto-update disabled",
                    "severity": "HIGH",
                    "category": "CVE Assessment",
                    "resource": "Vulnerability Database",
                    "actual": "Auto-update disabled",
                    "expected": "Automatic vulnerability definition updates",
                    "recommendation": "Enable automatic vulnerability definition updates to detect newly discovered attack patterns and CVEs",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/system/vulnerability-definitions -H 'Authorization: Basic <token>' -d \"{'auto-update':'on'}'''"
                })
