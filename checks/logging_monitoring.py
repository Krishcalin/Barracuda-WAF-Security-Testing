"""Logging and monitoring security checks."""

import logging
from utils.config_helper import safe_int, deep_get, extract_config

logger = logging.getLogger(__name__)


class LoggingMonitoringChecker:
    """Assess logging configuration — syslog, SIEM export, audit logging,
    alert policies, log retention."""

    def __init__(self, api_client):
        self.api = api_client
        self.findings = []

    def run_all(self):
        logger.info("Running logging and monitoring checks...")
        log_cfg = self.api.get_logging_config()
        cfg = extract_config(log_cfg, fallback={}) if isinstance(log_cfg, dict) else {}
        admin_cfg = self.api.get_admin_config()
        admin = extract_config(admin_cfg, fallback={}) if isinstance(admin_cfg, dict) else {}

        self._check_syslog_forwarding(cfg)
        self._check_syslog_tls(cfg)
        self._check_web_firewall_logging(cfg)
        self._check_access_logging(cfg)
        self._check_audit_logging(admin)
        self._check_log_retention(cfg)
        self._check_siem_integration(cfg)
        self._check_alert_policies(cfg)
        self._check_system_logging(cfg)
        self._check_notification_config(cfg)

        return self.findings

    def _check_syslog_forwarding(self, cfg):
        syslog = cfg.get("syslog-servers", cfg.get("remote-syslog", cfg.get("export-logs", [])))
        if isinstance(syslog, list) and not syslog:
            self.findings.append({
                "id": "LOG-001",
                "title": "No remote syslog server configured",
                "severity": "HIGH",
                "category": "Logging & Monitoring",
                "resource": "Syslog",
                "actual": "No remote syslog",
                "expected": "At least one remote syslog server",
                "recommendation": "Configure remote syslog forwarding to a centralized log management or SIEM platform",
                "remediation_cmd": "curl -X POST https://<WAF_IP>:8443/restapi/v3.2/syslog/syslog-servers -H 'Authorization: Basic <token>' -d \"{'name':'siem-server','server':'<SIEM_IP>','port':'514'}'''"
            })
        elif isinstance(syslog, dict):
            if not syslog.get("server", syslog.get("host", "")):
                self.findings.append({
                    "id": "LOG-001",
                    "title": "Syslog server address not configured",
                    "severity": "HIGH",
                    "category": "Logging & Monitoring",
                    "resource": "Syslog",
                    "actual": "No server address",
                    "expected": "Valid syslog server configured",
                    "recommendation": "Configure a syslog server address for centralized log collection",
                    "remediation_cmd": "curl -X POST https://<WAF_IP>:8443/restapi/v3.2/syslog/syslog-servers -H 'Authorization: Basic <token>' -d \"{'name':'siem-server','server':'<SIEM_IP>','port':'514'}'''"
                })

    def _check_syslog_tls(self, cfg):
        syslog = cfg.get("syslog-servers", cfg.get("remote-syslog", []))
        servers = syslog if isinstance(syslog, list) else [syslog] if isinstance(syslog, dict) else []
        for server in servers:
            if isinstance(server, dict):
                protocol = server.get("protocol", server.get("transport", ""))
                if isinstance(protocol, str) and protocol.upper() in ("UDP", "TCP"):
                    self.findings.append({
                        "id": "LOG-002",
                        "title": f"Syslog using unencrypted {protocol.upper()} transport",
                        "severity": "MEDIUM",
                        "category": "Logging & Monitoring",
                        "resource": server.get("server", server.get("host", "Syslog Server")),
                        "actual": f"{protocol.upper()} transport",
                        "expected": "TLS-encrypted syslog (RFC 5425)",
                        "recommendation": "Configure syslog over TLS to encrypt log data in transit",
                        "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/syslog/syslog-servers/<SERVER> -H 'Authorization: Basic <token>' -d \"{'protocol':'TLS'}'''"
                    })

    def _check_web_firewall_logging(self, cfg):
        wf_log = cfg.get("web-firewall-log", cfg.get("waf-logging", cfg.get("security-logging", "")))
        if isinstance(wf_log, str) and wf_log.lower() in ("off", "no", "disabled", ""):
            self.findings.append({
                "id": "LOG-003",
                "title": "Web firewall logging disabled",
                "severity": "CRITICAL",
                "category": "Logging & Monitoring",
                "resource": "WAF Logging",
                "actual": "WAF logging disabled",
                "expected": "Full WAF event logging enabled",
                "recommendation": "Enable web firewall logging to capture all attack events, violations, and blocked requests",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/syslog -H 'Authorization: Basic <token>' -d \"{'web-firewall-log':'on'}'''"
            })
        elif isinstance(wf_log, dict):
            level = wf_log.get("level", wf_log.get("log-level", ""))
            if isinstance(level, str) and level.lower() in ("error", "critical", "none"):
                self.findings.append({
                    "id": "LOG-004",
                    "title": f"WAF logging level too restrictive: {level}",
                    "severity": "HIGH",
                    "category": "Logging & Monitoring",
                    "resource": "WAF Logging",
                    "actual": f"Level: {level}",
                    "expected": "Warning or Verbose level",
                    "recommendation": "Set WAF logging to Warning or Verbose level to capture all security-relevant events",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/syslog -H 'Authorization: Basic <token>' -d \"{'web-firewall-log-level':'verbose'}'''"
                })

    def _check_access_logging(self, cfg):
        access = cfg.get("access-log", cfg.get("http-access-log", ""))
        if isinstance(access, str) and access.lower() in ("off", "no", "disabled", ""):
            self.findings.append({
                "id": "LOG-005",
                "title": "HTTP access logging disabled",
                "severity": "HIGH",
                "category": "Logging & Monitoring",
                "resource": "Access Log",
                "actual": "Access logging disabled",
                "expected": "Access logging enabled",
                "recommendation": "Enable HTTP access logging for traffic analysis, forensics, and compliance requirements",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/syslog -H 'Authorization: Basic <token>' -d \"{'access-log':'on'}'''"
            })

    def _check_audit_logging(self, admin):
        audit = admin.get("audit-log", admin.get("admin-audit-log", ""))
        if isinstance(audit, str) and audit.lower() in ("off", "no", "disabled", ""):
            self.findings.append({
                "id": "LOG-006",
                "title": "Administrative audit logging disabled",
                "severity": "CRITICAL",
                "category": "Logging & Monitoring",
                "resource": "Audit Log",
                "actual": "Audit logging disabled",
                "expected": "Full admin action audit logging",
                "recommendation": "Enable audit logging for all administrative actions — required for accountability and compliance",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin -H 'Authorization: Basic <token>' -d \"{'audit-log':'on'}'''"
            })

    def _check_log_retention(self, cfg):
        retention = cfg.get("log-retention", cfg.get("retention-days", cfg.get("max-log-age", 0)))
        try:
            retention = int(retention)
        except (ValueError, TypeError):
            retention = 0
        if retention > 0 and retention < 90:
            self.findings.append({
                "id": "LOG-007",
                "title": f"Log retention period too short: {retention} days",
                "severity": "MEDIUM",
                "category": "Logging & Monitoring",
                "resource": "Log Retention",
                "actual": f"{retention} days",
                "expected": ">= 90 days (PCI DSS: 1 year)",
                "recommendation": "Increase log retention to at least 90 days (365 days for PCI DSS compliance)",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/syslog -H 'Authorization: Basic <token>' -d \"{'log-retention':'365'}'''"
            })

    def _check_siem_integration(self, cfg):
        siem = cfg.get("siem-integration", cfg.get("cef-log", cfg.get("leef-log", {})))
        if isinstance(siem, dict):
            enabled = siem.get("status", siem.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "LOG-008",
                    "title": "SIEM integration (CEF/LEEF) not enabled",
                    "severity": "MEDIUM",
                    "category": "Logging & Monitoring",
                    "resource": "SIEM",
                    "actual": "SIEM integration disabled",
                    "expected": "CEF or LEEF format export enabled",
                    "recommendation": "Enable CEF or LEEF log format export for SIEM integration (Splunk, QRadar, Sentinel)",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/syslog -H 'Authorization: Basic <token>' -d \"{'cef-log':'on'}'''"
                })
        elif not siem:
            self.findings.append({
                "id": "LOG-008",
                "title": "No SIEM integration configured",
                "severity": "MEDIUM",
                "category": "Logging & Monitoring",
                "resource": "SIEM",
                "actual": "No SIEM integration",
                "expected": "SIEM platform integration",
                "recommendation": "Configure SIEM integration for centralized security monitoring and correlation",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/syslog -H 'Authorization: Basic <token>' -d \"{'cef-log':'on'}'''"
            })

    def _check_alert_policies(self, cfg):
        alerts = cfg.get("alert-policies", cfg.get("notifications", cfg.get("email-alerts", {})))
        if isinstance(alerts, dict):
            enabled = alerts.get("status", alerts.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "LOG-009",
                    "title": "Alert notifications disabled",
                    "severity": "HIGH",
                    "category": "Logging & Monitoring",
                    "resource": "Alerts",
                    "actual": "Alerts disabled",
                    "expected": "Alert notifications enabled",
                    "recommendation": "Enable alert notifications for critical events (attacks, system failures, certificate expiry)",
                    "remediation_cmd": "Configure alert policies via WAF management console: ADVANCED > Notifications"
                })
        elif not alerts:
            self.findings.append({
                "id": "LOG-009",
                "title": "No alert policies configured",
                "severity": "HIGH",
                "category": "Logging & Monitoring",
                "resource": "Alerts",
                "actual": "No alerts configured",
                "expected": "Alert policies for critical events",
                "recommendation": "Configure alert policies for attack detection, system health, and configuration changes",
                "remediation_cmd": "Configure alert policies via WAF management console: ADVANCED > Notifications"
            })

    def _check_system_logging(self, cfg):
        sys_log = cfg.get("system-log", cfg.get("system-logging", ""))
        if isinstance(sys_log, str) and sys_log.lower() in ("off", "no", "disabled", ""):
            self.findings.append({
                "id": "LOG-010",
                "title": "System event logging disabled",
                "severity": "MEDIUM",
                "category": "Logging & Monitoring",
                "resource": "System Log",
                "actual": "System logging disabled",
                "expected": "System logging enabled",
                "recommendation": "Enable system logging to capture firmware updates, reboots, HA failovers, and configuration changes",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/syslog -H 'Authorization: Basic <token>' -d \"{'system-log':'on'}'''"
            })

    def _check_notification_config(self, cfg):
        email = cfg.get("notification-email", cfg.get("admin-email", ""))
        if not email or (isinstance(email, str) and not email.strip()):
            self.findings.append({
                "id": "LOG-010",
                "title": "No notification email configured",
                "severity": "MEDIUM",
                "category": "Logging & Monitoring",
                "resource": "Notifications",
                "actual": "No email recipient",
                "expected": "Admin notification email configured",
                "recommendation": "Configure an admin notification email address for critical alerts and system events",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/syslog -H 'Authorization: Basic <token>' -d \"{'system-log':'on'}'''"
            })
