"""DDoS protection security checks."""

import logging
from utils.config_helper import safe_int, deep_get, extract_config

logger = logging.getLogger(__name__)


class DdosProtectionChecker:
    """Assess DDoS protection — slow client, connection limits, request limits,
    SYN flood protection."""

    def __init__(self, api_client):
        self.api = api_client
        self.findings = []

    def run_all(self):
        logger.info("Running DDoS protection checks...")
        services = self.api.get_services()

        for svc in services:
            name = svc.get("name", svc.get("id", "unknown"))
            detail = self.api.get_service_detail(name)
            cfg = extract_config(detail, fallback=svc) if isinstance(detail, dict) else svc

            self._check_slow_client(name, cfg)
            self._check_connection_limits(name, cfg)
            self._check_request_rate_limits(name, cfg)
            self._check_syn_flood(name, cfg)
            self._check_client_timeout(name, cfg)
            self._check_large_request_protection(name, cfg)
            self._check_http_flood(name, cfg)

        return self.findings

    def _check_slow_client(self, name, cfg):
        slow = cfg.get("slow-client-attack", cfg.get("slowloris-protection", {}))
        if isinstance(slow, dict):
            enabled = slow.get("status", slow.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "DDOS-001",
                    "title": "Slow client (Slowloris) attack protection disabled",
                    "severity": "HIGH",
                    "category": "DDoS Protection",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "Enabled",
                    "recommendation": "Enable slow client attack protection to defend against Slowloris and slow HTTP DoS attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/slow-client-attack -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''")
                })
            else:
                timeout = safe_int(slow.get("data-transfer-rate", slow.get("min-data-rate", 0)))
                if timeout == 0:
                    self.findings.append({
                        "id": "DDOS-002",
                        "title": "Slow client minimum data rate not configured",
                        "severity": "MEDIUM",
                        "category": "DDoS Protection",
                        "resource": name,
                        "actual": "No minimum rate set",
                        "expected": "Minimum data transfer rate configured",
                        "recommendation": "Set a minimum data transfer rate to detect and block slow HTTP attacks",
                        "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/slow-client-attack -H 'Authorization: Basic <token>' -d \"{'data-transfer-rate':'50'}'''")
                    })
        else:
            self.findings.append({
                "id": "DDOS-001",
                "title": "Slow client attack protection not configured",
                "severity": "HIGH",
                "category": "DDoS Protection",
                "resource": name,
                "actual": "Not configured",
                "expected": "Slow client protection enabled",
                "recommendation": "Configure slow client attack protection with appropriate data rate thresholds",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/slow-client-attack -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''")
            })

    def _check_connection_limits(self, name, cfg):
        conn = cfg.get("connection-limits", cfg.get("max-connections", {}))
        if isinstance(conn, dict):
            max_client = safe_int(conn.get("max-client-connections", conn.get("per-client-limit", 0)))
            if max_client == 0 or max_client > 5000:
                self.findings.append({
                    "id": "DDOS-003",
                    "title": "Per-client connection limit not set or too high",
                    "severity": "HIGH",
                    "category": "DDoS Protection",
                    "resource": name,
                    "actual": str(max_client) if max_client else "Unlimited",
                    "expected": "<= 5000 per client IP",
                    "recommendation": "Set per-client connection limits to prevent single-source connection exhaustion attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/connection-limits -H 'Authorization: Basic <token>' -d \"{'max-client-connections':'500'}'''")
                })
            max_total = safe_int(conn.get("max-total-connections", conn.get("total-limit", 0)))
            if max_total == 0:
                self.findings.append({
                    "id": "DDOS-004",
                    "title": "Total connection limit not configured",
                    "severity": "MEDIUM",
                    "category": "DDoS Protection",
                    "resource": name,
                    "actual": "No total limit",
                    "expected": "Total connection limit based on capacity",
                    "recommendation": "Set a total connection limit appropriate for your WAF and backend capacity",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/connection-limits -H 'Authorization: Basic <token>' -d \"{'max-total-connections':'10000'}'''")
                })
        else:
            self.findings.append({
                "id": "DDOS-003",
                "title": "Connection limits not configured",
                "severity": "HIGH",
                "category": "DDoS Protection",
                "resource": name,
                "actual": "No connection limits",
                "expected": "Per-client and total connection limits",
                "recommendation": "Configure connection limits to prevent resource exhaustion from excessive connections",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/connection-limits -H 'Authorization: Basic <token>' -d \"{'max-client-connections':'500'}'''")
            })

    def _check_request_rate_limits(self, name, cfg):
        rate = cfg.get("request-rate-limit", cfg.get("adaptive-profiling", {}).get("request-rate", {}))
        if isinstance(rate, dict):
            enabled = rate.get("status", rate.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "DDOS-005",
                    "title": "Request rate limiting disabled",
                    "severity": "HIGH",
                    "category": "DDoS Protection",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "Rate limiting enabled",
                    "recommendation": "Enable request rate limiting to cap requests per client and prevent HTTP flood attacks",
                    "remediation_cmd": ("curl -X POST https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/rate-control -H 'Authorization: Basic <token>' -d \"{'name':'default-rate','max-requests-per-second':'100'}'''")
                })
        elif not rate:
            rate_ctrl = self.api.get_rate_control(name)
            if not rate_ctrl:
                self.findings.append({
                    "id": "DDOS-005",
                    "title": "No request rate control configured",
                    "severity": "HIGH",
                    "category": "DDoS Protection",
                    "resource": name,
                    "actual": "No rate control",
                    "expected": "Rate limiting per client IP",
                    "recommendation": "Configure request rate control to limit requests per second per client",
                    "remediation_cmd": ("curl -X POST https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/rate-control -H 'Authorization: Basic <token>' -d \"{'name':'default-rate','max-requests-per-second':'100'}'''")
                })

    def _check_syn_flood(self, name, cfg):
        syn = cfg.get("syn-flood-protection", cfg.get("tcp-syn-protection", {}))
        if isinstance(syn, dict):
            enabled = syn.get("status", syn.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "DDOS-006",
                    "title": "SYN flood protection disabled",
                    "severity": "HIGH",
                    "category": "DDoS Protection",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "SYN flood protection enabled",
                    "recommendation": "Enable SYN flood protection with SYN cookies to defend against TCP SYN flood attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/syn-flood-protection -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''")
                })

    def _check_client_timeout(self, name, cfg):
        timeout = cfg.get("client-timeout", cfg.get("idle-timeout", 0))
        try:
            timeout = int(timeout)
        except (ValueError, TypeError):
            timeout = 0
        if timeout > 300:
            self.findings.append({
                "id": "DDOS-007",
                "title": f"Client idle timeout too long: {timeout}s",
                "severity": "MEDIUM",
                "category": "DDoS Protection",
                "resource": name,
                "actual": f"{timeout} seconds",
                "expected": "<= 300 seconds",
                "recommendation": "Reduce client idle timeout to free resources from inactive connections",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + " -H 'Authorization: Basic <token>' -d \"{'client-timeout':'120'}'''")
            })

    def _check_large_request_protection(self, name, cfg):
        max_body = cfg.get("max-request-body-size", cfg.get("request-limits", {}).get("max-request-length", 0))
        try:
            max_body = int(max_body)
        except (ValueError, TypeError):
            max_body = 0
        if max_body == 0 or max_body > 10485760:
            self.findings.append({
                "id": "DDOS-008",
                "title": "Large request body protection not configured",
                "severity": "MEDIUM",
                "category": "DDoS Protection",
                "resource": name,
                "actual": f"{max_body} bytes" if max_body else "Unlimited",
                "expected": "<= 10MB unless file uploads required",
                "recommendation": "Set max request body size to prevent large-payload DoS attacks",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/request-limits -H 'Authorization: Basic <token>' -d \"{'max-request-length':'10485760'}'''")
            })

    def _check_http_flood(self, name, cfg):
        flood = cfg.get("http-flood-protection", cfg.get("ddos-prevention", {}))
        if isinstance(flood, dict):
            enabled = flood.get("status", flood.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "DDOS-009",
                    "title": "HTTP flood protection disabled",
                    "severity": "HIGH",
                    "category": "DDoS Protection",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "HTTP flood protection enabled",
                    "recommendation": "Enable HTTP flood protection with CAPTCHA challenges to mitigate application-layer DDoS",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/http-flood-protection -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''")
                })
