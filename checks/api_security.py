"""API security checks — JSON/XML validation, content-type enforcement,
schema validation, payload limits."""

import logging
from utils.config_helper import safe_int, deep_get, extract_config

logger = logging.getLogger(__name__)


class ApiSecurityChecker:
    """Assess API security configurations for JSON/XML protection,
    content-type enforcement, and schema validation."""

    def __init__(self, api_client):
        self.api = api_client
        self.findings = []

    def run_all(self):
        logger.info("Running API security checks...")
        services = self.api.get_services()
        policies = self.api.get_security_policies()

        for svc in services:
            name = svc.get("name", svc.get("id", "unknown"))
            detail = self.api.get_service_detail(name)
            cfg = extract_config(detail, fallback=svc) if isinstance(detail, dict) else svc
            self._check_content_type_enforcement(name, cfg)
            self._check_api_discovery(name, cfg)
            self._check_cors_policy(name, cfg)

        for policy in policies:
            pname = policy.get("name", policy.get("id", "unknown"))
            detail = self.api.get_security_policy(pname) if isinstance(pname, str) else policy
            pcfg = extract_config(detail, fallback=policy) if isinstance(detail, dict) else policy
            self._check_json_validation(pname, pcfg)
            self._check_xml_validation(pname, pcfg)
            self._check_payload_limits(pname, pcfg)
            self._check_graphql_protection(pname, pcfg)
            self._check_api_rate_limiting(pname, pcfg)

        return self.findings

    def _check_json_validation(self, name, cfg):
        json_sec = cfg.get("json-security", cfg.get("json-policy", {}))
        if isinstance(json_sec, dict):
            enabled = json_sec.get("status", json_sec.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "API-001",
                    "title": "JSON body validation disabled",
                    "severity": "HIGH",
                    "category": "API Security",
                    "resource": name,
                    "actual": "JSON validation disabled",
                    "expected": "JSON validation enabled",
                    "recommendation": "Enable JSON body validation to detect malformed payloads and injection attempts in JSON APIs",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/json-security -H 'Authorization: Basic <token>' -d \"{'status':'on'}'''")
                })
            max_keys = safe_int(json_sec.get("max-keys", json_sec.get("max-object-keys", 0)))
            if max_keys == 0 or max_keys > 1000:
                self.findings.append({
                    "id": "API-002",
                    "title": "JSON max object keys not limited",
                    "severity": "MEDIUM",
                    "category": "API Security",
                    "resource": name,
                    "actual": str(max_keys) if max_keys else "Unlimited",
                    "expected": "<= 1000",
                    "recommendation": "Limit JSON max object keys to prevent hash collision DoS attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/json-security -H 'Authorization: Basic <token>' -d \"{'max-keys':'1000'}'''")
                })
        elif not json_sec:
            self.findings.append({
                "id": "API-001",
                "title": "JSON security not configured",
                "severity": "HIGH",
                "category": "API Security",
                "resource": name,
                "actual": "Not configured",
                "expected": "JSON validation enabled for API services",
                "recommendation": "Configure JSON security validation for all API-facing services",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/json-security -H 'Authorization: Basic <token>' -d \"{'status':'on'}'''")
            })

    def _check_xml_validation(self, name, cfg):
        xml_sec = cfg.get("xml-firewall", cfg.get("xml-policy", {}))
        if isinstance(xml_sec, dict):
            enabled = xml_sec.get("status", xml_sec.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "API-003",
                    "title": "XML firewall validation disabled",
                    "severity": "HIGH",
                    "category": "API Security",
                    "resource": name,
                    "actual": "XML validation disabled",
                    "expected": "XML validation enabled",
                    "recommendation": "Enable XML firewall to protect against XXE, XPath injection, and XML bomb attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/xml-firewall -H 'Authorization: Basic <token>' -d \"{'status':'on'}'''")
                })
            max_depth = safe_int(xml_sec.get("max-element-depth", xml_sec.get("max-depth", 0)))
            if max_depth == 0 or max_depth > 64:
                self.findings.append({
                    "id": "API-004",
                    "title": "XML max element depth not limited",
                    "severity": "MEDIUM",
                    "category": "API Security",
                    "resource": name,
                    "actual": str(max_depth) if max_depth else "Unlimited",
                    "expected": "<= 64",
                    "recommendation": "Limit XML element nesting depth to prevent billion-laughs and recursive entity expansion attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/xml-firewall -H 'Authorization: Basic <token>' -d \"{'max-element-depth':'64'}'''")
                })

    def _check_content_type_enforcement(self, name, cfg):
        content_type = cfg.get("content-type-enforcement", cfg.get("allowed-content-types", ""))
        if not content_type or (isinstance(content_type, str) and content_type.lower() in ("off", "disabled", "")):
            self.findings.append({
                "id": "API-005",
                "title": "Content-Type enforcement disabled",
                "severity": "MEDIUM",
                "category": "API Security",
                "resource": name,
                "actual": "No content-type restrictions",
                "expected": "Content-Type header enforcement enabled",
                "recommendation": "Enable content-type enforcement to reject requests with unexpected content types",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + " -H 'Authorization: Basic <token>' -d \"{'content-type-enforcement':'on'}'''")
            })

    def _check_payload_limits(self, name, cfg):
        limits = cfg.get("request-limits", cfg.get("api-limits", {}))
        if isinstance(limits, dict):
            max_payload = safe_int(limits.get("max-request-length", limits.get("max-body-size", 0)))
            if max_payload == 0 or max_payload > 5242880:
                self.findings.append({
                    "id": "API-006",
                    "title": "API payload size limit not configured or too high",
                    "severity": "MEDIUM",
                    "category": "API Security",
                    "resource": name,
                    "actual": f"{max_payload} bytes" if max_payload else "Unlimited",
                    "expected": "<= 5MB for API endpoints",
                    "recommendation": "Set appropriate API payload size limits to prevent large-payload abuse",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/request-limits -H 'Authorization: Basic <token>' -d \"{'max-request-length':'5242880'}'''")
                })

    def _check_api_rate_limiting(self, name, cfg):
        api_rate = cfg.get("api-rate-limiting", cfg.get("api-throttling", {}))
        if isinstance(api_rate, dict):
            enabled = api_rate.get("status", api_rate.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "API-007",
                    "title": "API-specific rate limiting disabled",
                    "severity": "HIGH",
                    "category": "API Security",
                    "resource": name,
                    "actual": "API rate limiting disabled",
                    "expected": "API rate limiting enabled per endpoint",
                    "recommendation": "Enable API-specific rate limiting to protect individual endpoints from abuse",
                    "remediation_cmd": ("curl -X POST https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/rate-control -H 'Authorization: Basic <token>' -d \"{'name':'api-rate','max-requests-per-second':'100'}'''")
                })

    def _check_api_discovery(self, name, cfg):
        discovery = cfg.get("api-discovery", cfg.get("openapi-spec", ""))
        if not discovery or (isinstance(discovery, str) and discovery.lower() in ("off", "disabled", "")):
            self.findings.append({
                "id": "API-008",
                "title": "API discovery/schema enforcement not configured",
                "severity": "INFO",
                "category": "API Security",
                "resource": name,
                "actual": "No API schema enforcement",
                "expected": "OpenAPI/Swagger schema enforcement",
                "recommendation": "Consider importing an OpenAPI specification for positive security model enforcement on API endpoints",
                "remediation_cmd": "Import OpenAPI spec via WAF management console: WEBSITES > API Discovery"
            })

    def _check_cors_policy(self, name, cfg):
        cors = cfg.get("cors", cfg.get("cross-origin-policy", {}))
        if isinstance(cors, dict):
            origins = cors.get("allowed-origins", cors.get("access-control-allow-origin", ""))
            if isinstance(origins, str) and origins.strip() == "*":
                self.findings.append({
                    "id": "API-008",
                    "title": "CORS allows all origins (*)",
                    "severity": "HIGH",
                    "category": "API Security",
                    "resource": name,
                    "actual": "Access-Control-Allow-Origin: *",
                    "expected": "Specific trusted origins only",
                    "recommendation": "Restrict CORS to specific trusted origins instead of wildcard (*) to prevent cross-origin attacks",
                    "remediation_cmd": "Import OpenAPI spec via WAF management console: WEBSITES > API Discovery"
                })

    def _check_graphql_protection(self, name, cfg):
        graphql = cfg.get("graphql-security", cfg.get("graphql-protection", {}))
        if isinstance(graphql, dict):
            enabled = graphql.get("status", graphql.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "API-007",
                    "title": "GraphQL protection disabled",
                    "severity": "MEDIUM",
                    "category": "API Security",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "GraphQL depth/complexity limits enabled",
                    "recommendation": "Enable GraphQL protection with query depth and complexity limits to prevent DoS via nested queries",
                    "remediation_cmd": ("curl -X POST https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/rate-control -H 'Authorization: Basic <token>' -d \"{'name':'api-rate','max-requests-per-second':'100'}'''")
                })
