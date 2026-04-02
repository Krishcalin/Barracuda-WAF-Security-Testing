"""Virtual service configuration security checks."""

import logging

logger = logging.getLogger(__name__)


class ServicesChecker:
    """Assess virtual service configuration — backend SSL, health checks,
    connection pooling, persistence, instant SSL."""

    def __init__(self, api_client):
        self.api = api_client
        self.findings = []

    def run_all(self):
        logger.info("Running service configuration checks...")
        services = self.api.get_services()

        if not services:
            self.findings.append({
                "id": "SVC-001",
                "title": "No virtual services configured",
                "severity": "INFO",
                "category": "Services",
                "resource": "Global",
                "actual": "No services found",
                "expected": "At least one virtual service configured",
                "recommendation": "Configure virtual services to proxy and protect backend applications",
                "remediation_cmd": "Configure virtual services via WAF management console: BASIC > Services"
            })
            return self.findings

        for svc in services:
            name = svc.get("name", svc.get("id", "unknown"))
            detail = self.api.get_service_detail(name)
            cfg = detail.get("data", detail) if isinstance(detail, dict) else svc

            self._check_backend_ssl(name, cfg)
            self._check_health_checks(name, cfg)
            self._check_connection_pooling(name, cfg)
            self._check_security_policy_assigned(name, cfg)
            self._check_http_service_exposed(name, cfg)
            self._check_instant_ssl(name, cfg)
            self._check_backend_keepalive(name, cfg)
            self._check_server_header(name, cfg)
            self._check_error_pages(name, cfg)
            self._check_content_caching(name, cfg)

        return self.findings

    def _check_backend_ssl(self, name, cfg):
        backend = cfg.get("backend", cfg.get("server", {}))
        if isinstance(backend, dict):
            ssl = backend.get("ssl", backend.get("backend-ssl", ""))
            if isinstance(ssl, str) and ssl.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "SVC-002",
                    "title": "Backend connection not using SSL/TLS",
                    "severity": "HIGH",
                    "category": "Services",
                    "resource": name,
                    "actual": "Backend SSL disabled",
                    "expected": "Backend SSL enabled",
                    "recommendation": "Enable SSL/TLS for backend server connections to encrypt traffic between WAF and application servers",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/backend -H 'Authorization: Basic <token>' -d \"{'ssl':'on'}'''")
                })
            validate = backend.get("validate-certificate", backend.get("ssl-verify", ""))
            if isinstance(validate, str) and validate.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "SVC-003",
                    "title": "Backend SSL certificate validation disabled",
                    "severity": "MEDIUM",
                    "category": "Services",
                    "resource": name,
                    "actual": "Certificate validation disabled",
                    "expected": "Certificate validation enabled",
                    "recommendation": "Enable backend certificate validation to prevent man-in-the-middle attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/backend -H 'Authorization: Basic <token>' -d \"{'validate-certificate':'on'}'''")
                })

    def _check_health_checks(self, name, cfg):
        health = cfg.get("health-check", cfg.get("server-health", {}))
        if isinstance(health, dict):
            enabled = health.get("status", health.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "SVC-004",
                    "title": "Backend health checks disabled",
                    "severity": "MEDIUM",
                    "category": "Services",
                    "resource": name,
                    "actual": "Health checks disabled",
                    "expected": "Health checks enabled",
                    "recommendation": "Enable health checks to detect and remove unhealthy backend servers from the pool",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/health-check -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''")
                })
        elif not health:
            self.findings.append({
                "id": "SVC-004",
                "title": "No health check configuration found",
                "severity": "MEDIUM",
                "category": "Services",
                "resource": name,
                "actual": "No health checks",
                "expected": "Regular health monitoring",
                "recommendation": "Configure health checks with appropriate intervals to ensure backend availability",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/health-check -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''")
            })

    def _check_connection_pooling(self, name, cfg):
        pool = cfg.get("connection-pooling", cfg.get("backend-connection-pooling", ""))
        if isinstance(pool, str) and pool.lower() in ("off", "no", "disabled", ""):
            self.findings.append({
                "id": "SVC-005",
                "title": "Backend connection pooling disabled",
                "severity": "LOW",
                "category": "Services",
                "resource": name,
                "actual": "Connection pooling disabled",
                "expected": "Connection pooling enabled",
                "recommendation": "Enable connection pooling to improve performance and reduce backend connection exhaustion risk",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + " -H 'Authorization: Basic <token>' -d \"{'connection-pooling':'on'}'''")
            })

    def _check_security_policy_assigned(self, name, cfg):
        policy = cfg.get("security-policy", cfg.get("web-firewall-policy", ""))
        if not policy or (isinstance(policy, str) and policy.lower() in ("none", "")):
            self.findings.append({
                "id": "SVC-006",
                "title": "No security policy assigned to service",
                "severity": "CRITICAL",
                "category": "Services",
                "resource": name,
                "actual": "No WAF policy assigned",
                "expected": "Active WAF security policy",
                "recommendation": "Assign a WAF security policy to this service to enable web application protection",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + " -H 'Authorization: Basic <token>' -d \"{'security-policy':'default-policy'}'''")
            })

    def _check_http_service_exposed(self, name, cfg):
        svc_type = cfg.get("type", cfg.get("service-type", ""))
        port = cfg.get("port", cfg.get("service-port", ""))
        if isinstance(svc_type, str) and svc_type.upper() == "HTTP":
            self.findings.append({
                "id": "SVC-007",
                "title": f"Unencrypted HTTP service exposed on port {port}",
                "severity": "HIGH",
                "category": "Services",
                "resource": name,
                "actual": f"HTTP service on port {port}",
                "expected": "HTTPS service or HTTP-to-HTTPS redirect",
                "recommendation": "Convert HTTP service to HTTPS or configure HTTP-to-HTTPS redirect",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + " -H 'Authorization: Basic <token>' -d \"{'type':'HTTPS'}'''")
            })

    def _check_instant_ssl(self, name, cfg):
        instant_ssl = cfg.get("instant-ssl", cfg.get("ssl-offloading", ""))
        if isinstance(instant_ssl, str) and instant_ssl.lower() in ("on", "enabled", "yes"):
            self.findings.append({
                "id": "SVC-008",
                "title": "Instant SSL enabled — verify backend is also encrypted",
                "severity": "INFO",
                "category": "Services",
                "resource": name,
                "actual": "Instant SSL active",
                "expected": "End-to-end encryption preferred",
                "recommendation": "When using Instant SSL, ensure backend connections also use SSL to maintain end-to-end encryption",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/backend -H 'Authorization: Basic <token>' -d \"{'ssl':'on'}'''")
            })

    def _check_backend_keepalive(self, name, cfg):
        keepalive = cfg.get("backend-keepalive", cfg.get("keepalive-timeout", 0))
        try:
            keepalive = int(keepalive)
        except (ValueError, TypeError):
            keepalive = 0
        if keepalive > 300:
            self.findings.append({
                "id": "SVC-009",
                "title": f"Backend keepalive timeout too long: {keepalive}s",
                "severity": "LOW",
                "category": "Services",
                "resource": name,
                "actual": f"{keepalive} seconds",
                "expected": "<= 300 seconds",
                "recommendation": "Reduce backend keepalive timeout to prevent connection resource exhaustion",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + " -H 'Authorization: Basic <token>' -d \"{'backend-keepalive':'120'}'''")
            })

    def _check_server_header(self, name, cfg):
        server_header = cfg.get("suppress-server-header", cfg.get("remove-server-header", ""))
        if isinstance(server_header, str) and server_header.lower() in ("off", "no", "disabled", ""):
            self.findings.append({
                "id": "SVC-010",
                "title": "Server header not suppressed",
                "severity": "LOW",
                "category": "Services",
                "resource": name,
                "actual": "Server header exposed",
                "expected": "Server header suppressed",
                "recommendation": "Suppress the Server response header to prevent backend technology fingerprinting",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + " -H 'Authorization: Basic <token>' -d \"{'suppress-server-header':'on'}'''")
            })

    def _check_error_pages(self, name, cfg):
        custom_errors = cfg.get("custom-error-page", cfg.get("error-pages", ""))
        if not custom_errors or (isinstance(custom_errors, str) and custom_errors.lower() in ("off", "disabled", "default", "")):
            self.findings.append({
                "id": "SVC-011",
                "title": "Custom error pages not configured",
                "severity": "LOW",
                "category": "Services",
                "resource": name,
                "actual": "Default error pages",
                "expected": "Custom branded error pages",
                "recommendation": "Configure custom error pages to prevent information leakage from default server error responses",
                "remediation_cmd": "Configure custom error pages via WAF management console: WEBSITES > Error Pages"
            })

    def _check_content_caching(self, name, cfg):
        caching = cfg.get("caching", cfg.get("content-caching", {}))
        if isinstance(caching, dict):
            no_store = caching.get("cache-control", "")
            if isinstance(no_store, str) and "no-store" not in no_store.lower() and "private" not in no_store.lower():
                self.findings.append({
                    "id": "SVC-012",
                    "title": "Sensitive content may be cached",
                    "severity": "INFO",
                    "category": "Services",
                    "resource": name,
                    "actual": f"Cache-Control: {no_store}" if no_store else "No cache directives",
                    "expected": "Cache-Control with no-store for sensitive content",
                    "recommendation": "Ensure sensitive pages include Cache-Control: no-store header to prevent data leakage via caches",
                    "remediation_cmd": "Configure Cache-Control headers via response header rules in WAF management console"
                })
