"""SSL/TLS configuration security checks."""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
    "RC2", "IDEA", "SEED", "CAMELLIA128"
]

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"]


class SslTlsChecker:
    """Assess SSL/TLS configuration — protocols, ciphers, certificates,
    HSTS, PFS, OCSP stapling."""

    def __init__(self, api_client):
        self.api = api_client
        self.findings = []

    def run_all(self):
        logger.info("Running SSL/TLS checks...")
        services = self.api.get_services()
        certs = self.api.get_certificates()

        for svc in services:
            name = svc.get("name", svc.get("id", "unknown"))
            svc_type = svc.get("type", svc.get("service-type", ""))
            if isinstance(svc_type, str) and svc_type.upper() in ("HTTP", "REDIRECT"):
                continue
            detail = self.api.get_service_detail(name)
            cfg = detail.get("data", detail) if isinstance(detail, dict) else svc
            ssl_cfg = cfg.get("ssl-security", cfg.get("ssl", {}))
            if isinstance(ssl_cfg, dict):
                self._check_tls_versions(name, ssl_cfg)
                self._check_cipher_suites(name, ssl_cfg)
                self._check_pfs(name, ssl_cfg)
                self._check_hsts(name, cfg)
                self._check_ssl_redirect(name, cfg)
                self._check_ocsp_stapling(name, ssl_cfg)
                self._check_client_cert(name, ssl_cfg)
                self._check_tls_renegotiation(name, ssl_cfg)

        for cert in certs:
            self._check_certificate_expiry(cert)
            self._check_key_size(cert)
            self._check_signature_algorithm(cert)

        if not certs and services:
            self.findings.append({
                "id": "SSL-013",
                "title": "No SSL certificates found",
                "severity": "HIGH",
                "category": "SSL/TLS",
                "resource": "Global",
                "actual": "No certificates configured",
                "expected": "Valid SSL certificates installed",
                "recommendation": "Install valid SSL/TLS certificates for all HTTPS services",
                "remediation_cmd": "Renew certificate and upload via: curl -X POST https://<WAF_IP>:8443/restapi/v3.2/signed-certificate -H 'Authorization: Basic <token>' -F 'signed_certificate=@new_cert.pem' -F 'key=@private.key'"
            })

        return self.findings

    def _check_tls_versions(self, name, ssl_cfg):
        protocols = ssl_cfg.get("enabled-protocols", ssl_cfg.get("ssl-protocols", ""))
        if isinstance(protocols, str):
            weak = [p for p in WEAK_PROTOCOLS if p.lower() in protocols.lower()]
            if weak:
                self.findings.append({
                    "id": "SSL-001",
                    "title": f"Weak TLS protocols enabled: {', '.join(weak)}",
                    "severity": "CRITICAL" if any("SSLv" in p for p in weak) else "HIGH",
                    "category": "SSL/TLS",
                    "resource": name,
                    "actual": protocols,
                    "expected": "TLSv1.2 and TLSv1.3 only",
                    "recommendation": "Disable SSLv2, SSLv3, TLSv1.0, and TLSv1.1. Enable only TLSv1.2 and TLSv1.3",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/ssl-security -H 'Authorization: Basic <token>' -d '{'enabled-protocols':'TLSv1.2 TLSv1.3'}'")
                })
            if "TLSv1.3" not in protocols and "tlsv1.3" not in protocols.lower():
                self.findings.append({
                    "id": "SSL-002",
                    "title": "TLS 1.3 not enabled",
                    "severity": "MEDIUM",
                    "category": "SSL/TLS",
                    "resource": name,
                    "actual": protocols,
                    "expected": "TLSv1.3 enabled",
                    "recommendation": "Enable TLS 1.3 for improved security and performance",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/ssl-security -H 'Authorization: Basic <token>' -d '{'enabled-protocols':'TLSv1.2 TLSv1.3'}'")
                })

    def _check_cipher_suites(self, name, ssl_cfg):
        ciphers = ssl_cfg.get("ciphers", ssl_cfg.get("cipher-suites", ""))
        if isinstance(ciphers, str):
            weak = [c for c in WEAK_CIPHERS if c.lower() in ciphers.lower()]
            if weak:
                self.findings.append({
                    "id": "SSL-003",
                    "title": f"Weak cipher suites enabled: {', '.join(weak)}",
                    "severity": "HIGH",
                    "category": "SSL/TLS",
                    "resource": name,
                    "actual": f"Weak ciphers found: {', '.join(weak)}",
                    "expected": "Only strong ciphers (AES-GCM, CHACHA20-POLY1305)",
                    "recommendation": "Remove weak cipher suites (RC4, DES, 3DES, NULL, EXPORT, MD5) and enable only AES-256-GCM, AES-128-GCM, CHACHA20",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/ssl-security -H 'Authorization: Basic <token>' -d '{'ciphers':'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256'}'")
                })
            if "CBC" in ciphers.upper():
                self.findings.append({
                    "id": "SSL-004",
                    "title": "CBC mode cipher suites enabled",
                    "severity": "MEDIUM",
                    "category": "SSL/TLS",
                    "resource": name,
                    "actual": "CBC ciphers present",
                    "expected": "GCM or CHACHA20 ciphers only",
                    "recommendation": "Replace CBC mode ciphers with GCM or CHACHA20-POLY1305 to prevent BEAST/POODLE attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/ssl-security -H 'Authorization: Basic <token>' -d '{'ciphers':'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256'}'")
                })

    def _check_pfs(self, name, ssl_cfg):
        pfs = ssl_cfg.get("perfect-forward-secrecy", ssl_cfg.get("pfs", ""))
        if isinstance(pfs, str) and pfs.lower() in ("off", "no", "disabled", ""):
            self.findings.append({
                "id": "SSL-005",
                "title": "Perfect Forward Secrecy (PFS) disabled",
                "severity": "HIGH",
                "category": "SSL/TLS",
                "resource": name,
                "actual": "PFS disabled",
                "expected": "PFS enabled (ECDHE/DHE key exchange)",
                "recommendation": "Enable PFS to ensure past sessions cannot be decrypted if private key is compromised",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/ssl-security -H 'Authorization: Basic <token>' -d '{'perfect-forward-secrecy':'on'}'")
            })

    def _check_hsts(self, name, cfg):
        hsts = cfg.get("hsts", cfg.get("strict-transport-security", {}))
        if isinstance(hsts, dict):
            enabled = hsts.get("status", hsts.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "SSL-006",
                    "title": "HTTP Strict Transport Security (HSTS) disabled",
                    "severity": "MEDIUM",
                    "category": "SSL/TLS",
                    "resource": name,
                    "actual": "HSTS disabled",
                    "expected": "HSTS enabled with max-age >= 31536000",
                    "recommendation": "Enable HSTS with max-age of at least one year (31536000) and include subdomains",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/hsts -H 'Authorization: Basic <token>' -d '{'status':'on','max-age':'31536000'}'")
                })
            else:
                max_age = int(hsts.get("max-age", 0))
                if max_age < 31536000:
                    self.findings.append({
                        "id": "SSL-007",
                        "title": "HSTS max-age too short",
                        "severity": "LOW",
                        "category": "SSL/TLS",
                        "resource": name,
                        "actual": f"{max_age} seconds",
                        "expected": ">= 31536000 seconds (1 year)",
                        "recommendation": "Increase HSTS max-age to at least 31536000 seconds (one year)",
                        "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/hsts -H 'Authorization: Basic <token>' -d '{'max-age':'31536000'}'")
                    })
        elif isinstance(hsts, str) and hsts.lower() in ("off", "no", "disabled", ""):
            self.findings.append({
                "id": "SSL-006",
                "title": "HTTP Strict Transport Security (HSTS) disabled",
                "severity": "MEDIUM",
                "category": "SSL/TLS",
                "resource": name,
                "actual": "HSTS disabled",
                "expected": "HSTS enabled with max-age >= 31536000",
                "recommendation": "Enable HSTS to force browsers to always use HTTPS",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/hsts -H 'Authorization: Basic <token>' -d '{'status':'on','max-age':'31536000'}'")
            })

    def _check_ssl_redirect(self, name, cfg):
        redirect = cfg.get("ssl-redirect", cfg.get("redirect-to-https", ""))
        if isinstance(redirect, str) and redirect.lower() in ("off", "no", "disabled", ""):
            self.findings.append({
                "id": "SSL-008",
                "title": "HTTP to HTTPS redirect not configured",
                "severity": "MEDIUM",
                "category": "SSL/TLS",
                "resource": name,
                "actual": "No HTTPS redirect",
                "expected": "HTTP to HTTPS redirect enabled",
                "recommendation": "Enable automatic HTTP to HTTPS redirection to prevent unencrypted access",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + " -H 'Authorization: Basic <token>' -d '{'ssl-redirect':'on'}'")
            })

    def _check_ocsp_stapling(self, name, ssl_cfg):
        ocsp = ssl_cfg.get("ocsp-stapling", ssl_cfg.get("enable-ocsp-stapling", ""))
        if isinstance(ocsp, str) and ocsp.lower() in ("off", "no", "disabled", ""):
            self.findings.append({
                "id": "SSL-009",
                "title": "OCSP stapling disabled",
                "severity": "LOW",
                "category": "SSL/TLS",
                "resource": name,
                "actual": "OCSP stapling disabled",
                "expected": "OCSP stapling enabled",
                "recommendation": "Enable OCSP stapling for faster certificate revocation checking and improved privacy",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/ssl-security -H 'Authorization: Basic <token>' -d '{'ocsp-stapling':'on'}'")
            })

    def _check_client_cert(self, name, ssl_cfg):
        client_auth = ssl_cfg.get("client-authentication", ssl_cfg.get("verify-client", ""))
        if isinstance(client_auth, str) and client_auth.lower() in ("off", "no", "disabled", "none", ""):
            self.findings.append({
                "id": "SSL-010",
                "title": "Client certificate authentication not enabled",
                "severity": "INFO",
                "category": "SSL/TLS",
                "resource": name,
                "actual": "Client cert auth disabled",
                "expected": "Consider mutual TLS for sensitive services",
                "recommendation": "Consider enabling client certificate authentication (mTLS) for API or admin interfaces",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/ssl-security -H 'Authorization: Basic <token>' -d '{'client-authentication':'optional'}'")
            })

    def _check_tls_renegotiation(self, name, ssl_cfg):
        renego = ssl_cfg.get("allow-ssl-renegotiation", ssl_cfg.get("secure-renegotiation", ""))
        if isinstance(renego, str) and renego.lower() in ("yes", "on", "enabled"):
            self.findings.append({
                "id": "SSL-011",
                "title": "Insecure SSL renegotiation allowed",
                "severity": "MEDIUM",
                "category": "SSL/TLS",
                "resource": name,
                "actual": "SSL renegotiation enabled",
                "expected": "SSL renegotiation disabled or secure only",
                "recommendation": "Disable SSL renegotiation or ensure only secure renegotiation is permitted",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/ssl-security -H 'Authorization: Basic <token>' -d '{'allow-ssl-renegotiation':'disabled'}'")
            })

    def _check_certificate_expiry(self, cert):
        name = cert.get("name", cert.get("common-name", "unknown"))
        expiry = cert.get("expiry", cert.get("not-after", cert.get("valid-to", "")))
        if not expiry:
            self.findings.append({
                "id": "SSL-012",
                "title": "Certificate expiry date not available",
                "severity": "MEDIUM",
                "category": "SSL/TLS",
                "resource": name,
                "actual": "Expiry unknown",
                "expected": "Valid certificate with known expiry",
                "recommendation": "Verify certificate installation and ensure valid certificate is installed",
                "remediation_cmd": "Verify certificate installation via WAF management console"
            })
            return
        try:
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S %Y GMT", "%Y-%m-%d"):
                try:
                    exp_date = datetime.strptime(expiry, fmt)
                    break
                except ValueError:
                    continue
            else:
                return
            days_left = (exp_date - datetime.now(timezone.utc).replace(tzinfo=None)).days
            if days_left < 0:
                self.findings.append({
                    "id": "SSL-013",
                    "title": f"Certificate expired {abs(days_left)} days ago",
                    "severity": "CRITICAL",
                    "category": "SSL/TLS",
                    "resource": name,
                    "actual": f"Expired on {expiry}",
                    "expected": "Valid, non-expired certificate",
                    "recommendation": "Immediately renew the expired SSL certificate",
                    "remediation_cmd": "Renew certificate and upload via: curl -X POST https://<WAF_IP>:8443/restapi/v3.2/signed-certificate -H 'Authorization: Basic <token>' -F 'signed_certificate=@new_cert.pem' -F 'key=@private.key'"
                })
            elif days_left < 30:
                self.findings.append({
                    "id": "SSL-014",
                    "title": f"Certificate expires in {days_left} days",
                    "severity": "HIGH",
                    "category": "SSL/TLS",
                    "resource": name,
                    "actual": f"Expires on {expiry} ({days_left} days)",
                    "expected": "Certificate valid for > 30 days",
                    "recommendation": "Renew the SSL certificate before expiry to avoid service disruption",
                    "remediation_cmd": "Renew certificate before expiry: curl -X POST https://<WAF_IP>:8443/restapi/v3.2/signed-certificate -H 'Authorization: Basic <token>' -F 'signed_certificate=@new_cert.pem' -F 'key=@private.key'"
                })
        except Exception:
            pass

    def _check_key_size(self, cert):
        name = cert.get("name", cert.get("common-name", "unknown"))
        key_size = cert.get("key-size", cert.get("key-length", cert.get("bits", 0)))
        try:
            key_size = int(key_size)
        except (ValueError, TypeError):
            return
        if key_size and key_size < 2048:
            self.findings.append({
                "id": "SSL-015",
                "title": f"Certificate key size too small: {key_size} bits",
                "severity": "HIGH",
                "category": "SSL/TLS",
                "resource": name,
                "actual": f"{key_size}-bit key",
                "expected": ">= 2048-bit RSA or 256-bit ECDSA",
                "recommendation": "Replace certificate with minimum 2048-bit RSA or 256-bit ECDSA key",
                "remediation_cmd": "Generate new certificate: openssl req -newkey rsa:2048 -sha256 -nodes -keyout server.key -out server.csr"
            })

    def _check_signature_algorithm(self, cert):
        name = cert.get("name", cert.get("common-name", "unknown"))
        sig_alg = cert.get("signature-algorithm", cert.get("sig-alg", ""))
        if isinstance(sig_alg, str) and ("sha1" in sig_alg.lower() or "md5" in sig_alg.lower()):
            self.findings.append({
                "id": "SSL-015",
                "title": f"Weak certificate signature algorithm: {sig_alg}",
                "severity": "HIGH",
                "category": "SSL/TLS",
                "resource": name,
                "actual": sig_alg,
                "expected": "SHA-256 or stronger",
                "recommendation": "Replace certificate with one using SHA-256 or SHA-384 signature algorithm",
                "remediation_cmd": "Generate new certificate: openssl req -newkey rsa:2048 -sha256 -nodes -keyout server.key -out server.csr"
            })
