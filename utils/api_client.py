"""Barracuda WAF REST API client with token authentication."""

import requests
import urllib3
import logging
import time

logger = logging.getLogger(__name__)


class BarracudaWafClient:
    """Read-only REST API client for Barracuda WAF."""

    def __init__(self, host, port=8443, username="admin", password="",
                 verify_ssl=True, timeout=30, max_retries=3):
        self.base_url = f"https://{host}:{port}/restapi/v3.2"
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries
        self.token = None
        self.session = requests.Session()

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self.session.verify = False

    def login(self):
        """Authenticate and obtain API token."""
        url = f"{self.base_url}/login"
        payload = {"username": self.username, "password": self.password}

        try:
            resp = self.session.post(url, json=payload,
                                     verify=self.verify_ssl, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            self.token = data.get("token") or data.get("Token")
            if not self.token:
                raise AuthenticationError(f"No token in response: {data}")
            self.session.headers.update({"Authorization": f"Basic {self.token}"})
            logger.info("Authenticated to Barracuda WAF at %s", self.base_url)
            return True
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Cannot connect to {self.base_url}: {e}") from e
        except requests.exceptions.HTTPError as e:
            raise AuthenticationError(f"Authentication failed: {e}") from e

    def logout(self):
        """Invalidate session token."""
        if self.token:
            try:
                self.session.delete(f"{self.base_url}/login/{self.token}",
                                    verify=self.verify_ssl, timeout=self.timeout)
            except Exception:
                pass
            self.token = None

    def get(self, endpoint, params=None):
        """GET request with retry logic. Returns parsed JSON or empty dict."""
        url = f"{self.base_url}{endpoint}"
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self.session.get(url, params=params,
                                        verify=self.verify_ssl, timeout=self.timeout)
                if resp.status_code == 401:
                    logger.warning("Token expired, re-authenticating...")
                    self.login()
                    resp = self.session.get(url, params=params,
                                            verify=self.verify_ssl, timeout=self.timeout)
                resp.raise_for_status()
                return resp.json() if resp.text.strip() else {}
            except requests.exceptions.HTTPError as e:
                if resp.status_code == 404:
                    logger.debug("Endpoint not found: %s", endpoint)
                    return {}
                if attempt == self.max_retries:
                    logger.error("GET %s failed after %d attempts: %s", endpoint, attempt, e)
                    return {}
                time.sleep(1 * attempt)
            except requests.exceptions.RequestException as e:
                if attempt == self.max_retries:
                    logger.error("GET %s failed: %s", endpoint, e)
                    return {}
                time.sleep(1 * attempt)
        return {}

    def get_list(self, endpoint, key=None):
        """GET and extract list from response. Barracuda API wraps lists in
        {'data': {<key>: [...]}} or {'object': [...]} patterns."""
        data = self.get(endpoint)
        if not data:
            return []
        if isinstance(data, list):
            return data
        if "data" in data:
            inner = data["data"]
            if isinstance(inner, list):
                return inner
            if isinstance(inner, dict):
                if key and key in inner:
                    return inner[key] if isinstance(inner[key], list) else [inner[key]]
                for v in inner.values():
                    if isinstance(v, list):
                        return v
                return [inner]
        if "object" in data:
            obj = data["object"]
            return obj if isinstance(obj, list) else [obj]
        return [data] if isinstance(data, dict) else []

    def get_system_info(self):
        """Get system/firmware information."""
        return self.get("/system") or {}

    def get_services(self):
        """Get all configured virtual services."""
        return self.get_list("/services", key="services")

    def get_service_detail(self, service_name):
        """Get detailed config for a specific service."""
        return self.get(f"/services/{service_name}")

    def get_security_policies(self):
        """Get all WAF security policies."""
        return self.get_list("/security-policies", key="security-policies")

    def get_security_policy(self, policy_name):
        """Get a specific security policy."""
        return self.get(f"/security-policies/{policy_name}")

    def get_certificates(self):
        """Get all SSL certificates."""
        return self.get_list("/signed-certificate", key="signed-certificate")

    def get_trusted_certificates(self):
        """Get trusted CA certificates."""
        return self.get_list("/trusted-certificate", key="trusted-certificate")

    def get_network_interfaces(self):
        """Get network interface configuration."""
        return self.get_list("/network/interface", key="interface")

    def get_vlans(self):
        """Get VLAN configuration."""
        return self.get_list("/network/vlan", key="vlan")

    def get_access_control(self, service_name):
        """Get access control rules for a service."""
        return self.get_list(f"/services/{service_name}/global-acls", key="global-acls")

    def get_rate_control(self, service_name):
        """Get rate control policies for a service."""
        return self.get_list(f"/services/{service_name}/rate-control", key="rate-control")

    def get_content_rules(self, service_name):
        """Get content rules for a service."""
        return self.get_list(f"/services/{service_name}/content-rules", key="content-rules")

    def get_logging_config(self):
        """Get syslog and logging configuration."""
        return self.get("/syslog") or {}

    def get_admin_config(self):
        """Get administrative access settings."""
        return self.get("/admin") or {}

    def get_cluster_config(self):
        """Get HA/cluster configuration."""
        return self.get("/cluster") or {}


class AuthenticationError(Exception):
    pass
