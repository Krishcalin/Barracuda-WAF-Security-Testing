"""Barracuda WAF REST API client with token authentication."""

import base64
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
        self._auth_method = None  # tracks which auth method works
        self.session = requests.Session()

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self.session.verify = False

    @staticmethod
    def _sanitize(value: str) -> str:
        """Strip whitespace, \\r, \\n from header/token values."""
        return value.replace("\r", "").replace("\n", "").strip()

    def _extract_token(self, data):
        """Extract token from various Barracuda API response formats.
        Handles: {"token": "x"}, {"Token": "x"}, {"login": {"token": "x"}},
                 {"data": {"token": "x"}}, {"login_token": "x"}"""
        if not isinstance(data, dict):
            return ""
        # Direct token keys
        for key in ("token", "Token", "login_token", "auth_token"):
            if key in data and isinstance(data[key], str):
                return self._sanitize(data[key])
        # Nested under "login", "data", or "response"
        for wrapper in ("login", "data", "response"):
            inner = data.get(wrapper)
            if isinstance(inner, dict):
                for key in ("token", "Token", "login_token", "auth_token"):
                    if key in inner and isinstance(inner[key], str):
                        return self._sanitize(inner[key])
        return ""

    def _try_auth_request(self, test_url):
        """Test if current session auth works against a known endpoint.
        Returns True if response is not 401."""
        try:
            resp = self.session.get(test_url, verify=self.verify_ssl, timeout=self.timeout)
            return resp.status_code != 401
        except Exception:
            return False

    def _apply_auth(self, token):
        """Try multiple auth header formats until one works.
        Barracuda WAF firmware versions use different auth mechanisms."""
        test_url = f"{self.base_url}/system"

        # Method 1: Basic <token> (most common in v3.2 API)
        self.session.headers.update({"Authorization": self._sanitize(f"Basic {token}")})
        if self._try_auth_request(test_url):
            self._auth_method = "Basic"
            logger.info("Auth method: Authorization: Basic <token>")
            return True

        # Method 2: Bearer <token>
        self.session.headers.update({"Authorization": self._sanitize(f"Bearer {token}")})
        if self._try_auth_request(test_url):
            self._auth_method = "Bearer"
            logger.info("Auth method: Authorization: Bearer <token>")
            return True

        # Method 3: Raw token as Authorization header
        self.session.headers.update({"Authorization": self._sanitize(token)})
        if self._try_auth_request(test_url):
            self._auth_method = "Raw"
            logger.info("Auth method: Authorization: <token>")
            return True

        # Method 4: Basic auth with base64(username:password)
        basic_creds = base64.b64encode(
            f"{self.username}:{self.password}".encode()
        ).decode()
        self.session.headers.update({"Authorization": f"Basic {basic_creds}"})
        if self._try_auth_request(test_url):
            self._auth_method = "BasicAuth"
            logger.info("Auth method: Authorization: Basic base64(user:pass)")
            return True

        # Method 5: Token as query parameter (clear auth header)
        self.session.headers.pop("Authorization", None)
        self.session.params = {"token": token}
        if self._try_auth_request(test_url):
            self._auth_method = "QueryParam"
            logger.info("Auth method: ?token=<token> query parameter")
            return True

        # Cleanup on failure
        self.session.params = {}
        logger.error("All authentication methods failed")
        return False

    def login(self):
        """Authenticate and obtain API token."""
        url = f"{self.base_url}/login"
        payload = {"username": self.username, "password": self.password}

        try:
            # Try JSON payload first, fall back to form-encoded
            resp = self.session.post(url, json=payload,
                                     verify=self.verify_ssl, timeout=self.timeout)
            if resp.status_code in (400, 415):
                logger.debug("JSON login failed (%d), trying form-encoded...",
                             resp.status_code)
                resp = self.session.post(url, data=payload,
                                         verify=self.verify_ssl, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            logger.debug("Login response: %s", data)

            self.token = self._extract_token(data)
            if not self.token:
                raise AuthenticationError(
                    f"No token found in login response. "
                    f"Response keys: {list(data.keys()) if isinstance(data, dict) else type(data)}"
                )

            # If we already know which auth method works, use it directly
            if self._auth_method == "BasicAuth":
                basic_creds = base64.b64encode(
                    f"{self.username}:{self.password}".encode()
                ).decode()
                self.session.headers.update({"Authorization": f"Basic {basic_creds}"})
            elif self._auth_method == "QueryParam":
                self.session.headers.pop("Authorization", None)
                self.session.params = {"token": self.token}
            elif self._auth_method:
                prefix = {"Basic": "Basic ", "Bearer": "Bearer ", "Raw": ""}
                hdr = self._sanitize(f"{prefix[self._auth_method]}{self.token}")
                self.session.headers.update({"Authorization": hdr})
            else:
                # First login — probe which auth method works
                if not self._apply_auth(self.token):
                    raise AuthenticationError(
                        "Login succeeded but all auth methods rejected. "
                        "Check WAF firmware version and API compatibility."
                    )

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
                safe_token = self._sanitize(self.token)
                self.session.delete(f"{self.base_url}/login/{safe_token}",
                                    verify=self.verify_ssl, timeout=self.timeout)
            except Exception:
                pass
            self.token = None
            self.session.params = {}

    def get(self, endpoint, params=None):
        """GET request with retry logic. Returns parsed JSON or empty dict."""
        url = f"{self.base_url}{endpoint}"
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self.session.get(url, params=params,
                                        verify=self.verify_ssl, timeout=self.timeout)

                # 401 — token expired, re-authenticate once and retry
                if resp.status_code == 401:
                    logger.warning("401 on %s (attempt %d), re-authenticating...",
                                   endpoint, attempt)
                    try:
                        self.login()
                    except (AuthenticationError, ConnectionError) as auth_err:
                        logger.error("Re-authentication failed: %s", auth_err)
                        return {}
                    resp = self.session.get(url, params=params,
                                            verify=self.verify_ssl, timeout=self.timeout)
                    if resp.status_code == 401:
                        logger.error("Still 401 after re-auth on %s — "
                                     "check credentials or permissions", endpoint)
                        return {}

                # 403 — insufficient permissions, do not retry
                if resp.status_code == 403:
                    logger.warning("403 on %s — insufficient privileges, skipping",
                                   endpoint)
                    return {}

                # 404 — endpoint not available on this WAF version
                if resp.status_code == 404:
                    logger.debug("404 on %s — endpoint not found", endpoint)
                    return {}

                resp.raise_for_status()
                return resp.json() if resp.text.strip() else {}
            except requests.exceptions.HTTPError as e:
                if attempt == self.max_retries:
                    logger.error("GET %s failed after %d attempts: %s",
                                 endpoint, attempt, e)
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

    def get_backup_config(self):
        """Get backup configuration."""
        return self.get("/backup") or {}

    def get_license_info(self):
        """Get license and subscription information."""
        return self.get("/license") or {}


class AuthenticationError(Exception):
    pass
