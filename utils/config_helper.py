"""Shared helpers for robust config extraction from Barracuda WAF API responses."""


def safe_int(value, default=0):
    """Convert value to int safely, returning default on failure."""
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_str(value, default=""):
    """Convert value to lowercase string safely."""
    if value is None:
        return default
    return str(value).strip()


def is_disabled(value):
    """Check if a config value represents a disabled/off state."""
    if not value:
        return True
    if isinstance(value, str):
        return value.lower() in ("off", "no", "disabled", "none", "false", "0", "")
    return False


def is_enabled(value):
    """Check if a config value represents an enabled/on state."""
    if not value:
        return False
    if isinstance(value, str):
        return value.lower() in ("on", "yes", "enabled", "true", "1", "active")
    return bool(value)


def deep_get(cfg, *key_paths, default=None):
    """Extract a value from nested config, trying multiple key paths.

    Each key_path can be:
      - A string: direct key lookup
      - A tuple of strings: nested lookup (key1 -> key2 -> ...)

    Example:
        deep_get(cfg,
                 "attack-action",
                 ("web-firewall-policy", "attack-action"),
                 ("policy", "attack-action"),
                 default="")
    """
    for path in key_paths:
        if isinstance(path, str):
            path = (path,)
        result = cfg
        found = True
        for key in path:
            if isinstance(result, dict) and key in result:
                result = result[key]
            else:
                found = False
                break
        if found and result is not None:
            return result
    return default


def extract_config(detail, fallback=None):
    """Extract the actual config dict from a Barracuda API response.

    Handles:
      - {"data": {config}}
      - {"data": {"name": {config}}}
      - {config} (already unwrapped)
      - Merges with fallback if provided
    """
    if not isinstance(detail, dict):
        return fallback or {}

    cfg = detail
    # Unwrap "data" if present
    if "data" in cfg and isinstance(cfg["data"], dict):
        cfg = cfg["data"]

    # If the unwrapped dict has a single key that's a dict, unwrap further
    dict_vals = {k: v for k, v in cfg.items() if isinstance(v, dict)}
    if len(dict_vals) == 1 and len(cfg) <= 3:
        cfg = next(iter(dict_vals.values()))

    return cfg
