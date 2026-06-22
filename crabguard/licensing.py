"""
CrabGuard – API Key Validation & Tier Management

Free tier  : passive scan, HTML report, CrabGuard branding
Pro tier   : active scan, PDF report, white-label, higher rate limits
Enterprise : team features, scan history, SLA (managed server-side)

Validation hits https://crabguard.io/api/v1/validate
Key format : cg_live_<32 chars>  (production)
             cg_test_<32 chars>  (sandbox)
"""
from __future__ import annotations
import hashlib
import os
from dataclasses import dataclass
from typing import Optional

import requests as _requests


VALIDATE_URL  = "https://crabguard.io/api/v1/validate"
CACHE: dict   = {}   # Simple in-process cache — avoid hammering the API


@dataclass
class LicenseInfo:
    valid:       bool
    tier:        str          # "free" | "pro" | "enterprise"
    email:       str  = ""
    org:         str  = ""
    error:       str  = ""

    @property
    def is_pro(self)        -> bool: return self.tier in ("pro", "enterprise")
    @property
    def is_enterprise(self) -> bool: return self.tier == "enterprise"


def validate(api_key: Optional[str]) -> LicenseInfo:
    """
    Validate an API key against crabguard.io.
    Falls back to free tier gracefully if the server is unreachable.
    Results are cached for the process lifetime.
    """
    if not api_key:
        return LicenseInfo(valid=True, tier="free")

    # Check in-process cache
    cache_key = hashlib.sha256(api_key.encode()).hexdigest()[:16]
    if cache_key in CACHE:
        return CACHE[cache_key]

    # Basic format check before hitting the network
    if not (api_key.startswith("cg_live_") or api_key.startswith("cg_test_")):
        info = LicenseInfo(
            valid=False, tier="free",
            error="Invalid key format. Keys start with cg_live_ or cg_test_. "
                  "Get yours at https://crabguard.io/pricing"
        )
        CACHE[cache_key] = info
        return info

    # Hit the validation endpoint
    try:
        resp = _requests.post(
            VALIDATE_URL,
            json={"api_key": api_key},
            timeout=5,
            headers={"User-Agent": "CrabGuard/1.0"},
        )
        if resp.status_code == 200:
            data  = resp.json()
            info  = LicenseInfo(
                valid=data.get("valid", False),
                tier=data.get("tier", "free"),
                email=data.get("email", ""),
                org=data.get("org", ""),
            )
        elif resp.status_code == 401:
            info = LicenseInfo(valid=False, tier="free",
                               error="Invalid or expired API key. Check https://crabguard.io/dashboard")
        else:
            # Server error — fail open to free tier so scan still works
            info = LicenseInfo(valid=True, tier="free",
                               error=f"Could not validate key (HTTP {resp.status_code}) — running as free tier")
    except Exception:
        # Network error — fail open so the tool still works offline
        info = LicenseInfo(valid=True, tier="free",
                           error="Could not reach crabguard.io — running as free tier")

    CACHE[cache_key] = info
    return info


def check_feature(feature: str, license_info: LicenseInfo) -> tuple[bool, str]:
    """
    Returns (allowed: bool, message: str).
    Call before running any Pro-gated feature.
    """
    PRO_FEATURES = {
        "active_scan":   "Active scanning (SQLi, XSS, SSRF, discovery)",
        "pdf_report":    "PDF report generation",
        "white_label":   "White-label / custom branding on reports",
        "deep_discovery":"Extended discovery wordlist (medium/full)",
    }

    if feature not in PRO_FEATURES:
        return True, ""

    if license_info.is_pro:
        return True, ""

    feature_name = PRO_FEATURES[feature]
    msg = (
        f"\n  ┌─────────────────────────────────────────────────────┐\n"
        f"  │  🔒  {feature_name:<49}│\n"
        f"  │      requires a CrabGuard Pro API key.              │\n"
        f"  │                                                     │\n"
        f"  │  Get yours at: https://crabguard.io/pricing         │\n"
        f"  │  Then run:  export CRABGUARD_API_KEY=cg_live_...    │\n"
        f"  └─────────────────────────────────────────────────────┘\n"
    )
    return False, msg
