"""
CrabGuard - Configuration
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CrabGuardConfig:
    api_key: Optional[str] = None
    timeout:             int   = 10
    max_redirects:       int   = 5
    user_agent:          str   = "CrabGuard/1.0 Security Scanner (https://ashishjsharda.github.io/crabguard)"
    verify_ssl:          bool  = True
    requests_per_second: float = 5.0
    max_concurrent:      int   = 3
    active_consent:      bool  = False
    sqli_depth:          int   = 2
    xss_depth:           int   = 2
    discovery_wordlist:  str   = "default"
    brand_name:          str   = "CrabGuard"
    brand_tagline:       str   = "Enterprise Web Security Scanner"
    report_author:       str   = ""
    proxy:               Optional[str] = None
    exclude_paths:       list  = field(default_factory=list)
    exclude_params:      list  = field(default_factory=list)

    def __post_init__(self):
        if self.api_key is None:
            self.api_key = os.environ.get("CRABGUARD_API_KEY")

    @property
    def is_pro(self) -> bool:
        return bool(self.api_key and self.api_key.startswith("cg_"))


DEFAULT_CONFIG = CrabGuardConfig()
