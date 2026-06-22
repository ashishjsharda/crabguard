"""
CrabGuard – HTTP Client with rate limiting and fingerprinting
"""
from __future__ import annotations
import time
import urllib.parse
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..config import CrabGuardConfig


class RateLimiter:
    def __init__(self, rps: float):
        self._interval = 1.0 / rps
        self._last = 0.0

    def wait(self):
        now = time.time()
        wait = self._interval - (now - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()


class CrabGuardHTTPClient:
    def __init__(self, config: CrabGuardConfig):
        self.config   = config
        self.session  = self._build_session()
        self._limiter = RateLimiter(config.requests_per_second)

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({"User-Agent": self.config.user_agent})
        s.verify  = self.config.verify_ssl
        s.max_redirects = self.config.max_redirects

        retry = Retry(total=2, backoff_factor=0.5,
                      status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("http://", adapter)
        s.mount("https://", adapter)

        if self.config.proxy:
            s.proxies = {"http": self.config.proxy, "https": self.config.proxy}
        return s

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        self._limiter.wait()
        try:
            return self.session.get(
                url,
                timeout=self.config.timeout,
                allow_redirects=True,
                **kwargs
            )
        except requests.exceptions.RequestException:
            return None

    def get_no_redirect(self, url: str, **kwargs) -> Optional[requests.Response]:
        self._limiter.wait()
        try:
            return self.session.get(
                url,
                timeout=self.config.timeout,
                allow_redirects=False,
                **kwargs
            )
        except requests.exceptions.RequestException:
            return None

    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        self._limiter.wait()
        try:
            return self.session.head(
                url,
                timeout=self.config.timeout,
                allow_redirects=True,
                **kwargs
            )
        except requests.exceptions.RequestException:
            return None


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    return parsed.geturl()


def extract_params(url: str) -> list[tuple[str, str]]:
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.parse_qsl(parsed.query)


def inject_param(url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new_params = [(k, value if k == param else v) for k, v in params]
    if not any(k == param for k, _ in params):
        new_params.append((param, value))
    new_query = urllib.parse.urlencode(new_params)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))
