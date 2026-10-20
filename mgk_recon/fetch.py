"""HTTP fetching with redirect-chain evidence.

Every observation is returned as an evidence-bearing record so the
dossier never makes an unsourced claim.
"""
import urllib.request
import urllib.error
from urllib.parse import urljoin
from dataclasses import dataclass, field


@dataclass
class Evidence:
    """One observation with its source."""
    claim: str
    source: str

    def to_dict(self):
        return {"claim": self.claim, "source": self.source}


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    redirect_chain: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    body_excerpt: str = ""
    error: str = ""


def fetch(url, timeout=10, max_redirects=10):
    """Fetch a URL, recording the full redirect chain as evidence."""
    chain, current, redirects = [], url, 0
    opener = urllib.request.build_opener(_NoRedirect())
    req_headers = {"User-Agent": "mgk-recon/0.1 (+passive recon skill)"}

    while redirects <= max_redirects:
        req = urllib.request.Request(current, headers=req_headers)
        try:
            response = opener.open(req, timeout=timeout)
            return FetchResult(
                url=url,
                final_url=current,
                status=response.status,
                redirect_chain=chain,
                headers=dict(response.headers.items()),
                body_excerpt=response.read(200_000).decode("utf-8", errors="replace"),
            )
        except urllib.error.HTTPError as error:
            if error.code in (301, 302, 303, 307, 308) and error.headers.get("Location"):
                nxt = urljoin(current, error.headers["Location"])
                chain.append({"from": current, "to": nxt, "status": error.code})
                current, redirects = nxt, redirects + 1
                continue
            return FetchResult(url=url, final_url=current, status=error.code,
                               redirect_chain=chain, headers=dict(error.headers.items()),
                               error=f"HTTP {error.code}")
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            return FetchResult(url=url, final_url=current, status=0,
                               redirect_chain=chain, error=str(error))
    return FetchResult(url=url, final_url=current, status=0, redirect_chain=chain,
                       error="too many redirects")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
