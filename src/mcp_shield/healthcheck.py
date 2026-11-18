"""Container health check: the HTTP face is up when an unauthenticated POST gets 401.

python -m mcp_shield.healthcheck [url]
"""

from __future__ import annotations

import sys
import urllib.error
import urllib.request


def main(url: str = "http://127.0.0.1:8765/mcp") -> int:
    try:
        urllib.request.urlopen(urllib.request.Request(url, method="POST"), timeout=3)
    except urllib.error.HTTPError as e:
        return 0 if e.code == 401 else 1  # 401 = running, and auth is enforced
    except OSError:
        return 1
    return 1  # 2xx without a token would mean auth is off: unhealthy


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:2]))
