import ipaddress
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen


USER_AGENT = "VulnPilot-ReportGen/0.4 authorized-scanner"
MAX_READ_BYTES = 512 * 1024
DEFAULT_TIMEOUT = 3
PORT_TIMEOUT = 0.75
MAX_WORKERS = 12
COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 587, 993, 995, 3000, 5000, 8000, 8080, 8443]
COMMON_PATHS = [
    "/",
    "/admin",
    "/login",
    "/api",
    "/api/docs",
    "/docs",
    "/swagger",
    "/swagger-ui",
    "/openapi.json",
    "/graphql",
    "/health",
    "/status",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
]
DEEP_PATHS = [
    "/admin/",
    "/administrator/",
    "/admin/login",
    "/admin.php",
    "/backup",
    "/backups",
    "/config",
    "/config.json",
    "/debug",
    "/dev",
    "/graphql",
    "/login/",
    "/logout",
    "/manage",
    "/metrics",
    "/phpinfo.php",
    "/server-status",
    "/test",
    "/uploads",
    "/vendor",
    "/version",
    "/wp-admin/",
    "/wp-login.php",
    "/api/v1",
    "/api/v2",
    "/api/swagger",
    "/api/swagger.json",
    "/api/openapi.json",
    "/swagger.json",
    "/swagger.yaml",
    "/redoc",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/.env",
    "/.git/HEAD",
    "/.svn/entries",
    "/.DS_Store",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
]
SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]
ENDPOINT_PATTERN = re.compile(
    rb"""(?:"|')((?:/api/|/v[0-9]+/|/[A-Za-z0-9_.~!$&'()*+,;=:@%-]+/)[A-Za-z0-9_./~!$&'()*+,;=:@?%#-]{2,160})(?:"|')"""
)


class ScannerError(Exception):
    pass


class DiscoveryParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = set()
        self.scripts = set()
        self.stylesheets = set()
        self.forms = []
        self.title_parts = []
        self.in_title = False
        self.generators = set()

    def handle_starttag(self, tag, attrs):
        attrs_dict = {name.lower(): value for name, value in attrs if value}

        if tag == "a" and attrs_dict.get("href"):
            self.links.add(attrs_dict["href"])
        elif tag == "script" and attrs_dict.get("src"):
            self.scripts.add(attrs_dict["src"])
        elif tag == "link" and attrs_dict.get("href"):
            self.stylesheets.add(attrs_dict["href"])
        elif tag == "form":
            self.forms.append({
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "get").upper(),
            })
        elif tag == "meta" and attrs_dict.get("name", "").lower() == "generator":
            self.generators.add(attrs_dict.get("content", ""))
        elif tag == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data.strip())

    @property
    def title(self):
        return " ".join(part for part in self.title_parts if part).strip()


def run_web_scan(target_url, options=None):
    options = options or {}
    start_time = time.perf_counter()
    started_at = now_iso()
    target_url = normalize_url(target_url)
    parsed = urlparse(target_url)
    hostname = parsed.hostname

    if not hostname:
        raise ScannerError("Target URL must include a hostname")

    profile = str(options.get("profile") or "web-baseline")
    deep_profile = profile == "deep-recon"
    scan_depth = clamp_int(options.get("scan_depth", 2 if deep_profile else 1), 0, 3)
    max_pages = clamp_int(options.get("max_pages", 80 if deep_profile else 25), 5, 120)
    include_ports = bool(options.get("include_ports", False))
    include_common_paths = bool(options.get("include_common_paths", True))
    include_recon = bool(options.get("include_recon", True))
    allow_private = bool(options.get("allow_private", False))
    requested_ports = normalize_ports(options.get("ports"))
    concurrency = clamp_int(options.get("concurrency", MAX_WORKERS), 2, MAX_WORKERS)
    path_profile = "deep" if deep_profile else str(options.get("path_profile") or "standard")

    result = {
        "target_url": target_url,
        "hostname": hostname,
        "started_at": started_at,
        "finished_at": None,
        "options": {
            "profile": profile,
            "scan_depth": scan_depth,
            "max_pages": max_pages,
            "include_ports": include_ports,
            "include_common_paths": include_common_paths,
            "include_recon": include_recon,
            "allow_private": allow_private,
            "ports": requested_ports,
            "concurrency": concurrency,
            "path_profile": path_profile,
        },
        "dns": {},
        "http": {},
        "security_headers": {},
        "tls": {},
        "robots": {},
        "sitemap": {},
        "recon": {},
        "crawl": {"pages": [], "discovered_urls": [], "forms": [], "assets": []},
        "common_paths": [],
        "ports": [],
        "observations": [],
        "errors": [],
        "summary": {},
        "timing": {},
    }

    dns_info = resolve_host(hostname)
    result["dns"] = dns_info
    private_ips = [ip for ip in dns_info["ip_addresses"] if is_private_ip(ip)]

    if private_ips and not allow_private:
        raise ScannerError("Target resolves to private or local IP space. Enable private target scanning for local lab targets.")

    tasks = {}
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        tasks[executor.submit(fetch_http, target_url)] = "http"
        tasks[executor.submit(fetch_known_file, target_url, "/robots.txt")] = "robots"
        tasks[executor.submit(fetch_known_file, target_url, "/sitemap.xml")] = "sitemap"
        tasks[executor.submit(crawl_site, target_url, scan_depth, max_pages, concurrency)] = "crawl"

        if parsed.scheme == "https":
            tasks[executor.submit(inspect_tls, hostname, parsed.port or 443)] = "tls"

        if include_common_paths:
            tasks[executor.submit(enumerate_common_paths, target_url, path_profile, concurrency)] = "common_paths"

        if include_ports:
            ports = requested_ports or COMMON_PORTS
            tasks[executor.submit(scan_ports, hostname, ports, concurrency)] = "ports"

        for future in as_completed(tasks):
            key = tasks[future]
            try:
                result[key] = future.result()
            except Exception as error:
                result["errors"].append({"task": key, "error": str(error)})

    if result["http"].get("headers"):
        result["security_headers"] = analyze_security_headers(result["http"]["headers"])

    if include_recon:
        result["recon"] = build_recon(result, concurrency)

    result["observations"] = build_observations(result)
    result["finished_at"] = now_iso()
    result["timing"] = {
        "elapsed_seconds": round(time.perf_counter() - start_time, 2),
        "started_at": result["started_at"],
        "finished_at": result["finished_at"],
    }
    result["summary"] = summarize_result(result)

    return result


def normalize_url(target_url):
    target_url = (target_url or "").strip()
    if not target_url:
        raise ScannerError("Target URL is required")

    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    parsed = urlparse(target_url)
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, ""))


def clamp_int(value, minimum, maximum):
    try:
        value = int(value)
    except (TypeError, ValueError):
        value = minimum
    return max(minimum, min(value, maximum))


def normalize_ports(ports):
    if not ports:
        return []

    normalized = []
    for port in ports[:32]:
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue

        if 1 <= port <= 65535 and port not in normalized:
            normalized.append(port)

    return normalized


def resolve_host(hostname):
    info = {
        "hostname": hostname,
        "ip_addresses": [],
        "addresses": [],
        "error": None,
    }

    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        info["error"] = str(error)
        return info

    seen = set()
    for family, _socktype, _proto, canonname, sockaddr in records:
        ip = sockaddr[0]
        if ip in seen:
            continue
        seen.add(ip)
        info["ip_addresses"].append(ip)
        info["addresses"].append({
            "ip": ip,
            "family": "IPv6" if family == socket.AF_INET6 else "IPv4",
            "canonname": canonname,
            "private": is_private_ip(ip),
        })

    return info


def is_private_ip(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return any([
        address.is_private,
        address.is_loopback,
        address.is_link_local,
        address.is_multicast,
        address.is_reserved,
        address.is_unspecified,
    ])


def fetch_http(url):
    fetched = fetch_url(url)
    info = {
        "url": url,
        "final_url": fetched.get("final_url"),
        "status_code": fetched.get("status_code"),
        "content_type": fetched.get("headers", {}).get("content-type", ""),
        "content_length": fetched.get("content_length", 0),
        "headers": fetched.get("headers", {}),
        "title": "",
        "forms": [],
        "technologies": [],
        "error": fetched.get("error"),
    }

    if fetched.get("body"):
        parser = parse_html(fetched["body"])
        info["title"] = parser.title
        info["forms"] = parser.forms[:20]
        info["technologies"] = detect_technologies(info["headers"], parser)

    return info


def fetch_url(url, timeout=DEFAULT_TIMEOUT):
    request = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml,text/plain;q=0.8,*/*;q=0.5",
        },
        method="GET",
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_READ_BYTES)
            headers = normalize_headers(response.headers.items())
            return {
                "status_code": response.status,
                "final_url": response.url,
                "headers": headers,
                "body": body,
                "content_length": len(body),
                "error": None,
            }
    except HTTPError as error:
        body = error.read(MAX_READ_BYTES)
        return {
            "status_code": error.code,
            "final_url": url,
            "headers": normalize_headers(error.headers.items()) if error.headers else {},
            "body": body,
            "content_length": len(body),
            "error": None,
        }
    except (URLError, TimeoutError, ssl.SSLError, socket.timeout, OSError) as error:
        return {
            "status_code": None,
            "final_url": url,
            "headers": {},
            "body": b"",
            "content_length": 0,
            "error": str(error),
        }


def normalize_headers(items):
    return {str(key).lower(): str(value) for key, value in items}


def parse_html(body):
    parser = DiscoveryParser()
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
    except Exception:
        pass
    return parser


def detect_technologies(headers, parser):
    technologies = []
    server = headers.get("server")
    powered_by = headers.get("x-powered-by")

    if server:
        technologies.append({"source": "server-header", "value": server})
    if powered_by:
        technologies.append({"source": "x-powered-by", "value": powered_by})

    for generator in sorted(parser.generators):
        technologies.append({"source": "meta-generator", "value": generator})

    return technologies


def analyze_security_headers(headers):
    normalized = {key.lower(): value for key, value in headers.items()}
    checks = {}

    for header in SECURITY_HEADERS:
        value = normalized.get(header)
        checks[header] = {
            "present": bool(value),
            "value": value or "",
        }

    return checks


def inspect_tls(hostname, port):
    info = {
        "hostname": hostname,
        "port": port,
        "protocol": "",
        "cipher": "",
        "subject": {},
        "issuer": {},
        "not_before": "",
        "not_after": "",
        "serial_number": "",
        "error": None,
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=DEFAULT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                info["protocol"] = tls_sock.version() or ""
                cipher = tls_sock.cipher()
                info["cipher"] = cipher[0] if cipher else ""
                info["subject"] = tuple_to_cert_dict(cert.get("subject", []))
                info["issuer"] = tuple_to_cert_dict(cert.get("issuer", []))
                info["not_before"] = cert.get("notBefore", "")
                info["not_after"] = cert.get("notAfter", "")
                info["serial_number"] = cert.get("serialNumber", "")
    except (ssl.SSLError, socket.timeout, OSError) as error:
        info["error"] = str(error)

    return info


def tuple_to_cert_dict(value):
    result = {}
    for group in value:
        for key, item_value in group:
            result[key] = item_value
    return result


def fetch_known_file(base_url, path):
    url = urljoin(base_url, path)
    fetched = fetch_url(url, timeout=DEFAULT_TIMEOUT)
    body = fetched.get("body", b"")

    return {
        "url": url,
        "status_code": fetched.get("status_code"),
        "content_type": fetched.get("headers", {}).get("content-type", ""),
        "content_length": fetched.get("content_length", 0),
        "preview": body[:1200].decode("utf-8", errors="replace") if body else "",
        "error": fetched.get("error"),
    }


def crawl_site(start_url, max_depth=1, max_pages=25, concurrency=MAX_WORKERS):
    start = urlparse(start_url)
    queue = [(start_url, 0)]
    seen = set()
    pages = []
    discovered = set()
    forms = []
    assets = set()

    while queue and len(pages) < max_pages:
        batch = []
        queued = set()

        while queue and len(batch) < concurrency and len(pages) + len(batch) < max_pages:
            url, depth = queue.pop(0)
            normalized = strip_fragment(url)

            if normalized in seen or normalized in queued:
                continue

            queued.add(normalized)
            batch.append((normalized, depth))

        if not batch:
            continue

        for url, _depth in batch:
            seen.add(url)

        with ThreadPoolExecutor(max_workers=min(concurrency, len(batch))) as executor:
            futures = {
                executor.submit(fetch_url, url): (url, depth)
                for url, depth in batch
            }

            for future in as_completed(futures):
                normalized, depth = futures[future]
                fetched = future.result()
                parser = parse_html(fetched.get("body", b""))
                page = {
                    "url": normalized,
                    "status_code": fetched.get("status_code"),
                    "content_type": fetched.get("headers", {}).get("content-type", ""),
                    "content_length": fetched.get("content_length", 0),
                    "title": parser.title,
                    "links_found": len(parser.links),
                    "forms_found": len(parser.forms),
                    "error": fetched.get("error"),
                }
                pages.append(page)

                for form in parser.forms:
                    forms.append({
                        "page_url": normalized,
                        "action": normalize_same_origin_url(normalized, form.get("action", ""), start),
                        "method": form.get("method", "GET"),
                    })

                for asset in parser.scripts.union(parser.stylesheets):
                    asset_url = normalize_same_origin_url(normalized, asset, start)
                    if asset_url:
                        assets.add(asset_url)

                for href in parser.links:
                    next_url = normalize_same_origin_url(normalized, href, start)
                    if not next_url:
                        continue

                    discovered.add(next_url)
                    if (
                        depth < max_depth
                        and next_url not in seen
                        and len(queue) + len(pages) < max_pages
                    ):
                        queue.append((next_url, depth + 1))

    return {
        "pages": pages,
        "discovered_urls": sorted(discovered)[:200],
        "forms": forms[:100],
        "assets": sorted(assets)[:200],
    }


def strip_fragment(url):
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def normalize_same_origin_url(base_url, candidate, start):
    if not candidate or candidate.startswith(("mailto:", "tel:", "javascript:", "#")):
        return ""

    joined = strip_fragment(urljoin(base_url, candidate))
    parsed = urlparse(joined)

    if parsed.scheme not in ("http", "https"):
        return ""

    if parsed.hostname != start.hostname:
        return ""

    return joined


def enumerate_common_paths(base_url, path_profile="standard", concurrency=MAX_WORKERS):
    parsed = urlparse(base_url)
    root = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
    paths = list(dict.fromkeys(COMMON_PATHS + (DEEP_PATHS if path_profile == "deep" else [])))

    def check_path(path):
        url = urljoin(root, path.lstrip("/"))
        fetched = fetch_url(url, timeout=DEFAULT_TIMEOUT)
        status_code = fetched.get("status_code")

        return {
            "path": path,
            "url": url,
            "status_code": status_code,
            "content_type": fetched.get("headers", {}).get("content-type", ""),
            "content_length": fetched.get("content_length", 0),
            "interesting": bool(status_code and status_code < 400 and path not in ("/", "/robots.txt", "/sitemap.xml")),
            "error": fetched.get("error"),
        }

    results = []
    with ThreadPoolExecutor(max_workers=min(concurrency, len(paths))) as executor:
        future_map = {executor.submit(check_path, path): path for path in paths}
        completed = {}

        for future in as_completed(future_map):
            completed[future_map[future]] = future.result()

    for path in paths:
        results.append(completed[path])

    return results


def scan_ports(hostname, ports, concurrency=MAX_WORKERS):
    ports = ports[:32]

    def check_port(port):
        status = "closed"
        error_text = ""

        try:
            with socket.create_connection((hostname, port), timeout=PORT_TIMEOUT):
                status = "open"
        except (socket.timeout, ConnectionRefusedError, OSError) as error:
            error_text = str(error)

        return {
            "port": port,
            "status": status,
            "error": error_text if status != "open" else "",
        }

    results = []
    with ThreadPoolExecutor(max_workers=min(concurrency, len(ports) or 1)) as executor:
        future_map = {executor.submit(check_port, port): port for port in ports}
        completed = {}

        for future in as_completed(future_map):
            completed[future_map[future]] = future.result()

    for port in ports:
        results.append(completed[port])

    return results


def build_recon(result, concurrency=MAX_WORKERS):
    http = result.get("http", {})
    crawl = result.get("crawl", {})
    common_paths = result.get("common_paths", [])
    assets = crawl.get("assets", [])[:40]
    endpoint_sources = []

    for known in (result.get("robots", {}), result.get("sitemap", {})):
        if known.get("preview"):
            endpoint_sources.extend(extract_endpoints(known["preview"].encode("utf-8", errors="replace")))

    script_assets = [
        asset for asset in assets
        if urlparse(asset).path.lower().endswith((".js", ".mjs", ".json"))
    ][:24]

    with ThreadPoolExecutor(max_workers=min(concurrency, len(script_assets) or 1)) as executor:
        future_map = {
            executor.submit(fetch_url, asset, DEFAULT_TIMEOUT): asset
            for asset in script_assets
        }

        for future in as_completed(future_map):
            asset = future_map[future]
            fetched = future.result()
            endpoints = extract_endpoints(fetched.get("body", b""))
            endpoint_sources.extend([
                {**endpoint, "source": asset}
                for endpoint in endpoints
            ])

    endpoints = []
    seen_endpoints = set()
    for endpoint in endpoint_sources:
        value = endpoint["value"]
        if value in seen_endpoints:
            continue
        seen_endpoints.add(value)
        endpoints.append(endpoint)

    interesting_paths = [
        item for item in common_paths
        if item.get("interesting")
    ]

    return {
        "dns_addresses": result.get("dns", {}).get("addresses", []),
        "technologies": http.get("technologies", []),
        "forms": crawl.get("forms", [])[:100],
        "assets": assets,
        "endpoints": endpoints[:120],
        "cookies": analyze_cookies(http.get("headers", {})),
        "interesting_paths": interesting_paths[:80],
        "security_headers": result.get("security_headers", {}),
        "tls": result.get("tls", {}),
    }


def extract_endpoints(body):
    endpoints = []

    for match in ENDPOINT_PATTERN.finditer(body or b""):
        value = match.group(1).decode("utf-8", errors="replace")
        if len(value) < 3 or value.startswith("//"):
            continue
        endpoints.append({
            "value": value,
            "source": "content",
        })

    return endpoints


def analyze_cookies(headers):
    raw_cookie = headers.get("set-cookie", "")
    if not raw_cookie:
        return []

    cookies = []
    for chunk in raw_cookie.split(","):
        parts = [part.strip() for part in chunk.split(";") if part.strip()]
        if not parts or "=" not in parts[0]:
            continue

        name = parts[0].split("=", 1)[0]
        flags = {part.lower() for part in parts[1:]}
        cookies.append({
            "name": name,
            "secure": "secure" in flags,
            "httponly": "httponly" in flags,
            "samesite": next((part for part in parts[1:] if part.lower().startswith("samesite=")), ""),
        })

    return cookies[:20]


def build_observations(result):
    observations = []

    if result["dns"].get("error"):
        observations.append({
            "severity": "medium",
            "category": "dns",
            "title": "DNS resolution failed",
            "detail": result["dns"]["error"],
        })

    http = result.get("http", {})
    if http.get("error"):
        observations.append({
            "severity": "medium",
            "category": "http",
            "title": "HTTP probe failed",
            "detail": http["error"],
        })
    elif http.get("status_code") and http["status_code"] >= 500:
        observations.append({
            "severity": "medium",
            "category": "http",
            "title": "Target returned a server error",
            "detail": f"Initial probe returned HTTP {http['status_code']}.",
        })

    missing_headers = [
        header for header, check in result.get("security_headers", {}).items()
        if not check.get("present")
    ]
    if missing_headers:
        observations.append({
            "severity": "low",
            "category": "headers",
            "title": "Missing security headers",
            "detail": ", ".join(missing_headers),
        })

    tls = result.get("tls", {})
    if tls.get("error"):
        observations.append({
            "severity": "medium",
            "category": "tls",
            "title": "TLS inspection failed",
            "detail": tls["error"],
        })

    exposed_paths = [
        item["path"] for item in result.get("common_paths", [])
        if item.get("interesting")
    ]
    if exposed_paths:
        observations.append({
            "severity": "info",
            "category": "content-discovery",
            "title": "Interesting paths responded",
            "detail": ", ".join(exposed_paths[:12]),
        })

    open_ports = [str(item["port"]) for item in result.get("ports", []) if item.get("status") == "open"]
    if open_ports:
        observations.append({
            "severity": "info",
            "category": "ports",
            "title": "Open ports detected",
            "detail": ", ".join(open_ports),
        })

    form_count = len(result.get("crawl", {}).get("forms", []))
    if form_count:
        observations.append({
            "severity": "info",
            "category": "crawl",
            "title": "Forms discovered",
            "detail": f"{form_count} form(s) found during same-origin crawl.",
        })

    endpoint_count = len(result.get("recon", {}).get("endpoints", []))
    if endpoint_count:
        observations.append({
            "severity": "info",
            "category": "recon",
            "title": "Client-side endpoints discovered",
            "detail": f"{endpoint_count} endpoint reference(s) found in same-origin assets.",
        })

    weak_cookies = [
        cookie["name"] for cookie in result.get("recon", {}).get("cookies", [])
        if not cookie.get("secure") or not cookie.get("httponly")
    ]
    if weak_cookies:
        observations.append({
            "severity": "low",
            "category": "cookies",
            "title": "Cookie hardening gaps",
            "detail": ", ".join(weak_cookies[:12]),
        })

    return observations


def summarize_result(result):
    ports = result.get("ports", [])
    common_paths = result.get("common_paths", [])
    crawl = result.get("crawl", {})
    security_headers = result.get("security_headers", {})

    return {
        "target_url": result.get("target_url"),
        "hostname": result.get("hostname"),
        "status_code": result.get("http", {}).get("status_code"),
        "title": result.get("http", {}).get("title", ""),
        "elapsed_seconds": result.get("timing", {}).get("elapsed_seconds", 0),
        "ip_count": len(result.get("dns", {}).get("ip_addresses", [])),
        "pages_crawled": len(crawl.get("pages", [])),
        "urls_discovered": len(crawl.get("discovered_urls", [])),
        "forms_discovered": len(crawl.get("forms", [])),
        "assets_discovered": len(crawl.get("assets", [])),
        "endpoints_discovered": len(result.get("recon", {}).get("endpoints", [])),
        "interesting_paths": len([item for item in common_paths if item.get("interesting")]),
        "open_ports": len([item for item in ports if item.get("status") == "open"]),
        "missing_security_headers": len([
            check for check in security_headers.values()
            if not check.get("present")
        ]),
        "observation_count": len(result.get("observations", [])),
    }


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")
