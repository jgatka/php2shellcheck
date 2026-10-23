# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Josh Gatka
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import asyncio
import errno
import ipaddress
import os
import re
import socket
import ssl
import sys
import tempfile
import time
import warnings
from urllib.parse import urljoin, urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver

ASCII_ART = r"""
    ___  _  _ ___  ___  ____ _  _ ____ _    _    ____ _  _ ____ ____ _  _
   |__] |__| |__]  __] [__  |__| |___ |    |    |    |__| |___ |    |_/
   |    |  | |    |__  ___] |  | |___ |___ |___ |___ |  | |___ |___ | \
============================ PHP2SHELLCHECK =============================
"""

DEFAULT_OUTPUT = "scan_results.txt"
MAX_TARGET_LINE = 512
MAX_HEADER_VALUE = 300
MAX_NETWORK_SIZE = 65536
MAX_REDIRECTS = 3
CONCURRENCY = 50

# First fixed release on each branch named in GHSA-w8hw-w9fx-j79w and
# GHSA-6wmf-4rv5-p3rp. Branches older than 8.2 are end of life and get no fix.
FIXED_RELEASES = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}
OLDEST_SUPPORTED = (8, 2)

VULNERABLE = "VULNERABLE"
END_OF_LIFE = "END OF LIFE"
VENDOR_BUILD = "VENDOR BUILD"
UNKNOWN = "VERSION UNKNOWN"
PATCHED = "PATCHED"

# Worst first. A host takes the worst status seen on any port.
STATUS_ORDER = (VULNERABLE, END_OF_LIFE, VENDOR_BUILD, UNKNOWN, PATCHED)
INDICATOR_STATUSES = (VULNERABLE, END_OF_LIFE, VENDOR_BUILD, UNKNOWN)

# Distro vendors backport security fixes without changing the upstream version,
# so a vendor's 8.3.6 or 7.4.33 can be fixed. Branches older than this are not
# shipped by any vendor release that is still maintained.
VENDOR_MIN_BRANCH = (7, 4)

PHP_VERSION = re.compile(
    r"(?i)\bPHP/(\d+)(?:\.(\d+))?(?:\.(\d+))?([-+~][0-9A-Za-z.+~-]*)?"
)
PHP_WORD = re.compile(r"(?i)\bphp\b")
PHP_SESSION_COOKIE = re.compile(r"(?i)(?:^|[\s;,])PHPSESSID=")
DISTRO_SUFFIX = re.compile(r"(?i)ubuntu|deb|\.el\d|el\d|sury|suse|amzn|alpine|fc\d")
# Sury, Alpine, and Fedora ship upstream patch releases, so their version is
# the real one. The others backport fixes into a frozen upstream version.
UPSTREAM_SUFFIX = re.compile(r"(?i)sury|alpine|fc\d")
# Apache names the OS in the Server header, e.g. "Apache/2.4.57 (Rocky Linux)".
# Plain CentOS is left out: CentOS Linux 7 and 8 are end of life.
SERVER_VENDOR = re.compile(
    r"(?i)\((Ubuntu|Debian|Red Hat[^)]*|Rocky Linux|AlmaLinux|CentOS Stream|"
    r"Oracle[^)]*|SUSE[^)]*|openSUSE[^)]*)\)"
)
HOSTNAME = re.compile(
    r"(?=.{1,253}$)"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*",
    re.IGNORECASE,
)

DEFAULT_PORT_SPEC = "80,443,8080,8443"
MAX_PORTS = 256
# Ports with a well-known scheme. Any other port is tried over HTTPS first and
# then plain HTTP, unless the -p entry names one, e.g. 9000/http.
KNOWN_SCHEMES = {
    80: "http",
    81: "http",
    591: "http",
    8000: "http",
    8008: "http",
    8080: "http",
    8081: "http",
    8888: "http",
    443: "https",
    4443: "https",
    8443: "https",
    9443: "https",
}
SCHEMES = ("http", "https")

# Many PHP apps send no PHP header from "/" (a static index or a redirect),
# so a port that answers without one gets a second request here.
FALLBACK_PATHS = ("/index.php",)

REDIRECT_CODES = (301, 302, 303, 307, 308)
DEFAULT_PORTS = {"http": 80, "https": 443}

# Certificate checks are off so a self-signed target can still be fingerprinted.
# Redirects are followed only to the same host, port, and scheme, so a response
# cannot steer the scan at another host.
SSL_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE
# Old PHP hosts are often the ones that only speak TLS 1.0/1.1 or legacy
# renegotiation. Allow them so a failed handshake does not hide a hit.
try:
    with warnings.catch_warnings():
        # Python 3.13+ warns that TLSv1 is deprecated; that is the point here.
        warnings.simplefilter("ignore", DeprecationWarning)
        SSL_CONTEXT.minimum_version = ssl.TLSVersion.TLSv1
except (AttributeError, ValueError):
    pass
try:
    SSL_CONTEXT.set_ciphers("DEFAULT:@SECLEVEL=0")
except ssl.SSLError:
    pass
SSL_CONTEXT.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)


def show_banner():
    """Print the banner. Green on a terminal, plain text when piped."""
    if sys.stdout.isatty():
        print("\033[1;32m" + ASCII_ART + "\033[0m")
    else:
        print(ASCII_ART)


def error(message):
    print(message, file=sys.stderr)


def format_duration(seconds):
    seconds = max(0, int(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours:d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


class ProgressBar:
    """Scan progress on stderr. One updating line on a terminal."""

    def __init__(self, total, stream=None):
        self.total = total
        self.done = 0
        self.hits = 0
        self.start = time.monotonic()
        self.stream = stream if stream is not None else sys.stderr
        self.tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self._last_report = 0
        self._closed = False

    def _bar(self):
        width = 28
        if self.total <= 0:
            return "#" * width
        filled = int(width * (self.done / self.total))
        if self.done and not filled:
            filled = 1
        if self.done >= self.total:
            filled = width
        return "#" * filled + "-" * (width - filled)

    def _eta(self):
        if self.done <= 0:
            return "--:--"
        if self.done >= self.total:
            return "00:00"
        elapsed = time.monotonic() - self.start
        if elapsed <= 0:
            return "--:--"
        remain = (self.total - self.done) * (elapsed / self.done)
        return format_duration(remain)

    def render(self):
        percent = (100.0 * self.done / self.total) if self.total else 100.0
        elapsed = format_duration(time.monotonic() - self.start)
        return (
            f"[{self._bar()}] {self.done}/{self.total} "
            f"{percent:5.1f}%  hits={self.hits}  "
            f"{elapsed} ETA {self._eta()}"
        )

    def tick(self, hit=False, message=None):
        if self._closed:
            return
        self.done += 1
        if hit:
            self.hits += 1
        line = self.render()
        if message:
            if self.tty:
                self.stream.write("\r\033[2K" + message + "\n")
            else:
                self.stream.write(message + "\n")
        if self.tty:
            self.stream.write("\r\033[2K" + line)
            self.stream.flush()
            return
        step = 1 if self.total <= 20 else max(1, self.total // 20)
        if (
            self.done == 1
            or self.done == self.total
            or self.done - self._last_report >= step
        ):
            self.stream.write(line + "\n")
            self.stream.flush()
            self._last_report = self.done

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self.tty:
            self.stream.write("\n")
            self.stream.flush()


def sanitize(value, limit=MAX_HEADER_VALUE):
    """Drop control characters so a header cannot forge extra report lines."""
    cleaned = []
    for char in value:
        if char in "\r\n\t" or not char.isprintable():
            cleaned.append(" ")
        else:
            cleaned.append(char)
    text = " ".join("".join(cleaned).split())
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def normalize_target(token):
    """Return a canonical host, or None when the token is not a host."""
    token = token.strip()
    if token.startswith("[") and token.endswith("]"):
        token = token[1:-1].strip()
    if not token or any(char.isspace() for char in token):
        return None
    if any(char in token for char in "/\\?#@"):
        return None
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        pass
    if ":" in token:
        return None
    host = token[:-1] if token.endswith(".") else token
    if HOSTNAME.fullmatch(host):
        return host
    return None


def host_from_url(value):
    """Return the host in a URL or a bare host name, or None.

    Accepts https://www.example.com/, www.example.com/path, and example.com.
    Only the host is kept; every probed port is still scanned.
    """
    text = value.strip()
    host = normalize_target(text)
    if host is not None:
        return host
    if "://" not in text:
        text = "//" + text
    try:
        parts = urlsplit(text)
        parts.port
    except ValueError:
        return None
    if parts.scheme and parts.scheme.lower() not in DEFAULT_PORTS:
        return None
    if not parts.hostname:
        return None
    return normalize_target(parts.hostname)


def expand_network(token):
    """Return the hosts in a CIDR block, or None when the token is not one.

    Blocks larger than MAX_NETWORK_SIZE addresses return an empty list so a
    typo such as 10.0.0.0/8 is skipped instead of scanned.
    """
    if "/" not in token:
        return None
    try:
        network = ipaddress.ip_network(token.strip(), strict=False)
    except ValueError:
        return None
    if network.num_addresses > MAX_NETWORK_SIZE:
        return []
    if network.num_addresses <= 2:
        return [str(address) for address in network]
    return [str(address) for address in network.hosts()]


def host_for_url(host):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    if address.version == 6:
        return f"[{address}]"
    return str(address)


def load_targets(path):
    hosts = []
    seen = set()
    skipped = 0
    duplicates = 0
    with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
        for line in handle:
            if len(line) > MAX_TARGET_LINE:
                skipped += 1
                continue
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            expanded = expand_network(raw)
            if expanded is None:
                host = normalize_target(raw)
                expanded = [host] if host is not None else []
            if not expanded:
                skipped += 1
                continue
            for host in expanded:
                key = host.lower()
                if key in seen:
                    duplicates += 1
                    continue
                seen.add(key)
                hosts.append(host)
    return hosts, skipped, duplicates


def parse_ports(spec):
    """Return [(port, scheme)] from a list like "80,443,9000/http,8000-8010".

    scheme is None when it should be detected. Raises ValueError with a
    message for the user.
    """
    ports = []
    seen = set()
    for raw in spec.split(","):
        item = raw.strip().lower()
        if not item:
            continue
        scheme = None
        if "/" in item:
            item, scheme = (part.strip() for part in item.split("/", 1))
            if scheme not in SCHEMES:
                raise ValueError(f"'{sanitize(raw, limit=40)}': scheme must be http or https")
        bounds = item.split("-", 1)
        if not all(bound.isdigit() for bound in bounds):
            raise ValueError(f"'{sanitize(raw, limit=40)}' is not a port or port range")
        low, high = int(bounds[0]), int(bounds[-1])
        if not 1 <= low <= high <= 65535:
            raise ValueError(f"'{sanitize(raw, limit=40)}' is outside 1-65535")
        if high - low + 1 > MAX_PORTS:
            raise ValueError(f"'{sanitize(raw, limit=40)}' is more than {MAX_PORTS} ports")
        for port in range(low, high + 1):
            if port in seen:
                continue
            seen.add(port)
            ports.append((port, scheme or KNOWN_SCHEMES.get(port)))
            if len(ports) > MAX_PORTS:
                raise ValueError(f"more than {MAX_PORTS} ports given")
    if not ports:
        raise ValueError("no ports given")
    return ports


def describe_ports(ports):
    """Return "80, 443, and 9000" for the start-up message."""
    names = [str(port) for port, _scheme in ports]
    if len(names) <= 2:
        return " and ".join(names)
    return ", ".join(names[:-1]) + ", and " + names[-1]


def is_local_address(text):
    """True for loopback, unspecified (0.0.0.0), and link-local addresses."""
    try:
        address = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    return address.is_loopback or address.is_unspecified or address.is_link_local


class ExternalResolver(AbstractResolver):
    """Drop local addresses from hostname lookups.

    A stale DNS record pointing at 127.0.0.1 or 0.0.0.0 would otherwise send
    the probe to the scanning machine, and any PHP running there would be
    reported against the client's hostname. IP targets do not pass through a
    resolver, so a 127.0.0.1 written in the target list is still scanned.
    """

    def __init__(self):
        self._resolver = aiohttp.DefaultResolver()
        self.local_hosts = set()

    async def resolve(self, host, port=0, family=socket.AF_INET):
        results = await self._resolver.resolve(host, port, family)
        kept = [item for item in results if not is_local_address(item["host"])]
        if not kept:
            self.local_hosts.add(host.lower().rstrip("."))
            raise OSError(f"{host} resolves only to local addresses")
        return kept

    async def close(self):
        await self._resolver.close()


def parse_version(text):
    """Return (major, minor, patch, suffix) from a PHP/x.y.z token, or None."""
    match = PHP_VERSION.search(text)
    if not match:
        return None
    major, minor, patch, suffix = match.groups()
    return (
        int(major),
        int(minor) if minor is not None else None,
        int(patch) if patch is not None else None,
        suffix or "",
    )


def vendor_build(version, vendor=None):
    """Return the vendor that backports fixes into this build, or None."""
    _major, _minor, _patch, suffix = version
    if suffix and UPSTREAM_SUFFIX.search(suffix):
        return None
    if suffix and DISTRO_SUFFIX.search(suffix):
        return "distro"
    return vendor


def classify(version, vendor=None):
    """Return (status, note) for a parsed version, or for None.

    vendor is the OS named in the Server header of the same response. A vendor
    build that would be VULNERABLE or END OF LIFE by its upstream number is
    VENDOR BUILD instead, because the fix may have been backported.
    """
    if version is None:
        return UNKNOWN, "PHP detected, no version shown"
    major, minor, patch, suffix = version
    backport = vendor_build(version, vendor)
    note = ""
    if suffix and DISTRO_SUFFIX.search(suffix):
        note = "distro build; vendor may have backported the fix, check the package changelog"
    vendor_note = (
        f"{backport} build; vendor may have backported the fix, check the package changelog"
        if backport
        else ""
    )
    if major < OLDEST_SUPPORTED[0] or (
        minor is not None and (major, minor) < OLDEST_SUPPORTED
    ):
        if backport and minor is not None and (major, minor) >= VENDOR_MIN_BRANCH:
            return VENDOR_BUILD, f"{vendor_note}; upstream branch {major}.{minor} is end of life"
        return END_OF_LIFE, note or "branch is end of life, no fix released"
    if minor is None:
        return UNKNOWN, "PHP major version only"
    fixed = FIXED_RELEASES.get((major, minor))
    if fixed is None:
        return UNKNOWN, f"branch {major}.{minor} is not listed in the advisories"
    if patch is None:
        return UNKNOWN, f"patch level not shown; fixed in {major}.{minor}.{fixed}"
    if patch < fixed:
        if backport:
            return VENDOR_BUILD, f"{vendor_note}; upstream fix is {major}.{minor}.{fixed}"
        return VULNERABLE, note or f"fixed in {major}.{minor}.{fixed}"
    return PATCHED, note


def worst_status(statuses):
    for status in STATUS_ORDER:
        if status in statuses:
            return status
    return None


def extract_signals(header_items):
    """Return (source, value, version, vendor) for each header that shows PHP.

    vendor is the OS named in a Server header of the same response, or None.
    """
    vendor = None
    for key, value in header_items:
        if str(key).lower() == "server":
            match = SERVER_VENDOR.search(str(value))
            if match:
                vendor = sanitize(match.group(1), limit=40)
                break
    signals = []
    for key, value in header_items:
        name = str(key).lower()
        cleaned = sanitize(str(value))
        if name == "x-powered-by" and PHP_WORD.search(cleaned):
            signals.append(("X-Powered-By", cleaned, parse_version(cleaned), vendor))
        elif name == "server" and PHP_VERSION.search(cleaned):
            signals.append(("Server", cleaned, parse_version(cleaned), vendor))
        elif name == "set-cookie" and PHP_SESSION_COOKIE.search(" " + cleaned):
            signals.append(("Set-Cookie", "PHPSESSID", None, vendor))
    return signals


def matching_headers(header_items, port, scheme, path="/"):
    """Return (status, line) for each PHP signal in a response."""
    found = []
    label = f"[Port {port}/{scheme.upper()}]"
    if path != "/":
        label = f"{label} {sanitize(path, limit=100)}"
    for source, value, version, vendor in extract_signals(header_items):
        status, note = classify(version, vendor)
        rendered = f"{label} {source}: {value} -> {status}"
        if note:
            rendered = f"{rendered} ({note})"
        found.append((status, rendered))
    return found


def host_status(indicators):
    """A host takes the worst versioned status; UNKNOWN only when no version."""
    statuses = {status for status, _line in indicators}
    versioned = statuses - {UNKNOWN}
    return worst_status(versioned) or worst_status(statuses)


def format_hit(host, status, indicators):
    lines = [f"[+] {host} [{status}]"]
    lines.extend(f"  {line}" for _status, line in indicators)
    return "\n".join(lines)


def paths_same(left, right):
    try:
        return os.path.samefile(left, right)
    except OSError:
        return os.path.abspath(left) == os.path.abspath(right)


def parse_arguments():
    description_text = (
        f"{ASCII_ART}\n"
        "Description:\n"
        "  This script checks for indicators of vulnerability to CVE-2026-109618 "
        "and CVE-2026-109619.\n"
        "  It probes ports 80, 443, 8080, and 8443 (change with -p), reads the\n"
        "  X-Powered-By and Server headers and the PHPSESSID cookie, then compares\n"
        "  any PHP version shown against the fixed releases (8.2.35, 8.3.36, 8.4.27,\n"
        "  8.5.12).\n"
        "  A match is an indicator from a banner. It does not prove the CVE is "
        "exploitable.\n"
        "\n"
        "  Hosts that show PHP are listed with a status. The file ends with a\n"
        "  summary of targets, hosts that responded, and hosts per status.\n"
        "  Use -q to print vulnerable, end-of-life, vendor-build, and unknown-version\n"
        "  hosts and nothing else."
    )

    parser = argparse.ArgumentParser(
        prog="php2shellcheck.py",
        description=description_text,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )

    parser.add_argument(
        "-t",
        "--target",
        dest="target_file",
        metavar="TARGET_FILE",
        help="Text file of IP addresses, hostnames, or CIDR blocks, one per line.",
    )
    parser.add_argument(
        "-u",
        "--url",
        dest="urls",
        action="append",
        default=[],
        metavar="URL",
        help="One URL or hostname to scan, such as https://www.example.com/ or "
        "example.com. Repeat to add more.",
    )
    parser.add_argument(
        "-p",
        "--ports",
        dest="ports",
        default=DEFAULT_PORT_SPEC,
        metavar="PORTS",
        help=f"Comma-separated ports or ranges to probe (default: {DEFAULT_PORT_SPEC}). "
        "Ports other than the common HTTP and HTTPS ones are tried over HTTPS, then "
        "HTTP. Add /http or /https to force one, e.g. 80,443,9000/http,8000-8010.",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        default=DEFAULT_OUTPUT,
        metavar="OUTPUT_FILE",
        help=f"Results file to write (default: {DEFAULT_OUTPUT}).",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Quiet mode. Print a host only when it shows a vulnerability indicator.",
    )
    parser.add_argument(
        "-h",
        "--help",
        action="store_true",
        help="Show this help message and exit.",
    )

    args = parser.parse_args()

    if args.help:
        parser.print_help()
        sys.exit(0)

    if not args.target_file and not args.urls:
        show_banner()
        error("Error: A target file (-t) or URL (-u) is required.\n")
        parser.print_help(sys.stderr)
        sys.exit(1)

    try:
        args.ports = parse_ports(args.ports)
    except ValueError as exc:
        error(f"Error: Invalid port list (-p): {exc}.")
        sys.exit(1)

    parent = os.path.dirname(os.path.abspath(args.output_file))
    if parent and not os.path.isdir(parent):
        error(f"Error: Output directory '{parent}' does not exist.")
        sys.exit(1)

    if args.target_file and paths_same(args.target_file, args.output_file):
        error("Error: Output file must not be the same as the target file.")
        sys.exit(1)

    return args


def same_origin_redirect(location, url, host, port, scheme):
    """Return the next URL when a redirect stays on this host, port, and scheme."""
    target = urlsplit(urljoin(url, location))
    if target.scheme != scheme or (target.hostname or "") != host.lower():
        return None
    try:
        target_port = target.port or DEFAULT_PORTS[scheme]
    except ValueError:
        return None
    if target_port != port:
        return None
    return target.geturl()


async def fetch_headers(session, url, request_kwargs, retries):
    """Return (status, Location, header items), or None when nothing answered."""
    for attempt in range(retries + 1):
        try:
            async with session.get(url, **request_kwargs) as response:
                return (
                    response.status,
                    response.headers.get("Location"),
                    list(response.headers.items()),
                )
        except asyncio.TimeoutError:
            if attempt < retries:
                continue
            return None
        except (aiohttp.ClientError, OSError, ValueError):
            return None
    return None


PORT_CLOSED_ERRNOS = {
    getattr(errno, name)
    for name in ("ECONNREFUSED", "EHOSTUNREACH", "ENETUNREACH")
    if hasattr(errno, name)
}
# Both were added after aiohttp 3.8; an empty tuple matches nothing.
CONNECT_TIMEOUT = getattr(aiohttp, "ConnectionTimeoutError", ())
CONNECT_DNS_ERROR = getattr(aiohttp, "ClientConnectorDNSError", ())


async def detect_scheme(session, host, port, request_kwargs):
    """Return "https", "http", or None when the port does not accept a connection.

    Used for ports with no well-known scheme. HTTPS goes first because many
    TLS servers answer a plain request with a 400 page, which would hide them.
    """
    url = f"https://{host_for_url(host)}:{port}/"
    try:
        async with session.get(url, ssl=SSL_CONTEXT, **request_kwargs):
            return "https"
    except CONNECT_TIMEOUT:
        return None
    except aiohttp.ClientConnectorSSLError:
        return "http"
    except aiohttp.ClientConnectorError as exc:
        if getattr(exc.os_error, "errno", None) in PORT_CLOSED_ERRNOS:
            return None
        if isinstance(exc, CONNECT_DNS_ERROR):
            return None
        return "http"
    except asyncio.TimeoutError:
        # Connected but no TLS reply. A plain HTTP server waiting for a
        # request line behaves this way.
        return "http"
    except (aiohttp.ClientError, OSError, ValueError):
        return "http"


async def check_target(session, host, port, scheme, semaphore):
    """Return (responded, indicators) for one port.

    scheme is "http", "https", or None to detect it.
    """
    request_kwargs = {
        "allow_redirects": False,
        "timeout": aiohttp.ClientTimeout(total=10, connect=5, sock_read=5),
    }

    responded = False
    indicators = []
    seen = set()
    async with semaphore:
        if scheme is None:
            scheme = await detect_scheme(session, host, port, request_kwargs)
            if scheme is None:
                return False, []
        if scheme == "https":
            request_kwargs["ssl"] = SSL_CONTEXT
        base = f"{scheme}://{host_for_url(host)}:{port}"
        for path in ("/",) + FALLBACK_PATHS:
            url = base + path
            # Retry a timeout only on the first request; a port that has already
            # answered does not need a second chance on the fallback path.
            retries = 0 if responded else 1
            for _hop in range(MAX_REDIRECTS + 1):
                result = await fetch_headers(session, url, request_kwargs, retries)
                if result is None:
                    break
                responded = True
                status, location, headers = result
                shown = urlsplit(url).path or "/"
                # The same header on every hop of a redirect chain is one
                # finding. Keep the first path it was seen on.
                for item, (_status, key) in zip(
                    matching_headers(headers, port, scheme, shown),
                    matching_headers(headers, port, scheme),
                ):
                    if key not in seen:
                        seen.add(key)
                        indicators.append(item)
                if status not in REDIRECT_CODES or not location:
                    break
                url = same_origin_redirect(location, url, host, port, scheme)
                if url is None:
                    break
            if indicators or not responded:
                break
    return responded, indicators


async def process_host(session, host, semaphore, ports):
    results = await asyncio.gather(
        *(
            check_target(session, host, port, scheme, semaphore)
            for port, scheme in ports
        )
    )
    responded = any(item[0] for item in results)
    indicators = []
    for _responded, match_list in results:
        indicators.extend(match_list)
    return responded, indicators


def write_report(
    path, findings, totals, unfinished, skipped, duplicates, ports=None, local_hosts=0
):
    """Write findings, then the summary. Replace the file only when complete.

    findings is a list of (host, status, indicators). totals holds the
    finished, responded, and per-status counts.
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S %Z").strip()
    fixed = ", ".join(
        f"{major}.{minor}.{patch}" for (major, minor), patch in sorted(FIXED_RELEASES.items())
    )
    lines = [
        "PHP2SHELLCHECK SCAN RESULTS",
        f"Timestamp: {timestamp}",
        "CVEs: CVE-2026-109618, CVE-2026-109619",
        f"Fixed releases: {fixed}. PHP 8.1 and older is end of life.",
        "Note: Status comes from version banners. It is an indicator only, not confirmation that the CVE is exploitable.",
    ]
    if ports:
        lines.append(f"Ports probed: {', '.join(str(port) for port, _scheme in ports)}")
    lines.append("")
    if not findings:
        lines.append("No hosts showed PHP.")
        lines.append("")
    else:
        ranked = sorted(findings, key=lambda item: STATUS_ORDER.index(item[1]))
        for host, status, indicators in ranked:
            lines.append(f"Host: {sanitize(host, limit=253)} [{status}]")
            for _status, line in indicators:
                lines.append(f"  {line}")
            lines.append("")

    scanned = totals["finished"]
    responded = totals["responded"]
    indicated = sum(totals[status] for status in INDICATOR_STATUSES)
    lines.extend(
        [
            "Summary",
            f"Targets scanned: {scanned}",
            f"Responded on at least one probed port: {responded}",
            f"No HTTP response on any probed port: {scanned - responded}",
            f"Hosts showing PHP: {len(findings)}",
            f"  Vulnerable (unpatched supported branch): {totals[VULNERABLE]}",
            f"  End of life (8.1 or older): {totals[END_OF_LIFE]}",
            f"  Vendor build (distro version, fix may be backported): {totals[VENDOR_BUILD]}",
            f"  Version unknown: {totals[UNKNOWN]}",
            f"  Patched: {totals[PATCHED]}",
            f"Hosts with vulnerability indicators: {indicated} of {responded} responding",
        ]
    )
    if local_hosts:
        lines.append(f"Hostnames not probed because they resolve to a local address: {local_hosts}")
    if unfinished:
        lines.append(f"Scan interrupted: {unfinished} host(s) not finished.")
    if skipped:
        lines.append(f"Invalid target lines skipped: {skipped}")
    if duplicates:
        lines.append(f"Duplicate targets skipped: {duplicates}")
    lines.append("")

    parent = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".php2shellcheck-", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
            handle.flush()
            os.fsync(handle.fileno())
        # Scan results describe client hosts, so keep them owner-only.
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def summarize(finished):
    """Return (findings, totals) from finished (host, responded, indicators)."""
    totals = {status: 0 for status in STATUS_ORDER}
    totals["finished"] = len(finished)
    totals["responded"] = 0
    findings = []
    for host, responded, indicators in finished:
        if responded:
            totals["responded"] += 1
        if indicators:
            status = host_status(indicators)
            totals[status] += 1
            findings.append((host, status, indicators))
    return findings, totals


async def main():
    args = parse_arguments()

    if not args.quiet:
        show_banner()

    hosts, skipped, duplicates = [], 0, 0
    if args.target_file:
        try:
            hosts, skipped, duplicates = load_targets(args.target_file)
        except FileNotFoundError:
            error(f"Error: Target file '{args.target_file}' not found.")
            sys.exit(1)
        except OSError as exc:
            error(f"Error: Could not read '{args.target_file}': {exc}")
            sys.exit(1)

    seen = {host.lower() for host in hosts}
    for url in args.urls:
        host = host_from_url(url)
        if host is None:
            error(f"Error: '{sanitize(url, limit=200)}' is not a valid URL or hostname.")
            sys.exit(1)
        if host.lower() in seen:
            duplicates += 1
            continue
        seen.add(host.lower())
        hosts.append(host)

    if not hosts:
        error(f"Error: No valid targets in '{args.target_file}'.")
        if skipped:
            error(f"Skipped {skipped} invalid line(s).")
        sys.exit(1)

    if not args.quiet:
        print(
            f"Starting scan of {len(hosts)} host(s) on ports {describe_ports(args.ports)}."
        )
        if skipped:
            print(f"Skipped {skipped} invalid target line(s).")
        print()

    progress = None if args.quiet else ProgressBar(len(hosts))
    results = [None] * len(hosts)
    semaphore = asyncio.Semaphore(CONCURRENCY)
    interrupted = False
    write_failed = False
    workers = []
    findings = []

    resolver = ExternalResolver()
    connector = aiohttp.TCPConnector(
        limit=CONCURRENCY,
        limit_per_host=4,
        force_close=True,
        ttl_dns_cache=60,
        resolver=resolver,
        ssl=SSL_CONTEXT,
    )
    timeout = aiohttp.ClientTimeout(total=10, connect=5, sock_read=5)
    session = aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        trust_env=False,
        headers={"User-Agent": "php2shellcheck"},
    )

    try:
        queue = asyncio.Queue()
        for index, host in enumerate(hosts):
            queue.put_nowait((index, host))

        async def worker():
            while True:
                index, host = await queue.get()
                try:
                    try:
                        responded, indicators = await process_host(
                            session, host, semaphore, args.ports
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        responded, indicators = False, []
                    results[index] = (host, responded, indicators)
                    status = host_status(indicators) if indicators else None
                    hit = status in INDICATOR_STATUSES
                    if indicators and (hit or not args.quiet):
                        message = format_hit(host, status, indicators)
                        if args.quiet:
                            print(message, flush=True)
                        elif progress is not None:
                            progress.tick(hit=hit, message=message)
                    elif progress is not None:
                        progress.tick(hit=False)
                finally:
                    queue.task_done()

        worker_count = min(CONCURRENCY, len(hosts))
        workers = [asyncio.create_task(worker()) for _ in range(worker_count)]
        await queue.join()
    except asyncio.CancelledError:
        interrupted = True
    finally:
        for task in workers:
            task.cancel()
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)
        try:
            await session.close()
        except (asyncio.CancelledError, Exception):
            pass
        try:
            await resolver.close()
        except (asyncio.CancelledError, Exception):
            pass
        if progress is not None:
            progress.close()
        finished = [item for item in results if item is not None]
        findings, totals = summarize(finished)
        unfinished = len(hosts) - len(finished)
        try:
            write_report(
                args.output_file,
                findings,
                totals,
                unfinished if interrupted else 0,
                skipped,
                duplicates,
                args.ports,
                len(resolver.local_hosts),
            )
        except OSError as exc:
            write_failed = True
            error(f"Error: Could not write '{args.output_file}': {exc}")

    if write_failed:
        return 1
    if interrupted:
        return 130

    if not args.quiet:
        indicated = sum(totals[status] for status in INDICATOR_STATUSES)
        print(
            f"Scan complete. {indicated} host(s) with indicators "
            f"({totals[VULNERABLE]} vulnerable, {totals[END_OF_LIFE]} end of life, "
            f"{totals[VENDOR_BUILD]} vendor build, {totals[UNKNOWN]} version unknown) "
            f"written to {args.output_file}."
        )
    return 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
    except KeyboardInterrupt:
        exit_code = 130
    if exit_code == 130:
        print(
            "\nScan interrupted. Partial results were saved when possible.",
            file=sys.stderr,
        )
    sys.exit(exit_code)
