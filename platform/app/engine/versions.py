"""Version parsing and comparison. Pure functions, no I/O.

Three kinds of version strings show up:

- PHP's own `PHP_VERSION`, e.g. "8.3.30" or "8.1.2-1ubuntu2.20". We split it ourselves and
  never hand it to a semver library: semver reads "-1ubuntu2.20" as a pre-release and sorts it
  BELOW 8.1.2.
- Debian/Ubuntu package versions, e.g. "8.2.29-1~deb12u1". Compared with dpkg's own rules.
- Everything else (WordPress core, plugins, themes, libraries): a forgiving "loose" format.
  Anything we can't parse returns None, and the matcher turns None into needs_check, never safe.
"""

import re
from dataclasses import dataclass
from functools import total_ordering

# --- PHP_VERSION ---------------------------------------------------------------

_PHP_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(.*)$")


@dataclass(frozen=True)
class PhpVersion:
    major: int
    minor: int
    release: int
    extra: str  # everything after MAJOR.MINOR.RELEASE, e.g. "", "-1ubuntu2.20", "RC1"
    raw: str

    @property
    def upstream(self) -> "LooseVersion":
        return LooseVersion((self.major, self.minor, self.release))

    @property
    def branch(self) -> str:
        return f"{self.major}.{self.minor}"


def parse_php(raw: str | None) -> PhpVersion | None:
    if not raw:
        return None
    m = _PHP_RE.match(raw.strip())
    if not m:
        return None
    major, minor, release, extra = m.groups()
    return PhpVersion(int(major), int(minor), int(release), extra, raw.strip())


# --- Loose versions (WordPress, plugins, themes, libraries) ---------------------

_PRE_RANK = {"dev": 0, "alpha": 1, "beta": 2, "pre": 3, "preview": 3, "rc": 4}

_LOOSE_RE = re.compile(
    r"""^v?
    (?P<rel>\d+(?:\.\d+)*)                 # 1.2.3
    (?P<letter>[a-z])?                     # OpenSSL-style patch letter: 1.1.1w
    (?:[-_.]?(?P<pre>dev|alpha|beta|preview|pre|rc)[-_.]?(?P<pren>\d+)?)?   # -beta2, RC1
    (?:\+[0-9a-z.-]+)?                     # build metadata, ignored
    $""",
    re.IGNORECASE | re.VERBOSE,
)


@total_ordering
@dataclass(frozen=True)
class LooseVersion:
    release: tuple[int, ...]
    letter: str = ""
    pre: tuple[int, int] | None = None  # (rank, number); None means a final release

    def _key(self) -> tuple[object, ...]:
        rel = self.release
        while len(rel) > 1 and rel[-1] == 0:  # 6.6 == 6.6.0
            rel = rel[:-1]
        # A final release sorts after any pre-release of the same version.
        pre = (1, 0, 0) if self.pre is None else (0, *self.pre)
        return (rel, self.letter, pre)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, LooseVersion):
            return NotImplemented
        a, b = self._key(), other._key()
        if a[0] != b[0]:
            return _release_lt(a[0], b[0])  # type: ignore[arg-type]
        return a[1:] < b[1:]  # type: ignore[operator]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, LooseVersion):
            return NotImplemented
        return self._key() == other._key()

    def __hash__(self) -> int:
        return hash(self._key())


def _release_lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) < b + (0,) * (n - len(b))


def parse_loose(raw: str | None) -> LooseVersion | None:
    if not raw:
        return None
    m = _LOOSE_RE.match(raw.strip())
    if not m:
        return None
    release = tuple(int(p) for p in m["rel"].split("."))
    pre = None
    if m["pre"]:
        pre = (_PRE_RANK[m["pre"].lower()], int(m["pren"] or 0))
    return LooseVersion(release, (m["letter"] or "").lower(), pre)


# --- Debian / Ubuntu package versions (dpkg rules) ------------------------------


def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    """Port of dpkg's verrevcmp(): compares an upstream-version or revision part."""
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) else 0
            bc = _dpkg_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


_DPKG_RE = re.compile(r"^(?:(\d+):)?([0-9][A-Za-z0-9.+~:-]*?)(?:-([A-Za-z0-9.+~]+))?$")


def is_dpkg_version(raw: str) -> bool:
    return bool(_DPKG_RE.match(raw))


def compare_dpkg(a: str, b: str) -> int:
    """Negative if a < b, 0 if equal, positive if a > b, using dpkg's ordering.

    Raises ValueError for strings that aren't Debian package versions.
    """

    def split(v: str) -> tuple[int, str, str]:
        m = _DPKG_RE.match(v.strip())
        if not m:
            raise ValueError(f"not a Debian package version: {v!r}")
        epoch, upstream, revision = m.groups()
        return int(epoch or 0), upstream, revision or ""

    ea, ua, ra = split(a)
    eb, ub, rb = split(b)
    if ea != eb:
        return ea - eb
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


# --- Pulling a version number out of descriptive strings ------------------------

_EXTRACTORS: dict[str, re.Pattern[str]] = {
    "lib:openssl": re.compile(r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)", re.I),
    "server:apache": re.compile(r"Apache/(\d+(?:\.\d+)+)", re.I),
    "server:nginx": re.compile(r"nginx/(\d+(?:\.\d+)+)", re.I),
    "server:litespeed": re.compile(r"LiteSpeed/(\d+(?:\.\d+)+)", re.I),
}


def extract_version(component_key: str, raw: str | None) -> str | None:
    """Return the bare version for components that report a descriptive string.

    "OpenSSL 3.0.13 30 Jan 2024" becomes "3.0.13"; "Apache/2.4.58 (Ubuntu)" becomes "2.4.58".
    Components without a known pattern get their raw value back, stripped. Anything with no
    version at all ("Apache" with ServerTokens Prod) comes back as None.
    """
    if raw is None:
        return None
    pattern = _EXTRACTORS.get(component_key)
    if pattern is None:
        return raw.strip() or None
    m = pattern.search(raw)
    return m.group(1) if m else None
