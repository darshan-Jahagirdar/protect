"""Standard component keys (DESIGN.md §4.4).

Every piece of software gets one key, and every source's own name is mapped onto it via
the component_aliases table. This module only knows the key *shapes*, not the aliases.
"""

import re
from enum import StrEnum


class ComponentKind(StrEnum):
    PHP = "php"
    PHP_EXT = "php-ext"
    LIB = "lib"
    WORDPRESS = "wordpress"
    WP_PLUGIN = "wp-plugin"
    WP_THEME = "wp-theme"
    DB = "db"
    SERVER = "server"
    OS = "os"


_NAME = r"[a-z0-9][a-z0-9._-]{0,99}"
_KEY_RE = re.compile(
    rf"^(?:php|wordpress|(?:php-ext|lib|wp-plugin|wp-theme|db|server|os):{_NAME})$"
)

# Components installed and patched by the operating system or host, where fixes are often
# backported without the upstream version number changing.
SYSTEM_PROVIDED = frozenset(
    {ComponentKind.PHP_EXT, ComponentKind.LIB, ComponentKind.DB, ComponentKind.SERVER}
)


def is_valid_key(key: str) -> bool:
    return bool(_KEY_RE.match(key))


def kind_of(key: str) -> ComponentKind:
    if not is_valid_key(key):
        raise ValueError(f"invalid component key: {key!r}")
    return ComponentKind(key.split(":", 1)[0])
