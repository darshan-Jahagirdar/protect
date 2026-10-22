"""Static checks that the WordPress plugin keeps its hard rules (AGENTS.md, DESIGN.md §2).

These read the plugin's PHP source. They don't replace review, but they catch the most
dangerous mistakes the moment someone (or some agent) makes them.
"""

import re
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parents[2] / "plugin" / "protect-reporter"
PHP_FILES = sorted(PLUGIN_DIR.rglob("*.php"))


def _code(path: Path) -> str:
    """Source with comments removed, so rules explained in comments don't trip the checks."""
    text = path.read_text()
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)(^|\s)(//|#(?!\[)).*$", r"\1", text)


def _all_code() -> dict[str, str]:
    return {str(p.relative_to(PLUGIN_DIR)): _code(p) for p in PHP_FILES}


def test_plugin_files_exist() -> None:
    names = {p.name for p in PHP_FILES}
    assert {"protect-reporter.php", "uninstall.php"} <= names
    assert len(PHP_FILES) >= 6


# R3: no commands on servers.
BANNED_CALLS = [
    "exec",
    "shell_exec",
    "system",
    "passthru",
    "proc_open",
    "popen",
    "pcntl_exec",
    "eval",
    "assert",
    "create_function",
    "unserialize",
]


@pytest.mark.parametrize("func", BANNED_CALLS)
def test_no_command_execution(func: str) -> None:
    pattern = re.compile(rf"(?<![\w>:$]){func}\s*\(")
    for name, code in _all_code().items():
        assert not pattern.search(code), f"{func}() used in {name}"


def test_no_backtick_shell() -> None:
    for name, code in _all_code().items():
        assert "`" not in code, f"backtick (shell) operator in {name}"


def test_no_preg_e_modifier() -> None:
    for name, code in _all_code().items():
        assert not re.search(r"preg_replace\s*\(\s*'/.*?/[a-z]*e[a-z]*'", code), name


# R1: output only. Nothing that accepts outside input.
BANNED_HOOKS = [
    "register_rest_route",
    "rest_api_init",
    "wp_ajax_",
    "add_rewrite_rule",
    "query_vars",
    "parse_request",
    "template_redirect",
    "xmlrpc",
    "add_feed",
    "init_hook_nopriv",
]


@pytest.mark.parametrize("needle", BANNED_HOOKS)
def test_no_inbound_endpoints(needle: str) -> None:
    for name, code in _all_code().items():
        assert needle not in code, f"{needle} found in {name}"


def test_admin_post_actions_are_only_ours_and_never_nopriv() -> None:
    actions: set[str] = set()
    for code in _all_code().values():
        actions |= set(re.findall(r"admin_post_(\w+)", code))
        assert "admin_post_nopriv" not in code
    assert actions == {"protect_reporter_enroll", "protect_reporter_report_now"}


def test_request_superglobals_only_in_admin() -> None:
    for name, code in _all_code().items():
        if name.startswith("admin/"):
            continue
        assert not re.search(r"\$_(GET|POST|REQUEST|COOKIE|FILES)\b", code), name


def test_admin_handlers_check_capability_and_nonce() -> None:
    code = _all_code()["admin/class-protect-reporter-admin.php"]
    assert "current_user_can( 'manage_options' )" in code
    assert "check_admin_referer" in code


# R2: reply bodies are never read. Outbound HTTP only through WordPress's API.
def test_reply_bodies_are_never_read() -> None:
    for name, code in _all_code().items():
        assert "wp_remote_retrieve_body" not in code, name
        assert "wp_remote_retrieve_headers" not in code, name
        assert not re.search(r"\$response\s*\[\s*'body'", code), name


@pytest.mark.parametrize(
    "needle", ["curl_init", "curl_exec", "fsockopen", "stream_socket_client", "wp_remote_request"]
)
def test_no_raw_network_calls(needle: str) -> None:
    for name, code in _all_code().items():
        assert needle not in code, f"{needle} in {name}"


def test_no_remote_file_reads() -> None:
    for name, code in _all_code().items():
        assert not re.search(r"file_get_contents\s*\(\s*['\"]https?:", code), name


def test_os_release_is_the_only_file_read_outside_wordpress() -> None:
    reads = []
    for code in _all_code().values():
        reads += re.findall(r"file_get_contents\s*\(\s*'([^']+)'", code)
    assert reads == ["/etc/os-release"]


# PHP 7.4 compatibility: the plugin must run on the old sites we're protecting.
PHP8_ONLY = [
    (r"\bmatch\s*\(", "match expression"),
    (r"\?->", "nullsafe operator"),
    (r"\bstr_contains\s*\(", "str_contains()"),
    (r"\bstr_starts_with\s*\(", "str_starts_with()"),
    (r"\bstr_ends_with\s*\(", "str_ends_with()"),
    (r"#\[", "attributes"),
    (r"\benum\s+\w+", "enums"),
    (r"\breadonly\b", "readonly"),
]


@pytest.mark.parametrize(("pattern", "what"), PHP8_ONLY)
def test_no_php8_only_syntax(pattern: str, what: str) -> None:
    for name, code in _all_code().items():
        assert not re.search(pattern, code), f"{what} in {name}"


def test_every_file_blocks_direct_access() -> None:
    for name, code in _all_code().items():
        guard = "WP_UNINSTALL_PLUGIN" if name == "uninstall.php" else "ABSPATH"
        assert f"defined( '{guard}' )" in code, f"{name} lacks a direct-access guard"


def test_uninstall_removes_every_option_the_plugin_writes() -> None:
    written: set[str] = set()
    for code in _all_code().values():
        written |= set(re.findall(r"update_option\(\s*'([a-z_]+)'", code))
        written |= set(re.findall(r"const \w+\s*=\s*'(protect_reporter_[a-z_]+)'", code))
    uninstall = _all_code()["uninstall.php"]
    for option in written:
        assert f"'{option}'" in uninstall, f"uninstall.php doesn't delete {option}"
