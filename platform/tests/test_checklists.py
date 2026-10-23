from pathlib import Path

import pytest

from app.checklists.loader import (
    PLACEHOLDERS,
    TemplateError,
    all_templates,
    load,
    render,
    template_for,
)

INCIDENT_KINDS = ["php-core", "wp-core", "wp-plugin", "wp-theme", "lib"]
HOST_TYPES = ["managed-wp", "cpanel", "vps", "unknown"]


def test_every_template_loads_and_is_valid() -> None:
    templates = all_templates()
    assert len(templates) >= 8
    for t in templates:
        assert t.items, t.key
        assert any(i.kind == "auto" for i in t.items), f"{t.key} has no auto-verified step"
        assert t.items[-1].key == "client_notice", f"{t.key} must end with the client notice"


@pytest.mark.parametrize("kind", INCIDENT_KINDS)
@pytest.mark.parametrize("host", HOST_TYPES)
def test_every_kind_and_host_gets_a_template(kind: str, host: str) -> None:
    t = template_for(kind, host)
    assert t.key.startswith(kind + "/")
    rendered = render(t, {p: "X" for p in PLACEHOLDERS})
    assert all("{" not in r.text for r in rendered)


def test_host_specific_template_is_preferred() -> None:
    assert template_for("php-core", "managed-wp").key == "php-core/managed-wp"
    assert template_for("php-core", "unknown").key == "php-core/default"
    assert template_for("wp-plugin", "managed-wp").key == "wp-plugin/default"


def test_php_templates_never_suggest_under_attack_mode_as_the_fix() -> None:
    for host in HOST_TYPES:
        for item in template_for("php-core", host).items:
            if "Under Attack" in item.text:
                assert "Not 'Under Attack'" in item.text


def test_missing_values_render_as_question_mark() -> None:
    rendered = render(template_for("php-core", "managed-wp"), {})
    assert "?" in rendered[0].text


@pytest.mark.parametrize(
    ("body", "problem"),
    [
        ("title: x\nitems:\n  - {key: a, kind: manual, text: 'uses {secret}'}\n", "placeholders"),
        ("title: x\nitems:\n  - {key: a, kind: robot, text: hi}\n", "unknown kind"),
        (
            "title: x\nitems:\n  - {key: a, kind: manual, text: hi}\n"
            "  - {key: a, kind: manual, text: again}\n",
            "duplicate",
        ),
        ("just a string\n", "list of items"),
    ],
)
def test_bad_templates_are_refused(tmp_path: Path, body: str, problem: str) -> None:
    folder = tmp_path / "php-core"
    folder.mkdir()
    path = folder / "bad.yaml"
    path.write_text(body)
    with pytest.raises(TemplateError, match=problem):
        load(path)
