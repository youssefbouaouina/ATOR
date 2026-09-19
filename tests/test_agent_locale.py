"""Regression tests for locale-independent Windows log-collector error handling.

Context
-------
`agent.collectors.logs._powershell_events` used to classify "you may not read this log"
by substring-matching the *localised* PowerShell error message against the English words
"unauthorized" / "denied" / "access". On a French-language Windows host a non-elevated
`Get-WinEvent -LogName Security` returns

    Tentative d'execution d'une operation non autorisee.

which matched none of them, so a routine permission failure was reported as a fatal
collector error - breaking `test_agent.py::test_live_collection_windows` on every
non-English host. The subprocess calls also decoded output with the locale codepage and
raised UnicodeDecodeError on unmappable bytes.

The fix classifies on the .NET exception *type name*, which Windows does not translate,
and pins subprocess decoding to UTF-8. These tests keep it that way.
"""
import subprocess

from agent.collectors import logs


class TestExceptionTypeClassification:
    """Primary path: classify by invariant .NET exception type name."""

    def test_unauthorized_access_is_tolerated_marker(self):
        assert logs._classify_ps_error("UnauthorizedAccessException", "Security") == [
            {"_error": "access_denied:Security"}
        ]

    def test_security_and_privilege_exceptions_also_tolerated(self):
        for exc in ("SecurityException", "PrivilegeNotHeldException"):
            assert logs._classify_ps_error(exc, "Security") == [
                {"_error": "access_denied:Security"}
            ], exc

    def test_missing_or_empty_log_is_not_an_error(self):
        # A log that does not exist yields no events and no error at all.
        for exc in ("EventLogNotFoundException", "NoMatchingEventsException"):
            assert logs._classify_ps_error(exc, "Microsoft-Windows-Sysmon/Operational") == [], exc

    def test_genuine_failure_is_surfaced(self):
        out = logs._classify_ps_error("InvalidOperationException", "System")
        assert out == [{"_error": "ps:InvalidOperationException"}]


class TestLocalisedMessageFallback:
    """Secondary path: the returncode!=0 branch only has a localised message."""

    def test_french_access_denied_is_recognised(self):
        # The exact message that caused the original failure.
        assert logs._is_access_denied_text(
            "Tentative d'exécution d'une opération non autorisée."
        )

    def test_english_german_spanish_recognised(self):
        assert logs._is_access_denied_text("Attempted to perform an unauthorized operation.")
        assert logs._is_access_denied_text("Zugriff verweigert")
        assert logs._is_access_denied_text("Acceso denegado")

    def test_unrelated_error_is_not_swallowed(self):
        # Must NOT be classified as a permission problem - that would hide real faults.
        assert not logs._is_access_denied_text("The RPC server is unavailable")
        assert not logs._is_access_denied_text("")
        assert not logs._is_access_denied_text(None)


class TestSubprocessDecoding:
    """Undecodable bytes must not raise; they are replaced."""

    def test_no_subprocess_run_relies_on_locale_codepage(self):
        # Guard the whole collector package: text=True without an explicit encoding
        # decodes using the system codepage and raises UnicodeDecodeError on bytes that
        # do not map (e.g. 0x90 under cp1252).
        import pathlib
        offenders = []
        root = pathlib.Path(logs.__file__).parent.parent  # agent/
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for chunk in text.split("subprocess.run(")[1:]:
                call = chunk[:400]
                if "text=True" in call and "encoding=" not in call:
                    offenders.append(path.name)
        assert not offenders, f"subprocess.run(text=True) without encoding= in: {offenders}"

    def test_utf8_replace_survives_invalid_bytes(self):
        # Mirrors how the collector now invokes subprocesses.
        proc = subprocess.run(
            ["python", "-c", r"import sys; sys.stdout.buffer.write(b'ok\x90\xff')"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
        )
        assert proc.stdout.startswith("ok")   # no exception, bytes replaced
