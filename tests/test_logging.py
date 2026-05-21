from __future__ import annotations

from fritzbox_logging import get_logger, reset_logging_for_tests


def test_project_logging_writes_redacted_file(tmp_path, monkeypatch) -> None:
    log_path = tmp_path / "fritzforensic.log"
    monkeypatch.setenv("FRITZBOX_LOG_FILE", str(log_path))
    monkeypatch.setenv("FRITZBOX_LOG_LEVEL", "DEBUG")
    reset_logging_for_tests()

    logger = get_logger("test")
    logger.debug("probe sid=0123456789abcdef&password=hunter2")

    reset_logging_for_tests()
    content = log_path.read_text(encoding="utf-8")
    assert "DEBUG fritzforensic.test" in content
    assert "sid=<redacted>" in content
    assert "password=<redacted>" in content
    assert "hunter2" not in content
