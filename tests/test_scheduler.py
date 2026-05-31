"""Tests for modules/scheduler.py."""
import json
import datetime
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


@pytest.fixture
def schedule_file(tmp_path):
    """Provide a temporary schedule file path and patch the module."""
    schedule_path = tmp_path / "test_schedules.json"
    with patch("modules.scheduler.SCHEDULE_FILE", schedule_path):
        yield schedule_path


class TestScheduledScan:
    def test_basic_construction(self):
        from modules.scheduler import ScheduledScan
        s = ScheduledScan(
            job_id="abc12345",
            target="example.com",
            modules=["whois", "dns"],
            interval_hours=24,
        )
        assert s.job_id == "abc12345"
        assert s.target == "example.com"
        assert s.modules == ["whois", "dns"]
        assert s.interval_hours == 24
        assert s.alert_on_change is True
        assert s.last_run is None
        assert s.last_hash is None

    def test_default_tags_empty_list(self):
        from modules.scheduler import ScheduledScan
        s = ScheduledScan(job_id="x", target="t", modules=["whois"])
        assert s.tags == []

    def test_tags_set_correctly(self):
        from modules.scheduler import ScheduledScan
        s = ScheduledScan(job_id="x", target="t", modules=["whois"], tags=["tag1", "scheduled"])
        assert s.tags == ["tag1", "scheduled"]

    def test_created_at_is_iso_string(self):
        from modules.scheduler import ScheduledScan
        s = ScheduledScan(job_id="x", target="t", modules=[])
        # Should be parseable as ISO datetime
        dt = datetime.datetime.fromisoformat(s.created_at)
        assert isinstance(dt, datetime.datetime)

    def test_to_dict_contains_all_fields(self):
        from modules.scheduler import ScheduledScan
        s = ScheduledScan(
            job_id="abc12345",
            target="example.com",
            modules=["whois"],
            interval_hours=12,
            tags=["test"],
        )
        d = s.to_dict()
        assert d["job_id"] == "abc12345"
        assert d["target"] == "example.com"
        assert d["modules"] == ["whois"]
        assert d["interval_hours"] == 12
        assert d["tags"] == ["test"]
        assert d["last_run"] is None
        assert d["last_hash"] is None
        assert "created_at" in d

    def test_from_dict_roundtrip(self):
        from modules.scheduler import ScheduledScan
        s = ScheduledScan(
            job_id="test1234",
            target="example.com",
            modules=["whois", "dns"],
            interval_hours=48,
            alert_on_change=False,
            output_dir="./custom_reports",
            tags=["custom"],
        )
        s.last_run = "2024-01-01T12:00:00"
        s.last_hash = "abc123def456"
        d = s.to_dict()
        restored = ScheduledScan.from_dict(d)
        assert restored.job_id == s.job_id
        assert restored.target == s.target
        assert restored.modules == s.modules
        assert restored.interval_hours == s.interval_hours
        assert restored.alert_on_change == s.alert_on_change
        assert restored.output_dir == s.output_dir
        assert restored.tags == s.tags
        assert restored.last_run == s.last_run
        assert restored.last_hash == s.last_hash

    def test_from_dict_defaults(self):
        from modules.scheduler import ScheduledScan
        minimal = {"job_id": "x", "target": "t"}
        s = ScheduledScan.from_dict(minimal)
        assert s.modules == ["whois", "dns"]
        assert s.interval_hours == 24
        assert s.alert_on_change is True
        assert s.output_dir == "./reports"
        assert s.tags == []


class TestDataHash:
    def test_deterministic(self):
        from modules.scheduler import _data_hash
        data = {"whois": {"registrar": "ICANN"}, "dns": {"A": ["1.2.3.4"]}}
        h1 = _data_hash(data)
        h2 = _data_hash(data)
        assert h1 == h2

    def test_different_data_different_hash(self):
        from modules.scheduler import _data_hash
        h1 = _data_hash({"a": 1})
        h2 = _data_hash({"a": 2})
        assert h1 != h2

    def test_order_independent(self):
        from modules.scheduler import _data_hash
        h1 = _data_hash({"a": 1, "b": 2})
        h2 = _data_hash({"b": 2, "a": 1})
        assert h1 == h2

    def test_returns_16_chars(self):
        from modules.scheduler import _data_hash
        h = _data_hash({"test": "data"})
        assert len(h) == 16

    def test_empty_dict(self):
        from modules.scheduler import _data_hash
        h = _data_hash({})
        assert isinstance(h, str)
        assert len(h) == 16


class TestLoadSaveSchedules:
    def test_no_file_returns_empty(self, schedule_file):
        from modules.scheduler import _load_schedules
        result = _load_schedules()
        assert result == {}

    def test_save_and_load_roundtrip(self, schedule_file):
        from modules.scheduler import ScheduledScan, _load_schedules, _save_schedules
        s = ScheduledScan(job_id="test1", target="a.com", modules=["whois"])
        _save_schedules({"test1": s})
        loaded = _load_schedules()
        assert "test1" in loaded
        assert loaded["test1"].target == "a.com"

    def test_corrupt_file_returns_empty(self, schedule_file):
        from modules.scheduler import _load_schedules
        schedule_file.write_text("NOT VALID JSON", encoding="utf-8")
        result = _load_schedules()
        assert result == {}

    def test_save_creates_parent_dirs(self, tmp_path):
        from modules.scheduler import ScheduledScan, _load_schedules, _save_schedules
        nested_path = tmp_path / "a" / "b" / "schedules.json"
        with patch("modules.scheduler.SCHEDULE_FILE", nested_path):
            s = ScheduledScan(job_id="j1", target="t", modules=[])
            _save_schedules({"j1": s})
            assert nested_path.exists()
            loaded = _load_schedules()
            assert "j1" in loaded


class TestAddSchedule:
    def test_returns_scheduled_scan(self, schedule_file):
        from modules.scheduler import add_schedule
        s = add_schedule("example.com", ["whois", "dns"])
        assert s.target == "example.com"
        assert s.modules == ["whois", "dns"]

    def test_job_id_is_8_chars(self, schedule_file):
        from modules.scheduler import add_schedule
        s = add_schedule("example.com", ["whois"])
        assert len(s.job_id) == 8

    def test_persisted_to_file(self, schedule_file):
        from modules.scheduler import add_schedule, _load_schedules
        s = add_schedule("example.com", ["whois"])
        loaded = _load_schedules()
        assert s.job_id in loaded

    def test_custom_interval(self, schedule_file):
        from modules.scheduler import add_schedule
        s = add_schedule("example.com", ["whois"], interval_hours=48)
        assert s.interval_hours == 48

    def test_custom_tags(self, schedule_file):
        from modules.scheduler import add_schedule
        s = add_schedule("example.com", ["whois"], tags=["important", "daily"])
        assert "important" in s.tags
        assert "daily" in s.tags

    def test_multiple_schedules_different_ids(self, schedule_file):
        from modules.scheduler import add_schedule
        s1 = add_schedule("a.com", ["whois"])
        s2 = add_schedule("b.com", ["whois"])
        assert s1.job_id != s2.job_id


class TestRemoveSchedule:
    def test_remove_existing(self, schedule_file):
        from modules.scheduler import add_schedule, remove_schedule, _load_schedules
        s = add_schedule("example.com", ["whois"])
        result = remove_schedule(s.job_id)
        assert result is True
        loaded = _load_schedules()
        assert s.job_id not in loaded

    def test_remove_nonexistent_returns_false(self, schedule_file):
        from modules.scheduler import remove_schedule
        result = remove_schedule("doesnotexist")
        assert result is False

    def test_remove_only_removes_target(self, schedule_file):
        from modules.scheduler import add_schedule, remove_schedule, _load_schedules
        s1 = add_schedule("a.com", ["whois"])
        s2 = add_schedule("b.com", ["dns"])
        remove_schedule(s1.job_id)
        loaded = _load_schedules()
        assert s1.job_id not in loaded
        assert s2.job_id in loaded


class TestListSchedules:
    def test_empty_returns_empty_list(self, schedule_file):
        from modules.scheduler import list_schedules
        result = list_schedules()
        assert result == []

    def test_returns_all_schedules(self, schedule_file):
        from modules.scheduler import add_schedule, list_schedules
        add_schedule("a.com", ["whois"])
        add_schedule("b.com", ["dns"])
        result = list_schedules()
        assert len(result) == 2

    def test_returned_items_are_scheduled_scan(self, schedule_file):
        from modules.scheduler import add_schedule, list_schedules, ScheduledScan
        add_schedule("example.com", ["whois"])
        result = list_schedules()
        assert all(isinstance(s, ScheduledScan) for s in result)


class TestRunScheduledScan:
    def test_unknown_job_id_raises_scheduler_error(self, schedule_file):
        from modules.scheduler import run_scheduled_scan
        from modules.exceptions import SchedulerError
        with pytest.raises(SchedulerError):
            run_scheduled_scan("nonexistent")

    def test_successful_run_returns_dict(self, schedule_file):
        from modules.scheduler import add_schedule, run_scheduled_scan

        mock_data = {"whois": {"registrar": "ICANN"}}

        with patch("modules.scheduler._dispatch_module_sync", return_value={"registrar": "ICANN"}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db") as mock_db:
                    mock_db.return_value.save_scan.return_value = "scan123"
                    s = add_schedule("example.com", ["whois"])
                    result = run_scheduled_scan(s.job_id)

        assert result["job_id"] == s.job_id
        assert result["target"] == "example.com"
        assert "data_hash" in result
        assert "run_at" in result
        assert "changed" in result

    def test_first_run_changed_is_false(self, schedule_file):
        from modules.scheduler import add_schedule, run_scheduled_scan

        with patch("modules.scheduler._dispatch_module_sync", return_value={}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db") as mock_db:
                    mock_db.return_value.save_scan.return_value = "s1"
                    s = add_schedule("example.com", ["whois"])
                    result = run_scheduled_scan(s.job_id)

        # First run: last_hash was None, so changed=False
        assert result["changed"] is False

    def test_second_run_with_different_data_changed_true(self, schedule_file):
        from modules.scheduler import add_schedule, run_scheduled_scan, _load_schedules, _save_schedules

        with patch("modules.scheduler._dispatch_module_sync", return_value={"value": "first"}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db") as mock_db:
                    mock_db.return_value.save_scan.return_value = "s1"
                    s = add_schedule("example.com", ["whois"])
                    # First run
                    run_scheduled_scan(s.job_id)

        # Now run with different data
        with patch("modules.scheduler._dispatch_module_sync", return_value={"value": "changed"}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db") as mock_db:
                    mock_db.return_value.save_scan.return_value = "s2"
                    result = run_scheduled_scan(s.job_id)

        assert result["changed"] is True

    def test_on_change_callback_called_when_changed(self, schedule_file):
        from modules.scheduler import add_schedule, run_scheduled_scan

        callback_called = []

        def on_change(target, old, new):
            callback_called.append((target, old, new))

        with patch("modules.scheduler._dispatch_module_sync", return_value={"v": "1"}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db") as mock_db:
                    mock_db.return_value.save_scan.return_value = "s1"
                    s = add_schedule("example.com", ["whois"])
                    run_scheduled_scan(s.job_id)  # first run

        with patch("modules.scheduler._dispatch_module_sync", return_value={"v": "2"}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db") as mock_db:
                    mock_db.return_value.save_scan.return_value = "s2"
                    run_scheduled_scan(s.job_id, on_change=on_change)

        assert len(callback_called) == 1
        assert callback_called[0][0] == "example.com"

    def test_module_failure_stored_in_results(self, schedule_file):
        from modules.scheduler import add_schedule, run_scheduled_scan

        def failing_dispatch(module, target):
            raise RuntimeError("Connection refused")

        with patch("modules.scheduler._dispatch_module_sync", side_effect=failing_dispatch):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db") as mock_db:
                    mock_db.return_value.save_scan.return_value = "s1"
                    s = add_schedule("example.com", ["whois"])
                    result = run_scheduled_scan(s.job_id)

        assert "whois" in result["data"]
        assert "error" in result["data"]["whois"]

    def test_last_run_updated_after_scan(self, schedule_file):
        from modules.scheduler import add_schedule, run_scheduled_scan, _load_schedules

        with patch("modules.scheduler._dispatch_module_sync", return_value={}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db") as mock_db:
                    mock_db.return_value.save_scan.return_value = "s1"
                    s = add_schedule("example.com", ["whois"])
                    run_scheduled_scan(s.job_id)

        updated = _load_schedules()[s.job_id]
        assert updated.last_run is not None


class TestRunAllDue:
    def test_empty_schedules_returns_empty_list(self, schedule_file):
        from modules.scheduler import run_all_due
        results = run_all_due()
        assert results == []

    def test_new_schedule_is_due(self, schedule_file):
        from modules.scheduler import add_schedule, run_all_due

        with patch("modules.scheduler._dispatch_module_sync", return_value={}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db") as mock_db:
                    mock_db.return_value.save_scan.return_value = "s1"
                    add_schedule("example.com", ["whois"])
                    results = run_all_due()

        assert len(results) == 1

    def test_recently_run_not_due(self, schedule_file):
        from modules.scheduler import add_schedule, run_all_due, _load_schedules, _save_schedules

        with patch("modules.scheduler._dispatch_module_sync", return_value={}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db") as mock_db:
                    mock_db.return_value.save_scan.return_value = "s1"
                    s = add_schedule("example.com", ["whois"], interval_hours=24)
                    run_all_due()  # first run, sets last_run

        # Run again immediately - should not be due (24h interval not elapsed)
        with patch("modules.scheduler._dispatch_module_sync", return_value={}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db") as mock_db:
                    mock_db.return_value.save_scan.return_value = "s2"
                    results = run_all_due()

        assert len(results) == 0


class TestDispatchModuleSync:
    def test_unknown_module_raises_value_error(self):
        from modules.scheduler import _dispatch_module_sync
        with pytest.raises(ValueError, match="Unknown module"):
            _dispatch_module_sync("nonexistent_module", "target")

    def test_whois_module_dispatches(self):
        from modules.scheduler import _dispatch_module_sync
        with patch("modules.whois_lookup.whois_lookup", return_value={"registrar": "ICANN"}) as mock:
            result = _dispatch_module_sync("whois", "example.com")
            mock.assert_called_once_with("example.com")
        assert result == {"registrar": "ICANN"}

    def test_dns_module_dispatches(self):
        from modules.scheduler import _dispatch_module_sync
        with patch("modules.whois_lookup.dns_enum", return_value={"A": ["1.2.3.4"]}) as mock:
            result = _dispatch_module_sync("dns", "example.com")
            mock.assert_called_once_with("example.com")

    def test_none_return_converted_to_empty_dict(self):
        from modules.scheduler import _dispatch_module_sync
        with patch("modules.whois_lookup.whois_lookup", return_value=None):
            result = _dispatch_module_sync("whois", "example.com")
        assert result == {}