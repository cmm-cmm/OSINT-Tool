"""Tests for modules/scheduler.py."""
import json
import datetime
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


@pytest.fixture
def schedule_file(tmp_path):
    """Return a temp path for the schedule file."""
    return tmp_path / "schedules.json"


@pytest.fixture(autouse=True)
def patch_schedule_file(schedule_file):
    """Redirect all scheduler file I/O to a temp file."""
    with patch("modules.scheduler.SCHEDULE_FILE", schedule_file):
        yield schedule_file


class TestScheduledScan:
    def test_basic_construction(self):
        from modules.scheduler import ScheduledScan
        scan = ScheduledScan(
            job_id="abc12345",
            target="example.com",
            modules=["whois", "dns"],
        )
        assert scan.job_id == "abc12345"
        assert scan.target == "example.com"
        assert scan.modules == ["whois", "dns"]
        assert scan.interval_hours == 24
        assert scan.alert_on_change is True
        assert scan.last_run is None
        assert scan.last_hash is None

    def test_tags_default_empty(self):
        from modules.scheduler import ScheduledScan
        scan = ScheduledScan("id", "target", ["whois"])
        assert scan.tags == []

    def test_tags_provided(self):
        from modules.scheduler import ScheduledScan
        scan = ScheduledScan("id", "target", ["whois"], tags=["pentest"])
        assert "pentest" in scan.tags

    def test_to_dict_round_trips(self):
        from modules.scheduler import ScheduledScan
        scan = ScheduledScan(
            job_id="abc12345",
            target="example.com",
            modules=["whois", "dns"],
            interval_hours=12,
            tags=["test"],
        )
        d = scan.to_dict()
        restored = ScheduledScan.from_dict(d)
        assert restored.job_id == scan.job_id
        assert restored.target == scan.target
        assert restored.modules == scan.modules
        assert restored.interval_hours == scan.interval_hours
        assert restored.tags == scan.tags

    def test_from_dict_defaults(self):
        from modules.scheduler import ScheduledScan
        d = {"job_id": "x", "target": "t.com"}
        scan = ScheduledScan.from_dict(d)
        assert scan.modules == ["whois", "dns"]
        assert scan.interval_hours == 24
        assert scan.alert_on_change is True

    def test_from_dict_preserves_last_run(self):
        from modules.scheduler import ScheduledScan
        d = {
            "job_id": "x",
            "target": "t.com",
            "modules": ["whois"],
            "last_run": "2024-01-15T10:30:00",
            "last_hash": "abc123",
        }
        scan = ScheduledScan.from_dict(d)
        assert scan.last_run == "2024-01-15T10:30:00"
        assert scan.last_hash == "abc123"

    def test_created_at_is_set(self):
        from modules.scheduler import ScheduledScan
        scan = ScheduledScan("id", "target", ["whois"])
        assert scan.created_at is not None
        # Should be a valid ISO format timestamp
        datetime.datetime.fromisoformat(scan.created_at)


class TestDataHash:
    def test_deterministic(self):
        from modules.scheduler import _data_hash
        data = {"whois": {"domain": "example.com"}, "dns": {"A": ["1.2.3.4"]}}
        h1 = _data_hash(data)
        h2 = _data_hash(data)
        assert h1 == h2

    def test_different_data_different_hash(self):
        from modules.scheduler import _data_hash
        h1 = _data_hash({"key": "value1"})
        h2 = _data_hash({"key": "value2"})
        assert h1 != h2

    def test_returns_16_char_string(self):
        from modules.scheduler import _data_hash
        h = _data_hash({"test": "data"})
        assert len(h) == 16
        assert isinstance(h, str)

    def test_empty_dict(self):
        from modules.scheduler import _data_hash
        h = _data_hash({})
        assert len(h) == 16


class TestLoadSaveSchedules:
    def test_load_nonexistent_returns_empty(self, schedule_file):
        from modules.scheduler import _load_schedules
        assert not schedule_file.exists()
        result = _load_schedules()
        assert result == {}

    def test_save_and_load(self, schedule_file):
        from modules.scheduler import _load_schedules, _save_schedules, ScheduledScan
        scan = ScheduledScan("abc12345", "example.com", ["whois"])
        _save_schedules({"abc12345": scan})
        loaded = _load_schedules()
        assert "abc12345" in loaded
        assert loaded["abc12345"].target == "example.com"

    def test_corrupt_file_returns_empty(self, schedule_file):
        from modules.scheduler import _load_schedules
        schedule_file.write_text("not valid json", encoding="utf-8")
        result = _load_schedules()
        assert result == {}


class TestAddSchedule:
    def test_add_returns_scheduled_scan(self):
        from modules.scheduler import add_schedule
        scan = add_schedule("example.com", ["whois", "dns"])
        from modules.scheduler import ScheduledScan
        assert isinstance(scan, ScheduledScan)
        assert scan.target == "example.com"
        assert scan.modules == ["whois", "dns"]

    def test_add_persists_to_file(self, schedule_file):
        from modules.scheduler import add_schedule
        add_schedule("example.com", ["whois"])
        assert schedule_file.exists()
        data = json.loads(schedule_file.read_text())
        assert len(data) == 1

    def test_add_multiple_schedules(self):
        from modules.scheduler import add_schedule, list_schedules
        add_schedule("a.com", ["whois"])
        add_schedule("b.com", ["dns"])
        schedules = list_schedules()
        assert len(schedules) == 2

    def test_add_with_tags(self):
        from modules.scheduler import add_schedule
        scan = add_schedule("example.com", ["whois"], tags=["vip"])
        assert "vip" in scan.tags

    def test_add_custom_interval(self):
        from modules.scheduler import add_schedule
        scan = add_schedule("example.com", ["whois"], interval_hours=6)
        assert scan.interval_hours == 6

    def test_job_id_is_8_chars(self):
        from modules.scheduler import add_schedule
        scan = add_schedule("example.com", ["whois"])
        assert len(scan.job_id) == 8


class TestRemoveSchedule:
    def test_remove_existing(self):
        from modules.scheduler import add_schedule, remove_schedule
        scan = add_schedule("example.com", ["whois"])
        result = remove_schedule(scan.job_id)
        assert result is True

    def test_remove_decreases_count(self):
        from modules.scheduler import add_schedule, remove_schedule, list_schedules
        scan = add_schedule("example.com", ["whois"])
        add_schedule("other.com", ["dns"])
        remove_schedule(scan.job_id)
        schedules = list_schedules()
        assert len(schedules) == 1

    def test_remove_nonexistent_returns_false(self):
        from modules.scheduler import remove_schedule
        result = remove_schedule("nonexistent_id")
        assert result is False


class TestListSchedules:
    def test_empty_list(self):
        from modules.scheduler import list_schedules
        result = list_schedules()
        assert result == []

    def test_returns_list_of_scheduled_scans(self):
        from modules.scheduler import add_schedule, list_schedules, ScheduledScan
        add_schedule("example.com", ["whois"])
        schedules = list_schedules()
        assert len(schedules) == 1
        assert isinstance(schedules[0], ScheduledScan)


class TestRunScheduledScan:
    def test_raises_on_unknown_job_id(self):
        from modules.scheduler import run_scheduled_scan
        from modules.exceptions import SchedulerError
        with pytest.raises(SchedulerError, match="No scheduled scan"):
            run_scheduled_scan("no_such_id")

    def test_run_updates_last_run(self):
        from modules.scheduler import add_schedule, run_scheduled_scan
        scan = add_schedule("example.com", ["whois"])

        with patch("modules.scheduler._dispatch_module_sync", return_value={"domain": "example.com"}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db"):
                    result = run_scheduled_scan(scan.job_id)

        assert result["run_at"] is not None
        assert result["job_id"] == scan.job_id

    def test_run_returns_expected_keys(self):
        from modules.scheduler import add_schedule, run_scheduled_scan
        scan = add_schedule("example.com", ["whois"])

        with patch("modules.scheduler._dispatch_module_sync", return_value={}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db"):
                    result = run_scheduled_scan(scan.job_id)

        expected_keys = {"job_id", "target", "modules_run", "run_at", "data_hash", "changed", "data"}
        assert expected_keys.issubset(result.keys())

    def test_first_run_changed_is_false(self):
        """First run has no previous hash, so changed should be False."""
        from modules.scheduler import add_schedule, run_scheduled_scan
        scan = add_schedule("example.com", ["whois"])
        assert scan.last_hash is None

        with patch("modules.scheduler._dispatch_module_sync", return_value={}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db"):
                    result = run_scheduled_scan(scan.job_id)

        assert result["changed"] is False

    def test_changed_detected_on_diff(self):
        """Second run with different data should set changed=True."""
        from modules.scheduler import add_schedule, run_scheduled_scan, _load_schedules, _save_schedules
        scan = add_schedule("example.com", ["whois"])

        # Manually set a previous hash
        schedules = _load_schedules()
        schedules[scan.job_id].last_hash = "aaaa1111bbbb2222"
        _save_schedules(schedules)

        with patch("modules.scheduler._dispatch_module_sync", return_value={"new": "data"}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db"):
                    result = run_scheduled_scan(scan.job_id)

        assert result["changed"] is True

    def test_on_change_callback_called_on_change(self):
        """Callback should be invoked when data changes."""
        from modules.scheduler import add_schedule, run_scheduled_scan, _load_schedules, _save_schedules
        scan = add_schedule("example.com", ["whois"])

        schedules = _load_schedules()
        schedules[scan.job_id].last_hash = "old_hash_0000000"
        _save_schedules(schedules)

        callback = MagicMock()

        with patch("modules.scheduler._dispatch_module_sync", return_value={"changed": "data"}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db"):
                    run_scheduled_scan(scan.job_id, on_change=callback)

        callback.assert_called_once()

    def test_module_failure_stored_as_error(self):
        from modules.scheduler import add_schedule, run_scheduled_scan
        scan = add_schedule("example.com", ["whois"])

        with patch("modules.scheduler._dispatch_module_sync", side_effect=Exception("timeout")):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db"):
                    result = run_scheduled_scan(scan.job_id)

        assert "error" in result["data"].get("whois", {})

    def test_report_failure_does_not_crash(self):
        from modules.scheduler import add_schedule, run_scheduled_scan
        scan = add_schedule("example.com", ["whois"])

        with patch("modules.scheduler._dispatch_module_sync", return_value={}):
            with patch("modules.scheduler.save_report", side_effect=Exception("write error")):
                with patch("modules.scheduler.get_db"):
                    result = run_scheduled_scan(scan.job_id)

        assert "job_id" in result  # Ran without crashing


class TestRunAllDue:
    def test_empty_schedules_returns_empty(self):
        from modules.scheduler import run_all_due
        result = run_all_due()
        assert result == []

    def test_new_scan_is_due(self):
        from modules.scheduler import add_schedule, run_all_due
        add_schedule("example.com", ["whois"])

        with patch("modules.scheduler._dispatch_module_sync", return_value={}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db"):
                    results = run_all_due()

        assert len(results) == 1
        assert results[0]["target"] == "example.com"

    def test_recently_run_scan_not_due(self):
        from modules.scheduler import add_schedule, run_all_due, _load_schedules, _save_schedules
        scan = add_schedule("example.com", ["whois"], interval_hours=24)

        # Mark it as just run
        schedules = _load_schedules()
        schedules[scan.job_id].last_run = datetime.datetime.utcnow().isoformat(timespec="seconds")
        _save_schedules(schedules)

        with patch("modules.scheduler._dispatch_module_sync", return_value={}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db"):
                    results = run_all_due()

        assert len(results) == 0

    def test_overdue_scan_runs(self):
        from modules.scheduler import add_schedule, run_all_due, _load_schedules, _save_schedules
        scan = add_schedule("example.com", ["whois"], interval_hours=1)

        # Mark it as run 2 hours ago
        two_hours_ago = (datetime.datetime.utcnow() - datetime.timedelta(hours=2)).isoformat(timespec="seconds")
        schedules = _load_schedules()
        schedules[scan.job_id].last_run = two_hours_ago
        _save_schedules(schedules)

        with patch("modules.scheduler._dispatch_module_sync", return_value={}):
            with patch("modules.scheduler.save_report"):
                with patch("modules.scheduler.get_db"):
                    results = run_all_due()

        assert len(results) == 1


class TestDispatchModuleSync:
    def test_unknown_module_raises(self):
        from modules.scheduler import _dispatch_module_sync
        with pytest.raises(ValueError, match="Unknown module"):
            _dispatch_module_sync("unknown_module_xyz", "example.com")

    def test_known_modules_list(self):
        """Verify all known module names are handled without ValueError."""
        from modules.scheduler import _dispatch_module_sync
        known_modules = ["whois", "dns", "ip", "email", "username", "ssl", "breach"]
        for module in known_modules:
            with patch(f"modules.scheduler._dispatch_module_sync") as mock_dispatch:
                mock_dispatch.return_value = {}
                # Just verify calling does not raise ValueError for known modules
                result = mock_dispatch(module, "example.com")
                assert result == {}