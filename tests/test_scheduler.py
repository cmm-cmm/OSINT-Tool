"""Tests for modules/scheduler.py — OSINT scan scheduling."""
import json
import datetime
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, call


@pytest.fixture
def schedule_file(tmp_path):
    """Return a temporary schedule file path and patch SCHEDULE_FILE."""
    sf = tmp_path / "schedules.json"
    with patch("modules.scheduler.SCHEDULE_FILE", sf):
        yield sf


class TestScheduledScan:
    def test_basic_init(self):
        from modules.scheduler import ScheduledScan
        s = ScheduledScan(
            job_id="abc12345",
            target="example.com",
            modules=["whois", "dns"],
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
        s = ScheduledScan("id", "t.com", ["whois"])
        assert s.tags == []

    def test_custom_interval(self):
        from modules.scheduler import ScheduledScan
        s = ScheduledScan("id", "t.com", ["whois"], interval_hours=12)
        assert s.interval_hours == 12

    def test_to_dict_roundtrip(self):
        from modules.scheduler import ScheduledScan
        s = ScheduledScan(
            job_id="abc12345",
            target="example.com",
            modules=["whois"],
            interval_hours=6,
            tags=["pentest"],
            output_dir="./out",
        )
        d = s.to_dict()
        assert d["job_id"] == "abc12345"
        assert d["target"] == "example.com"
        assert d["interval_hours"] == 6
        assert "pentest" in d["tags"]

    def test_from_dict(self):
        from modules.scheduler import ScheduledScan
        d = {
            "job_id": "test1234",
            "target": "test.com",
            "modules": ["dns", "ssl"],
            "interval_hours": 48,
            "alert_on_change": False,
            "output_dir": "./reports",
            "tags": ["automated"],
            "created_at": "2024-01-01T00:00:00",
            "last_run": "2024-01-02T00:00:00",
            "last_hash": "abcdef123456",
        }
        s = ScheduledScan.from_dict(d)
        assert s.job_id == "test1234"
        assert s.target == "test.com"
        assert s.modules == ["dns", "ssl"]
        assert s.interval_hours == 48
        assert s.alert_on_change is False
        assert s.last_run == "2024-01-02T00:00:00"
        assert s.last_hash == "abcdef123456"
        assert "automated" in s.tags

    def test_from_dict_defaults(self):
        from modules.scheduler import ScheduledScan
        d = {"job_id": "x", "target": "t.com"}
        s = ScheduledScan.from_dict(d)
        assert s.modules == ["whois", "dns"]
        assert s.interval_hours == 24
        assert s.alert_on_change is True

    def test_to_dict_from_dict_roundtrip(self):
        from modules.scheduler import ScheduledScan
        original = ScheduledScan("abc", "example.com", ["whois", "dns"], tags=["t1"])
        original.last_run = "2024-01-01T12:00:00"
        original.last_hash = "deadbeef1234"
        recovered = ScheduledScan.from_dict(original.to_dict())
        assert recovered.job_id == original.job_id
        assert recovered.target == original.target
        assert recovered.last_run == original.last_run
        assert recovered.last_hash == original.last_hash
        assert recovered.tags == original.tags


class TestDataHash:
    def test_deterministic(self):
        from modules.scheduler import _data_hash
        data = {"key": "value", "number": 42}
        h1 = _data_hash(data)
        h2 = _data_hash(data)
        assert h1 == h2

    def test_different_data_different_hash(self):
        from modules.scheduler import _data_hash
        h1 = _data_hash({"a": 1})
        h2 = _data_hash({"a": 2})
        assert h1 != h2

    def test_returns_16_chars(self):
        from modules.scheduler import _data_hash
        h = _data_hash({"test": "data"})
        assert len(h) == 16

    def test_order_independent(self):
        """dict.sort_keys=True means order doesn't matter."""
        from modules.scheduler import _data_hash
        h1 = _data_hash({"b": 2, "a": 1})
        h2 = _data_hash({"a": 1, "b": 2})
        assert h1 == h2


class TestLoadSaveSchedules:
    def test_load_empty_when_no_file(self, schedule_file):
        from modules.scheduler import _load_schedules
        assert not schedule_file.exists()
        result = _load_schedules()
        assert result == {}

    def test_save_and_load(self, schedule_file):
        from modules.scheduler import _load_schedules, _save_schedules, ScheduledScan
        scan = ScheduledScan("abc", "example.com", ["whois"])
        _save_schedules({"abc": scan})
        loaded = _load_schedules()
        assert "abc" in loaded
        assert loaded["abc"].target == "example.com"

    def test_save_creates_file(self, schedule_file):
        from modules.scheduler import _save_schedules, ScheduledScan
        scan = ScheduledScan("test", "t.com", ["dns"])
        _save_schedules({"test": scan})
        assert schedule_file.exists()

    def test_load_invalid_json_returns_empty(self, schedule_file):
        from modules.scheduler import _load_schedules
        schedule_file.write_text("not valid json", encoding="utf-8")
        result = _load_schedules()
        assert result == {}


class TestAddSchedule:
    def test_returns_scheduled_scan(self, schedule_file):
        from modules.scheduler import add_schedule
        result = add_schedule("example.com", ["whois", "dns"])
        assert result.target == "example.com"
        assert result.modules == ["whois", "dns"]

    def test_job_id_assigned(self, schedule_file):
        from modules.scheduler import add_schedule
        result = add_schedule("example.com", ["whois"])
        assert result.job_id is not None
        assert len(result.job_id) > 0

    def test_persisted_to_file(self, schedule_file):
        from modules.scheduler import add_schedule, _load_schedules
        scan = add_schedule("persist.com", ["dns"], interval_hours=12)
        loaded = _load_schedules()
        assert scan.job_id in loaded
        assert loaded[scan.job_id].target == "persist.com"

    def test_custom_interval(self, schedule_file):
        from modules.scheduler import add_schedule
        scan = add_schedule("t.com", ["whois"], interval_hours=6)
        assert scan.interval_hours == 6

    def test_tags_stored(self, schedule_file):
        from modules.scheduler import add_schedule, _load_schedules
        scan = add_schedule("t.com", ["whois"], tags=["pentest"])
        loaded = _load_schedules()
        assert "pentest" in loaded[scan.job_id].tags

    def test_multiple_schedules(self, schedule_file):
        from modules.scheduler import add_schedule, _load_schedules
        s1 = add_schedule("a.com", ["whois"])
        s2 = add_schedule("b.com", ["dns"])
        loaded = _load_schedules()
        assert s1.job_id in loaded
        assert s2.job_id in loaded


class TestRemoveSchedule:
    def test_remove_existing(self, schedule_file):
        from modules.scheduler import add_schedule, remove_schedule, _load_schedules
        scan = add_schedule("remove.com", ["whois"])
        result = remove_schedule(scan.job_id)
        assert result is True
        loaded = _load_schedules()
        assert scan.job_id not in loaded

    def test_remove_nonexistent(self, schedule_file):
        from modules.scheduler import remove_schedule
        result = remove_schedule("nonexistent_id")
        assert result is False

    def test_returns_false_for_missing_id(self, schedule_file):
        from modules.scheduler import remove_schedule
        assert remove_schedule("xxxxxxxx") is False


class TestListSchedules:
    def test_empty_when_none(self, schedule_file):
        from modules.scheduler import list_schedules
        result = list_schedules()
        assert result == []

    def test_returns_list_of_scheduled_scans(self, schedule_file):
        from modules.scheduler import add_schedule, list_schedules, ScheduledScan
        add_schedule("a.com", ["whois"])
        add_schedule("b.com", ["dns"])
        result = list_schedules()
        assert len(result) == 2
        assert all(isinstance(s, ScheduledScan) for s in result)


class TestRunScheduledScan:
    def test_missing_job_id_raises(self, schedule_file):
        from modules.scheduler import run_scheduled_scan
        from modules.exceptions import SchedulerError
        with pytest.raises(SchedulerError):
            run_scheduled_scan("nonexistent_id")

    def test_returns_result_dict(self, schedule_file):
        from modules.scheduler import add_schedule, run_scheduled_scan

        with patch("modules.scheduler._dispatch_module_sync", return_value={"data": "test"}):
            with patch("modules.report.save_report", return_value={}):
                with patch("modules.db.get_db"):
                    scan = add_schedule("example.com", ["whois"])
                    result = run_scheduled_scan(scan.job_id)

        assert "job_id" in result
        assert "target" in result
        assert "data_hash" in result
        assert "changed" in result
        assert "data" in result

    def test_changed_false_on_first_run(self, schedule_file):
        from modules.scheduler import add_schedule, run_scheduled_scan

        with patch("modules.scheduler._dispatch_module_sync", return_value={"x": 1}):
            with patch("modules.report.save_report", return_value={}):
                with patch("modules.db.get_db"):
                    scan = add_schedule("example.com", ["whois"])
                    result = run_scheduled_scan(scan.job_id)

        # First run: last_hash was None, so changed should be False
        assert result["changed"] is False

    def test_changed_true_when_data_differs(self, schedule_file):
        from modules.scheduler import add_schedule, run_scheduled_scan

        counter = {"n": 0}

        def mock_dispatch(module, target):
            counter["n"] += 1
            return {"result": counter["n"]}

        with patch("modules.scheduler._dispatch_module_sync", side_effect=mock_dispatch):
            with patch("modules.report.save_report", return_value={}):
                with patch("modules.db.get_db"):
                    scan = add_schedule("example.com", ["whois"])
                    run_scheduled_scan(scan.job_id)  # First run
                    result = run_scheduled_scan(scan.job_id)  # Second run with different data

        assert result["changed"] is True

    def test_on_change_callback_called(self, schedule_file):
        from modules.scheduler import add_schedule, run_scheduled_scan

        counter = {"n": 0}

        def mock_dispatch(module, target):
            counter["n"] += 1
            return {"result": counter["n"]}

        change_callback = MagicMock()

        with patch("modules.scheduler._dispatch_module_sync", side_effect=mock_dispatch):
            with patch("modules.report.save_report", return_value={}):
                with patch("modules.db.get_db"):
                    scan = add_schedule("example.com", ["whois"])
                    run_scheduled_scan(scan.job_id)  # Establish baseline
                    run_scheduled_scan(scan.job_id, on_change=change_callback)

        change_callback.assert_called_once()

    def test_on_change_not_called_when_no_change(self, schedule_file):
        from modules.scheduler import add_schedule, run_scheduled_scan

        def mock_dispatch(module, target):
            return {"static": "data"}

        change_callback = MagicMock()

        with patch("modules.scheduler._dispatch_module_sync", side_effect=mock_dispatch):
            with patch("modules.report.save_report", return_value={}):
                with patch("modules.db.get_db"):
                    scan = add_schedule("example.com", ["whois"])
                    run_scheduled_scan(scan.job_id)  # Establish baseline
                    run_scheduled_scan(scan.job_id, on_change=change_callback)

        change_callback.assert_not_called()

    def test_last_run_updated(self, schedule_file):
        from modules.scheduler import add_schedule, run_scheduled_scan, list_schedules

        with patch("modules.scheduler._dispatch_module_sync", return_value={}):
            with patch("modules.report.save_report", return_value={}):
                with patch("modules.db.get_db"):
                    scan = add_schedule("example.com", ["whois"])
                    assert scan.last_run is None
                    run_scheduled_scan(scan.job_id)
                    updated = {s.job_id: s for s in list_schedules()}
                    assert updated[scan.job_id].last_run is not None

    def test_module_failure_captured_in_data(self, schedule_file):
        from modules.scheduler import add_schedule, run_scheduled_scan

        def failing_dispatch(module, target):
            raise ValueError("Module failed")

        with patch("modules.scheduler._dispatch_module_sync", side_effect=failing_dispatch):
            with patch("modules.report.save_report", return_value={}):
                with patch("modules.db.get_db"):
                    scan = add_schedule("example.com", ["whois"])
                    result = run_scheduled_scan(scan.job_id)

        assert "error" in result["data"]["whois"]

    def test_result_contains_modules_run(self, schedule_file):
        from modules.scheduler import add_schedule, run_scheduled_scan

        with patch("modules.scheduler._dispatch_module_sync", return_value={}):
            with patch("modules.report.save_report", return_value={}):
                with patch("modules.db.get_db"):
                    scan = add_schedule("example.com", ["whois", "dns"])
                    result = run_scheduled_scan(scan.job_id)

        assert result["modules_run"] == ["whois", "dns"]


class TestRunAllDue:
    def test_empty_schedules(self, schedule_file):
        from modules.scheduler import run_all_due
        results = run_all_due()
        assert results == []

    def test_never_run_scans_are_due(self, schedule_file):
        from modules.scheduler import add_schedule, run_all_due

        with patch("modules.scheduler._dispatch_module_sync", return_value={}):
            with patch("modules.report.save_report", return_value={}):
                with patch("modules.db.get_db"):
                    add_schedule("due.com", ["whois"])
                    results = run_all_due()

        assert len(results) == 1
        assert results[0]["target"] == "due.com"

    def test_recently_run_scan_not_due(self, schedule_file):
        from modules.scheduler import add_schedule, run_all_due, _load_schedules, _save_schedules

        with patch("modules.scheduler._dispatch_module_sync", return_value={}):
            with patch("modules.report.save_report", return_value={}):
                with patch("modules.db.get_db"):
                    scan = add_schedule("recent.com", ["whois"], interval_hours=24)
                    # Set last_run to now
                    schedules = _load_schedules()
                    schedules[scan.job_id].last_run = datetime.datetime.utcnow().isoformat(timespec="seconds")
                    _save_schedules(schedules)
                    results = run_all_due()

        assert len(results) == 0

    def test_overdue_scan_is_run(self, schedule_file):
        from modules.scheduler import add_schedule, run_all_due, _load_schedules, _save_schedules

        with patch("modules.scheduler._dispatch_module_sync", return_value={}):
            with patch("modules.report.save_report", return_value={}):
                with patch("modules.db.get_db"):
                    scan = add_schedule("overdue.com", ["whois"], interval_hours=1)
                    # Set last_run to 2 hours ago
                    schedules = _load_schedules()
                    two_hours_ago = (datetime.datetime.utcnow() -
                                     datetime.timedelta(hours=2)).isoformat(timespec="seconds")
                    schedules[scan.job_id].last_run = two_hours_ago
                    _save_schedules(schedules)
                    results = run_all_due()

        assert len(results) == 1


class TestDispatchModuleSync:
    def test_unknown_module_raises(self):
        from modules.scheduler import _dispatch_module_sync
        with pytest.raises(ValueError, match="Unknown module"):
            _dispatch_module_sync("unknown_module_xyz", "target")

    def test_known_module_names(self):
        """Verify that the known module names are accepted (not raising ValueError)."""
        from modules.scheduler import _dispatch_module_sync
        known_modules = ["whois", "dns", "ip", "email", "username", "ssl", "breach"]
        for module in known_modules:
            # Each known module should NOT raise ValueError - the ValueError is only
            # for unknown modules. Actual dispatching may raise ImportError if
            # the underlying module isn't present, but that's a different error.
            try:
                _dispatch_module_sync(module, "test.com")
            except ValueError as exc:
                pytest.fail(f"Known module {module!r} raised ValueError: {exc}")
            except Exception:
                pass  # Import/network errors expected in test environment