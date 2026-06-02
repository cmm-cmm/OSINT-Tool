"""Tests for modules/scheduler.py — change detection and schedule management."""
import json
import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture
def tmp_schedule_dir(tmp_path, monkeypatch):
    """Redirect schedule storage to a temp directory."""
    import modules.scheduler as sched
    fake_file = tmp_path / "schedules.json"
    monkeypatch.setattr(sched, "SCHEDULE_FILE", fake_file)
    return tmp_path


class TestScheduledScan:
    def test_to_dict_roundtrip(self):
        from modules.scheduler import ScheduledScan
        scan = ScheduledScan(
            job_id="abc123",
            target="example.com",
            modules=["whois", "dns"],
            interval_hours=12,
            alert_on_change=True,
            output_dir="./out",
            tags=["test"],
        )
        d = scan.to_dict()
        restored = ScheduledScan.from_dict(d)
        assert restored.job_id == "abc123"
        assert restored.target == "example.com"
        assert restored.modules == ["whois", "dns"]
        assert restored.interval_hours == 12
        assert restored.tags == ["test"]

    def test_from_dict_defaults(self):
        from modules.scheduler import ScheduledScan
        d = {"job_id": "x1", "target": "test.com"}
        scan = ScheduledScan.from_dict(d)
        assert scan.modules == ["whois", "dns"]
        assert scan.interval_hours == 24
        assert scan.alert_on_change is True

    def test_last_run_starts_none(self):
        from modules.scheduler import ScheduledScan
        scan = ScheduledScan("j1", "t.com", ["whois"])
        assert scan.last_run is None
        assert scan.last_hash is None


class TestScheduleManagement:
    def test_add_and_list(self, tmp_schedule_dir):
        from modules.scheduler import add_schedule, list_schedules
        scan = add_schedule("example.com", ["whois", "dns"], interval_hours=6)
        assert scan.job_id
        schedules = list_schedules()
        assert len(schedules) == 1
        assert schedules[0].target == "example.com"

    def test_remove_existing(self, tmp_schedule_dir):
        from modules.scheduler import add_schedule, remove_schedule, list_schedules
        scan = add_schedule("test.com", ["dns"])
        assert remove_schedule(scan.job_id) is True
        assert list_schedules() == []

    def test_remove_nonexistent(self, tmp_schedule_dir):
        from modules.scheduler import remove_schedule
        assert remove_schedule("nonexistent_id") is False

    def test_multiple_schedules(self, tmp_schedule_dir):
        from modules.scheduler import add_schedule, list_schedules
        add_schedule("a.com", ["whois"])
        add_schedule("b.com", ["dns"])
        add_schedule("c.com", ["ip"])
        assert len(list_schedules()) == 3


class TestChangeDetection:
    def test_data_hash_deterministic(self):
        from modules.scheduler import _data_hash
        data = {"a": 1, "b": [1, 2, 3]}
        h1 = _data_hash(data)
        h2 = _data_hash(data)
        assert h1 == h2

    def test_data_hash_changes_on_diff(self):
        from modules.scheduler import _data_hash
        h1 = _data_hash({"registrar": "GoDaddy"})
        h2 = _data_hash({"registrar": "Namecheap"})
        assert h1 != h2

    def test_run_scheduled_scan_change_detection(self, tmp_schedule_dir):
        from modules.scheduler import add_schedule, run_scheduled_scan
        scan = add_schedule("change-test.com", ["whois"])

        call_count = [0]

        def mock_dispatch(module, target):
            call_count[0] += 1
            return {"registrar": f"Registrar-{call_count[0]}"}

        with patch("modules.scheduler._dispatch_module_sync", side_effect=mock_dispatch):
            # First run: no previous hash → changed=False
            r1 = run_scheduled_scan(scan.job_id)
            assert r1["changed"] is False

            # Second run: different data → changed=True
            r2 = run_scheduled_scan(scan.job_id)
            assert r2["changed"] is True

    def test_run_scheduled_scan_no_change(self, tmp_schedule_dir):
        from modules.scheduler import add_schedule, run_scheduled_scan
        scan = add_schedule("stable.com", ["whois"])

        fixed_data = {"registrar": "SameRegistrar", "ns": ["ns1.stable.com"]}

        with patch("modules.scheduler._dispatch_module_sync", return_value=fixed_data):
            run_scheduled_scan(scan.job_id)  # first run
            r2 = run_scheduled_scan(scan.job_id)
            assert r2["changed"] is False

    def test_on_change_callback_called(self, tmp_schedule_dir):
        from modules.scheduler import add_schedule, run_scheduled_scan
        scan = add_schedule("cb-test.com", ["whois"])
        callback_calls = []

        def on_change(target, old, new):
            callback_calls.append({"target": target, "new": new})

        with patch("modules.scheduler._dispatch_module_sync", return_value={"data": "v1"}):
            run_scheduled_scan(scan.job_id)  # sets hash

        with patch("modules.scheduler._dispatch_module_sync", return_value={"data": "v2"}):
            run_scheduled_scan(scan.job_id, on_change=on_change)

        assert len(callback_calls) == 1
        assert callback_calls[0]["target"] == "cb-test.com"

    def test_run_nonexistent_job_raises(self, tmp_schedule_dir):
        from modules.scheduler import run_scheduled_scan
        from modules.exceptions import SchedulerError
        with pytest.raises(SchedulerError):
            run_scheduled_scan("nonexistent-job-id")


class TestRunAllDue:
    def test_runs_only_due_scans(self, tmp_schedule_dir):
        import datetime
        from modules.scheduler import add_schedule, list_schedules, run_all_due
        import modules.scheduler as sched

        scan = add_schedule("due.com", ["whois"], interval_hours=1)

        # Mark as last run 2 hours ago → is due
        schedules = sched._load_schedules()
        two_hours_ago = (datetime.datetime.utcnow() - datetime.timedelta(hours=2)).isoformat(timespec="seconds")
        schedules[scan.job_id].last_run = two_hours_ago
        schedules[scan.job_id].last_hash = "oldhash"
        sched._save_schedules(schedules)

        with patch("modules.scheduler._dispatch_module_sync", return_value={"data": "new"}):
            results = run_all_due()

        assert len(results) == 1
        assert results[0]["target"] == "due.com"
