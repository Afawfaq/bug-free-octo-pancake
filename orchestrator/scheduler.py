#!/usr/bin/env python3
"""
Scan Scheduler for LAN Reconnaissance Framework
================================================

Provides scheduled and recurring scan capabilities.
Supports cron-like expressions, one-time schedules, and periodic scans.

Features:
- Cron-style scheduling
- One-time scheduled scans
- Recurring scans with configurable intervals
- Scan job management (add, remove, pause, resume)
- Persistence across restarts
- Email/webhook notifications on completion

Usage:
    from scheduler import ScanScheduler
    
    scheduler = ScanScheduler()
    scheduler.add_job("daily-scan", cron="0 2 * * *", config=scan_config)
    scheduler.start()
"""

import os
import sys
import json
import time
import threading
import sqlite3
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from enum import Enum
import uuid


class JobStatus(Enum):
    """Scan job status values."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class ScheduleType(Enum):
    """Types of scheduling."""
    ONCE = "once"           # One-time execution at specific datetime
    INTERVAL = "interval"   # Repeat every N seconds/minutes/hours
    CRON = "cron"           # Cron-style expression
    DAILY = "daily"         # Daily at specific time
    WEEKLY = "weekly"       # Weekly on specific day and time


class CronParser:
    """
    Simple cron expression parser.
    
    Supports: minute hour day_of_month month day_of_week
    Example: "0 2 * * *" = 2:00 AM every day
    """
    
    @staticmethod
    def parse(cron_expr: str) -> Dict[str, List[int]]:
        """Parse cron expression into components."""
        parts = cron_expr.strip().split()
        if len(parts) != 5:
            raise ValueError(f"Invalid cron expression: {cron_expr}")
        
        return {
            "minute": CronParser._parse_field(parts[0], 0, 59),
            "hour": CronParser._parse_field(parts[1], 0, 23),
            "day": CronParser._parse_field(parts[2], 1, 31),
            "month": CronParser._parse_field(parts[3], 1, 12),
            "weekday": CronParser._parse_field(parts[4], 0, 6)
        }
    
    @staticmethod
    def _parse_field(field: str, min_val: int, max_val: int) -> List[int]:
        """Parse a single cron field."""
        if field == "*":
            return list(range(min_val, max_val + 1))
        
        values = []
        for part in field.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                values.extend(range(start, end + 1))
            elif "/" in part:
                base, step = part.split("/")
                if base == "*":
                    start = min_val
                else:
                    start = int(base)
                values.extend(range(start, max_val + 1, int(step)))
            else:
                values.append(int(part))
        
        return sorted(set(values))
    
    @staticmethod
    def matches(cron_expr: str, dt: datetime) -> bool:
        """Check if datetime matches cron expression."""
        parsed = CronParser.parse(cron_expr)
        return (
            dt.minute in parsed["minute"] and
            dt.hour in parsed["hour"] and
            dt.day in parsed["day"] and
            dt.month in parsed["month"] and
            dt.weekday() in parsed["weekday"]
        )
    
    @staticmethod
    def next_run(cron_expr: str, after: Optional[datetime] = None) -> datetime:
        """Calculate next run time from cron expression."""
        if after is None:
            after = datetime.now()
        
        # Start from next minute
        current = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
        
        # Search for next matching time (up to 1 year)
        for _ in range(525600):  # Max minutes in a year
            if CronParser.matches(cron_expr, current):
                return current
            current += timedelta(minutes=1)
        
        raise ValueError(f"Could not find next run time for: {cron_expr}")


class ScanJob:
    """
    Represents a scheduled scan job.
    """
    
    def __init__(
        self,
        job_id: str,
        name: str,
        schedule_type: ScheduleType,
        config: Dict,
        schedule_value: str,
        enabled: bool = True,
        notification_config: Optional[Dict] = None
    ):
        self.job_id = job_id
        self.name = name
        self.schedule_type = schedule_type
        self.config = config
        self.schedule_value = schedule_value
        self.enabled = enabled
        self.notification_config = notification_config or {}
        
        self.status = JobStatus.PENDING
        self.last_run: Optional[datetime] = None
        self.next_run: Optional[datetime] = None
        self.run_count = 0
        self.last_result: Optional[Dict] = None
        self.created_at = datetime.now()
        
        # Calculate initial next run
        self._calculate_next_run()
    
    def _calculate_next_run(self):
        """Calculate next run time based on schedule."""
        now = datetime.now()
        
        if self.schedule_type == ScheduleType.ONCE:
            # schedule_value is ISO datetime string
            self.next_run = datetime.fromisoformat(self.schedule_value)
        
        elif self.schedule_type == ScheduleType.INTERVAL:
            # schedule_value is seconds (e.g., "3600" for 1 hour)
            interval = int(self.schedule_value)
            if self.last_run:
                self.next_run = self.last_run + timedelta(seconds=interval)
            else:
                self.next_run = now + timedelta(seconds=interval)
        
        elif self.schedule_type == ScheduleType.CRON:
            self.next_run = CronParser.next_run(self.schedule_value, self.last_run)
        
        elif self.schedule_type == ScheduleType.DAILY:
            # schedule_value is time string "HH:MM"
            hour, minute = map(int, self.schedule_value.split(":"))
            target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if target <= now:
                target += timedelta(days=1)
            self.next_run = target
        
        elif self.schedule_type == ScheduleType.WEEKLY:
            # schedule_value is "DAY HH:MM" (e.g., "MON 02:00")
            day_map = {"MON": 0, "TUE": 1, "WED": 2, "THU": 3, "FRI": 4, "SAT": 5, "SUN": 6}
            parts = self.schedule_value.split()
            target_day = day_map.get(parts[0].upper(), 0)
            hour, minute = map(int, parts[1].split(":"))
            
            days_ahead = target_day - now.weekday()
            if days_ahead <= 0:
                days_ahead += 7
            
            target = now + timedelta(days=days_ahead)
            target = target.replace(hour=hour, minute=minute, second=0, microsecond=0)
            self.next_run = target
    
    def should_run(self) -> bool:
        """Check if job should run now."""
        if not self.enabled or self.status == JobStatus.PAUSED:
            return False
        return self.next_run is not None and datetime.now() >= self.next_run
    
    def mark_started(self):
        """Mark job as started."""
        self.status = JobStatus.RUNNING
    
    def mark_completed(self, result: Dict):
        """Mark job as completed with result."""
        self.status = JobStatus.COMPLETED
        self.last_run = datetime.now()
        self.last_result = result
        self.run_count += 1
        self._calculate_next_run()
    
    def mark_failed(self, error: str):
        """Mark job as failed."""
        self.status = JobStatus.FAILED
        self.last_run = datetime.now()
        self.last_result = {"error": error}
        self.run_count += 1
        self._calculate_next_run()
    
    def to_dict(self) -> Dict:
        """Convert job to dictionary for serialization."""
        return {
            "job_id": self.job_id,
            "name": self.name,
            "schedule_type": self.schedule_type.value,
            "config": self.config,
            "schedule_value": self.schedule_value,
            "enabled": self.enabled,
            "notification_config": self.notification_config,
            "status": self.status.value,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "run_count": self.run_count,
            "created_at": self.created_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "ScanJob":
        """Create job from dictionary."""
        job = cls(
            job_id=data["job_id"],
            name=data["name"],
            schedule_type=ScheduleType(data["schedule_type"]),
            config=data["config"],
            schedule_value=data["schedule_value"],
            enabled=data.get("enabled", True),
            notification_config=data.get("notification_config")
        )
        job.status = JobStatus(data.get("status", "pending"))
        job.last_run = datetime.fromisoformat(data["last_run"]) if data.get("last_run") else None
        job.run_count = data.get("run_count", 0)
        job.created_at = datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now()
        job._calculate_next_run()
        return job


class ScanScheduler:
    """
    Scheduler for managing and executing scheduled scan jobs.
    """
    
    def __init__(
        self,
        db_path: Optional[str] = None,
        scan_executor: Optional[Callable] = None,
        check_interval: int = 60
    ):
        """
        Initialize scheduler.
        
        Args:
            db_path: Path to SQLite database for persistence
            scan_executor: Callable that executes scans (receives config Dict)
            check_interval: Seconds between schedule checks
        """
        self.db_path = db_path or os.path.join(
            os.path.dirname(__file__),
            "..",
            "data",
            "scheduler.db"
        )
        self.scan_executor = scan_executor
        self.check_interval = check_interval
        
        self.jobs: Dict[str, ScanJob] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Initialize database and load jobs
        self._init_db()
        self._load_jobs()
    
    def _init_db(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scheduled_jobs (
                    job_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    schedule_type TEXT NOT NULL,
                    config TEXT NOT NULL,
                    schedule_value TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    notification_config TEXT,
                    status TEXT DEFAULT 'pending',
                    last_run TEXT,
                    next_run TEXT,
                    run_count INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS job_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    status TEXT NOT NULL,
                    result TEXT,
                    error TEXT,
                    FOREIGN KEY (job_id) REFERENCES scheduled_jobs(job_id)
                )
            ''')
            
            conn.commit()
    
    def _load_jobs(self):
        """Load jobs from database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scheduled_jobs")
            
            for row in cursor.fetchall():
                data = {
                    "job_id": row["job_id"],
                    "name": row["name"],
                    "schedule_type": row["schedule_type"],
                    "config": json.loads(row["config"]),
                    "schedule_value": row["schedule_value"],
                    "enabled": bool(row["enabled"]),
                    "notification_config": json.loads(row["notification_config"]) if row["notification_config"] else None,
                    "status": row["status"],
                    "last_run": row["last_run"],
                    "run_count": row["run_count"],
                    "created_at": row["created_at"]
                }
                self.jobs[data["job_id"]] = ScanJob.from_dict(data)
    
    def _save_job(self, job: ScanJob):
        """Save job to database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO scheduled_jobs
                (job_id, name, schedule_type, config, schedule_value, enabled,
                 notification_config, status, last_run, next_run, run_count, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                job.job_id,
                job.name,
                job.schedule_type.value,
                json.dumps(job.config),
                job.schedule_value,
                int(job.enabled),
                json.dumps(job.notification_config) if job.notification_config else None,
                job.status.value,
                job.last_run.isoformat() if job.last_run else None,
                job.next_run.isoformat() if job.next_run else None,
                job.run_count,
                job.created_at.isoformat()
            ))
            conn.commit()
    
    def _save_job_history(self, job: ScanJob, start_time: datetime, 
                          end_time: datetime, status: str, 
                          result: Optional[Dict] = None, error: Optional[str] = None):
        """Save job execution history."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO job_history (job_id, start_time, end_time, status, result, error)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                job.job_id,
                start_time.isoformat(),
                end_time.isoformat(),
                status,
                json.dumps(result) if result else None,
                error
            ))
            conn.commit()
    
    def add_job(
        self,
        name: str,
        config: Dict,
        schedule_type: str = "interval",
        schedule_value: str = "3600",
        enabled: bool = True,
        notification_config: Optional[Dict] = None
    ) -> str:
        """
        Add a new scheduled job.
        
        Args:
            name: Job name
            config: Scan configuration
            schedule_type: "once", "interval", "cron", "daily", "weekly"
            schedule_value: Schedule value (depends on type)
            enabled: Whether job is enabled
            notification_config: Notification settings
        
        Returns:
            Job ID
        """
        job_id = str(uuid.uuid4())[:8]
        
        job = ScanJob(
            job_id=job_id,
            name=name,
            schedule_type=ScheduleType(schedule_type),
            config=config,
            schedule_value=schedule_value,
            enabled=enabled,
            notification_config=notification_config
        )
        
        with self._lock:
            self.jobs[job_id] = job
            self._save_job(job)
        
        return job_id
    
    def remove_job(self, job_id: str) -> bool:
        """Remove a scheduled job."""
        with self._lock:
            if job_id not in self.jobs:
                return False
            
            del self.jobs[job_id]
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scheduled_jobs WHERE job_id = ?", (job_id,))
                conn.commit()
            
            return True
    
    def pause_job(self, job_id: str) -> bool:
        """Pause a scheduled job."""
        with self._lock:
            if job_id not in self.jobs:
                return False
            
            self.jobs[job_id].status = JobStatus.PAUSED
            self._save_job(self.jobs[job_id])
            return True
    
    def resume_job(self, job_id: str) -> bool:
        """Resume a paused job."""
        with self._lock:
            if job_id not in self.jobs:
                return False
            
            job = self.jobs[job_id]
            if job.status == JobStatus.PAUSED:
                job.status = JobStatus.PENDING
                job._calculate_next_run()
                self._save_job(job)
            return True
    
    def get_job(self, job_id: str) -> Optional[Dict]:
        """Get job details."""
        with self._lock:
            if job_id not in self.jobs:
                return None
            return self.jobs[job_id].to_dict()
    
    def list_jobs(self) -> List[Dict]:
        """List all scheduled jobs."""
        with self._lock:
            return [job.to_dict() for job in self.jobs.values()]
    
    def get_job_history(self, job_id: str, limit: int = 10) -> List[Dict]:
        """Get execution history for a job."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM job_history
                WHERE job_id = ?
                ORDER BY start_time DESC
                LIMIT ?
            ''', (job_id, limit))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def _execute_job(self, job: ScanJob):
        """Execute a scan job."""
        start_time = datetime.now()
        job.mark_started()
        self._save_job(job)
        
        try:
            if self.scan_executor:
                result = self.scan_executor(job.config)
            else:
                # Placeholder execution
                result = {"message": "No executor configured", "config": job.config}
            
            job.mark_completed(result)
            self._save_job(job)
            self._save_job_history(job, start_time, datetime.now(), "completed", result)
            
            # Send notification if configured
            self._send_notification(job, "completed", result)
            
        except Exception as e:
            error_msg = str(e)
            job.mark_failed(error_msg)
            self._save_job(job)
            self._save_job_history(job, start_time, datetime.now(), "failed", error=error_msg)
            
            # Send failure notification
            self._send_notification(job, "failed", {"error": error_msg})
    
    def _send_notification(self, job: ScanJob, status: str, result: Dict):
        """Send notification for job completion/failure."""
        if not job.notification_config:
            return
        
        try:
            # Import notification module if available
            from notifications import NotificationManager
            
            manager = NotificationManager()
            
            if job.notification_config.get("slack_webhook"):
                manager.send_slack(
                    job.notification_config["slack_webhook"],
                    f"Scheduled scan '{job.name}' {status}",
                    result
                )
            
            if job.notification_config.get("email"):
                manager.send_email(
                    job.notification_config["email"],
                    f"Scheduled scan '{job.name}' {status}",
                    json.dumps(result, indent=2)
                )
                
        except ImportError:
            pass  # Notifications module not available
        except Exception:
            pass  # Notification failed, but don't crash
    
    def _scheduler_loop(self):
        """Main scheduler loop."""
        while self._running:
            try:
                with self._lock:
                    jobs_to_run = [
                        job for job in self.jobs.values()
                        if job.should_run()
                    ]
                
                for job in jobs_to_run:
                    # Run job in separate thread
                    thread = threading.Thread(
                        target=self._execute_job,
                        args=(job,),
                        daemon=True
                    )
                    thread.start()
                
            except Exception as e:
                print(f"Scheduler error: {e}")
            
            # Wait before next check
            time.sleep(self.check_interval)
    
    def start(self):
        """Start the scheduler."""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Stop the scheduler."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
    
    def run_now(self, job_id: str) -> bool:
        """Manually trigger a job to run immediately."""
        with self._lock:
            if job_id not in self.jobs:
                return False
            
            job = self.jobs[job_id]
            thread = threading.Thread(
                target=self._execute_job,
                args=(job,),
                daemon=True
            )
            thread.start()
            return True


# Convenience functions for quick scheduling
def schedule_daily(name: str, config: Dict, time_str: str = "02:00") -> str:
    """Schedule a daily scan at specified time."""
    scheduler = ScanScheduler()
    return scheduler.add_job(name, config, "daily", time_str)


def schedule_weekly(name: str, config: Dict, day_time: str = "SUN 03:00") -> str:
    """Schedule a weekly scan on specified day and time."""
    scheduler = ScanScheduler()
    return scheduler.add_job(name, config, "weekly", day_time)


def schedule_cron(name: str, config: Dict, cron_expr: str) -> str:
    """Schedule a scan with cron expression."""
    scheduler = ScanScheduler()
    return scheduler.add_job(name, config, "cron", cron_expr)


def schedule_interval(name: str, config: Dict, seconds: int) -> str:
    """Schedule a recurring scan at fixed intervals."""
    scheduler = ScanScheduler()
    return scheduler.add_job(name, config, "interval", str(seconds))


if __name__ == "__main__":
    # Example usage
    scheduler = ScanScheduler()
    
    # Add some test jobs
    job1_id = scheduler.add_job(
        name="Daily Quick Scan",
        config={"profile": "quick", "target_network": "192.168.1.0/24"},
        schedule_type="daily",
        schedule_value="02:00"
    )
    
    job2_id = scheduler.add_job(
        name="Weekly Full Scan",
        config={"profile": "thorough", "target_network": "192.168.1.0/24"},
        schedule_type="weekly",
        schedule_value="SUN 03:00"
    )
    
    job3_id = scheduler.add_job(
        name="Hourly Monitor",
        config={"profile": "quick", "phases": ["passive", "discovery"]},
        schedule_type="interval",
        schedule_value="3600"
    )
    
    # List jobs
    print("\nScheduled Jobs:")
    for job in scheduler.list_jobs():
        print(f"  {job['name']} ({job['job_id']})")
        print(f"    Schedule: {job['schedule_type']} - {job['schedule_value']}")
        print(f"    Next run: {job['next_run']}")
        print()
    
    # Start scheduler
    print("Starting scheduler...")
    scheduler.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping scheduler...")
        scheduler.stop()
