#!/usr/bin/env python3
"""
Enhanced CLI Tool for LAN Reconnaissance Framework
==================================================

Provides a unified command-line interface for all framework operations.
Supports interactive mode, configuration management, and batch operations.

Features:
- Unified command structure
- Interactive shell mode
- Tab completion (when available)
- Output formatting (table, json, csv)
- Configuration profiles
- Batch job execution

Usage:
    # Single command
    lanrecon scan --target 192.168.1.0/24 --profile quick
    
    # Interactive mode
    lanrecon shell
    
    # Batch mode
    lanrecon batch jobs.yaml
"""

import os
import sys
import json
import argparse
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any


class OutputFormatter:
    """Handles output formatting for CLI."""
    
    @staticmethod
    def table(data: List[Dict], columns: Optional[List[str]] = None) -> str:
        """Format data as ASCII table."""
        if not data:
            return "No data"
        
        if columns is None:
            columns = list(data[0].keys())
        
        # Calculate column widths
        widths = {col: len(col) for col in columns}
        for row in data:
            for col in columns:
                value = str(row.get(col, ""))[:50]  # Truncate long values
                widths[col] = max(widths[col], len(value))
        
        # Build table
        lines = []
        
        # Header
        header = " | ".join(col.ljust(widths[col]) for col in columns)
        separator = "-+-".join("-" * widths[col] for col in columns)
        lines.append(header)
        lines.append(separator)
        
        # Rows
        for row in data:
            line = " | ".join(
                str(row.get(col, ""))[:50].ljust(widths[col])
                for col in columns
            )
            lines.append(line)
        
        return "\n".join(lines)
    
    @staticmethod
    def json_output(data: Any, indent: int = 2) -> str:
        """Format data as JSON."""
        return json.dumps(data, indent=indent, default=str)
    
    @staticmethod
    def csv_output(data: List[Dict], columns: Optional[List[str]] = None) -> str:
        """Format data as CSV."""
        if not data:
            return ""
        
        if columns is None:
            columns = list(data[0].keys())
        
        lines = [",".join(columns)]
        for row in data:
            values = []
            for col in columns:
                value = str(row.get(col, ""))
                if "," in value or '"' in value:
                    value = f'"{value.replace(chr(34), chr(34)+chr(34))}"'
                values.append(value)
            lines.append(",".join(values))
        
        return "\n".join(lines)


class Colors:
    """ANSI color codes."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    
    @classmethod
    def disable(cls):
        """Disable colors."""
        cls.RESET = cls.BOLD = cls.RED = cls.GREEN = ""
        cls.YELLOW = cls.BLUE = cls.CYAN = ""


class LanReconCLI:
    """Main CLI application."""
    
    VERSION = "2.3.0"
    
    def __init__(self):
        self.formatter = OutputFormatter()
        self.output_format = "table"
        self.verbose = False
        
        # Check if colors should be disabled
        if not sys.stdout.isatty() or os.getenv("NO_COLOR"):
            Colors.disable()
    
    def print_success(self, message: str):
        """Print success message."""
        print(f"{Colors.GREEN}✓{Colors.RESET} {message}")
    
    def print_error(self, message: str):
        """Print error message."""
        print(f"{Colors.RED}✗{Colors.RESET} {message}", file=sys.stderr)
    
    def print_warning(self, message: str):
        """Print warning message."""
        print(f"{Colors.YELLOW}⚠{Colors.RESET} {message}")
    
    def print_info(self, message: str):
        """Print info message."""
        print(f"{Colors.CYAN}ℹ{Colors.RESET} {message}")
    
    def format_output(self, data: Any) -> str:
        """Format output based on current format setting."""
        if self.output_format == "json":
            return self.formatter.json_output(data)
        elif self.output_format == "csv":
            if isinstance(data, list):
                return self.formatter.csv_output(data)
            return self.formatter.json_output(data)
        else:
            if isinstance(data, list) and data and isinstance(data[0], dict):
                return self.formatter.table(data)
            return str(data)
    
    # ==================== Commands ====================
    
    def cmd_scan(self, args):
        """Start a new scan."""
        config = {
            "target_network": args.target,
            "profile": args.profile,
            "parallel": not args.no_parallel,
            "timeout": args.timeout
        }
        
        self.print_info(f"Starting scan of {args.target} with profile '{args.profile}'")
        
        # Build docker-compose command
        env_vars = [
            f"TARGET_NETWORK={args.target}",
            f"PARALLEL_EXECUTION={'true' if not args.no_parallel else 'false'}",
            f"SCAN_TIMEOUT={args.timeout}"
        ]
        
        if args.dry_run:
            self.print_warning("Dry run - would execute:")
            print(f"  docker-compose up -d")
            print(f"  Environment: {env_vars}")
            return 0
        
        try:
            # Execute scan
            result = subprocess.run(
                ["docker-compose", "up", "-d"],
                env={**os.environ, **dict(e.split("=") for e in env_vars)},
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                self.print_success("Scan started successfully")
                return 0
            else:
                self.print_error(f"Failed to start scan: {result.stderr}")
                return 1
                
        except FileNotFoundError:
            self.print_error("docker-compose not found. Is Docker installed?")
            return 1
    
    def cmd_status(self, args):
        """Get scan status."""
        try:
            result = subprocess.run(
                ["docker-compose", "ps", "--format", "json"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                try:
                    containers = json.loads(result.stdout) if result.stdout.strip() else []
                    if isinstance(containers, dict):
                        containers = [containers]
                    
                    status_data = []
                    for c in containers:
                        status_data.append({
                            "Name": c.get("Name", c.get("name", "unknown")),
                            "Status": c.get("State", c.get("status", "unknown")),
                            "Health": c.get("Health", "N/A")
                        })
                    
                    if status_data:
                        print(self.format_output(status_data))
                    else:
                        self.print_info("No containers running")
                except json.JSONDecodeError:
                    # Fallback to plain output
                    print(result.stdout)
                return 0
            else:
                self.print_error(f"Failed to get status: {result.stderr}")
                return 1
                
        except FileNotFoundError:
            self.print_error("docker-compose not found")
            return 1
    
    def cmd_stop(self, args):
        """Stop running scan."""
        self.print_info("Stopping scan...")
        
        try:
            result = subprocess.run(
                ["docker-compose", "down"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                self.print_success("Scan stopped")
                return 0
            else:
                self.print_error(f"Failed to stop: {result.stderr}")
                return 1
                
        except FileNotFoundError:
            self.print_error("docker-compose not found")
            return 1
    
    def cmd_logs(self, args):
        """View logs."""
        cmd = ["docker-compose", "logs"]
        
        if args.follow:
            cmd.append("-f")
        
        if args.tail:
            cmd.extend(["--tail", str(args.tail)])
        
        if args.container:
            cmd.append(args.container)
        
        try:
            subprocess.run(cmd)
            return 0
        except FileNotFoundError:
            self.print_error("docker-compose not found")
            return 1
    
    def cmd_results(self, args):
        """View scan results."""
        output_dir = args.output_dir or "./output"
        
        if not os.path.exists(output_dir):
            self.print_error(f"Output directory not found: {output_dir}")
            return 1
        
        # Find latest results
        result_files = []
        for f in os.listdir(output_dir):
            if f.endswith(".json"):
                path = os.path.join(output_dir, f)
                result_files.append({
                    "file": f,
                    "modified": datetime.fromtimestamp(os.path.getmtime(path)).isoformat(),
                    "size": os.path.getsize(path)
                })
        
        result_files.sort(key=lambda x: x["modified"], reverse=True)
        
        if args.list:
            print(self.format_output(result_files))
            return 0
        
        if args.file:
            filepath = os.path.join(output_dir, args.file)
        elif result_files:
            filepath = os.path.join(output_dir, result_files[0]["file"])
        else:
            self.print_error("No result files found")
            return 1
        
        try:
            with open(filepath) as f:
                data = json.load(f)
            
            if args.summary:
                # Print summary
                summary = {
                    "scan_time": data.get("timestamp"),
                    "target": data.get("target_network"),
                    "hosts_found": len(data.get("hosts", [])),
                    "findings": len(data.get("findings", [])),
                    "risk_score": data.get("risk_score", "N/A")
                }
                print(self.format_output([summary]))
            else:
                print(self.format_output(data))
            
            return 0
            
        except Exception as e:
            self.print_error(f"Failed to read results: {e}")
            return 1
    
    def cmd_config(self, args):
        """Manage configuration."""
        config_file = args.config_file or ".env"
        
        if args.show:
            if os.path.exists(config_file):
                with open(config_file) as f:
                    print(f.read())
            else:
                self.print_info(f"No config file found at {config_file}")
            return 0
        
        if args.set:
            # Parse key=value pairs
            config = {}
            if os.path.exists(config_file):
                with open(config_file) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            key, value = line.split("=", 1)
                            config[key] = value
            
            for setting in args.set:
                if "=" not in setting:
                    self.print_error(f"Invalid setting format: {setting}")
                    return 1
                key, value = setting.split("=", 1)
                config[key] = value
                self.print_success(f"Set {key}={value}")
            
            # Write config
            with open(config_file, "w") as f:
                for key, value in sorted(config.items()):
                    f.write(f"{key}={value}\n")
            
            return 0
        
        if args.get:
            if os.path.exists(config_file):
                with open(config_file) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith(f"{args.get}="):
                            print(line.split("=", 1)[1])
                            return 0
            self.print_error(f"Config key not found: {args.get}")
            return 1
        
        self.print_info("Use --show, --set KEY=VALUE, or --get KEY")
        return 0
    
    def cmd_profiles(self, args):
        """List available scan profiles."""
        profiles_file = os.path.join(
            os.path.dirname(__file__),
            "..",
            "data",
            "scan-profiles.json"
        )
        
        if os.path.exists(profiles_file):
            with open(profiles_file) as f:
                profiles = json.load(f)
            
            profile_list = []
            for name, config in profiles.get("profiles", {}).items():
                profile_list.append({
                    "name": name,
                    "description": config.get("description", ""),
                    "estimated_time": config.get("estimated_time", "N/A")
                })
            
            print(self.format_output(profile_list))
        else:
            # Default profiles
            default_profiles = [
                {"name": "quick", "description": "Fast scan with minimal probing", "estimated_time": "5-10 min"},
                {"name": "standard", "description": "Balanced scan", "estimated_time": "15-30 min"},
                {"name": "thorough", "description": "Comprehensive scan", "estimated_time": "45-90 min"},
                {"name": "stealth", "description": "Low-noise scan", "estimated_time": "30-60 min"},
                {"name": "iot_focused", "description": "IoT device focus", "estimated_time": "20-40 min"},
                {"name": "vulnerability", "description": "Security focus", "estimated_time": "30-60 min"},
                {"name": "compliance", "description": "Compliance checking", "estimated_time": "20-45 min"}
            ]
            print(self.format_output(default_profiles))
        
        return 0
    
    def cmd_schedule(self, args):
        """Manage scheduled scans."""
        try:
            from scheduler import ScanScheduler
            scheduler = ScanScheduler()
            
            if args.list:
                jobs = scheduler.list_jobs()
                if jobs:
                    job_list = []
                    for job in jobs:
                        job_list.append({
                            "ID": job["job_id"],
                            "Name": job["name"],
                            "Schedule": f"{job['schedule_type']}:{job['schedule_value']}",
                            "Next Run": job.get("next_run", "N/A"),
                            "Status": job.get("status", "pending")
                        })
                    print(self.format_output(job_list))
                else:
                    self.print_info("No scheduled jobs")
                return 0
            
            if args.add:
                job_id = scheduler.add_job(
                    name=args.name or f"job_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                    config={"target_network": args.target, "profile": args.profile},
                    schedule_type=args.schedule_type,
                    schedule_value=args.schedule_value
                )
                self.print_success(f"Added scheduled job: {job_id}")
                return 0
            
            if args.remove:
                if scheduler.remove_job(args.remove):
                    self.print_success(f"Removed job: {args.remove}")
                else:
                    self.print_error(f"Job not found: {args.remove}")
                    return 1
                return 0
            
            if args.run_now:
                if scheduler.run_now(args.run_now):
                    self.print_success(f"Job triggered: {args.run_now}")
                else:
                    self.print_error(f"Job not found: {args.run_now}")
                    return 1
                return 0
            
        except ImportError:
            self.print_error("Scheduler module not available")
            return 1
        
        return 0
    
    def cmd_export(self, args):
        """Export scan data."""
        try:
            from export_import import ExportManager
            exporter = ExportManager()
            
            if args.all:
                output = exporter.export_all_scans(
                    format=args.format,
                    output=args.output,
                    compress=args.compress
                )
            elif args.scan_id:
                output = exporter.export_scan(
                    scan_id=args.scan_id,
                    format=args.format,
                    output=args.output,
                    anonymize=args.anonymize,
                    compress=args.compress
                )
            elif args.hosts:
                output = exporter.export_hosts(
                    format=args.format,
                    output=args.output,
                    anonymize=args.anonymize
                )
            elif args.findings:
                output = exporter.export_findings(
                    format=args.format,
                    output=args.output,
                    anonymize=args.anonymize
                )
            else:
                self.print_error("Specify --scan-id, --all, --hosts, or --findings")
                return 1
            
            self.print_success(f"Exported to: {output}")
            return 0
            
        except ImportError:
            self.print_error("Export module not available")
            return 1
        except Exception as e:
            self.print_error(f"Export failed: {e}")
            return 1
    
    def cmd_import(self, args):
        """Import scan data."""
        try:
            from export_import import ImportManager
            importer = ImportManager()
            
            result = importer.import_file(
                args.file,
                merge=not args.replace,
                validate=not args.no_validate
            )
            
            if result["success"]:
                self.print_success(f"Import successful: {result['stats']}")
                return 0
            else:
                self.print_error(f"Import failed: {result.get('errors', 'Unknown error')}")
                return 1
                
        except ImportError:
            self.print_error("Import module not available")
            return 1
        except Exception as e:
            self.print_error(f"Import failed: {e}")
            return 1
    
    def cmd_anomalies(self, args):
        """View detected anomalies."""
        try:
            from anomaly_detection import AnomalyDetector
            detector = AnomalyDetector()
            
            anomalies = detector.get_anomaly_history(
                host=args.host,
                anomaly_type=args.type,
                severity=args.severity,
                limit=args.limit
            )
            
            if anomalies:
                anomaly_list = []
                for a in anomalies:
                    anomaly_list.append({
                        "Time": a.get("detected_at", "")[:19],
                        "Severity": a.get("severity", "").upper(),
                        "Type": a.get("anomaly_type", ""),
                        "Host": a.get("host", "N/A"),
                        "Description": a.get("description", "")[:50]
                    })
                print(self.format_output(anomaly_list))
            else:
                self.print_info("No anomalies found")
            
            return 0
            
        except ImportError:
            self.print_error("Anomaly detection module not available")
            return 1
    
    def cmd_version(self, args):
        """Show version information."""
        print(f"LAN Reconnaissance Framework CLI v{self.VERSION}")
        print(f"Framework v2.3.0")
        return 0
    
    def cmd_shell(self, args):
        """Start interactive shell."""
        self.print_info("Starting interactive shell (type 'help' for commands, 'exit' to quit)")
        
        while True:
            try:
                cmd = input(f"{Colors.CYAN}lanrecon>{Colors.RESET} ").strip()
                
                if not cmd:
                    continue
                
                if cmd.lower() in ("exit", "quit", "q"):
                    break
                
                if cmd.lower() == "help":
                    print("\nAvailable commands:")
                    print("  scan    - Start a scan")
                    print("  status  - View scan status")
                    print("  stop    - Stop running scan")
                    print("  logs    - View logs")
                    print("  results - View results")
                    print("  config  - Manage configuration")
                    print("  exit    - Exit shell")
                    print()
                    continue
                
                # Parse and execute command
                parts = cmd.split()
                sys.argv = ["lanrecon"] + parts
                self.run()
                
            except KeyboardInterrupt:
                print()
                continue
            except EOFError:
                break
        
        return 0
    
    def run(self):
        """Run CLI with argument parsing."""
        parser = argparse.ArgumentParser(
            prog="lanrecon",
            description="LAN Reconnaissance Framework CLI",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  lanrecon scan --target 192.168.1.0/24
  lanrecon scan --target 10.0.0.0/24 --profile thorough
  lanrecon status
  lanrecon results --summary
  lanrecon export --scan-id abc123 --format json
  lanrecon schedule --add --target 192.168.1.0/24 --cron "0 2 * * *"
            """
        )
        
        parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
        parser.add_argument("-f", "--format", choices=["table", "json", "csv"], 
                          default="table", help="Output format")
        parser.add_argument("--no-color", action="store_true", help="Disable colored output")
        
        subparsers = parser.add_subparsers(dest="command", help="Command to run")
        
        # scan command
        scan_parser = subparsers.add_parser("scan", help="Start a new scan")
        scan_parser.add_argument("-t", "--target", required=True, help="Target network (CIDR)")
        scan_parser.add_argument("-p", "--profile", default="standard", help="Scan profile")
        scan_parser.add_argument("--no-parallel", action="store_true", help="Disable parallel execution")
        scan_parser.add_argument("--timeout", type=int, default=600, help="Scan timeout in seconds")
        scan_parser.add_argument("--dry-run", action="store_true", help="Show what would be done")
        
        # status command
        subparsers.add_parser("status", help="View scan status")
        
        # stop command
        subparsers.add_parser("stop", help="Stop running scan")
        
        # logs command
        logs_parser = subparsers.add_parser("logs", help="View container logs")
        logs_parser.add_argument("-f", "--follow", action="store_true", help="Follow log output")
        logs_parser.add_argument("-n", "--tail", type=int, help="Number of lines to show")
        logs_parser.add_argument("container", nargs="?", help="Specific container")
        
        # results command
        results_parser = subparsers.add_parser("results", help="View scan results")
        results_parser.add_argument("-l", "--list", action="store_true", help="List result files")
        results_parser.add_argument("-s", "--summary", action="store_true", help="Show summary only")
        results_parser.add_argument("--file", help="Specific result file")
        results_parser.add_argument("-o", "--output-dir", help="Output directory")
        
        # config command
        config_parser = subparsers.add_parser("config", help="Manage configuration")
        config_parser.add_argument("--show", action="store_true", help="Show current config")
        config_parser.add_argument("--set", action="append", help="Set config value (KEY=VALUE)")
        config_parser.add_argument("--get", help="Get config value")
        config_parser.add_argument("--config-file", help="Config file path")
        
        # profiles command
        subparsers.add_parser("profiles", help="List scan profiles")
        
        # schedule command
        schedule_parser = subparsers.add_parser("schedule", help="Manage scheduled scans")
        schedule_parser.add_argument("-l", "--list", action="store_true", help="List scheduled jobs")
        schedule_parser.add_argument("--add", action="store_true", help="Add new scheduled job")
        schedule_parser.add_argument("--remove", help="Remove job by ID")
        schedule_parser.add_argument("--run-now", help="Run job immediately")
        schedule_parser.add_argument("--name", help="Job name")
        schedule_parser.add_argument("--target", help="Target network")
        schedule_parser.add_argument("--profile", default="standard", help="Scan profile")
        schedule_parser.add_argument("--schedule-type", default="daily", 
                                    choices=["once", "interval", "cron", "daily", "weekly"])
        schedule_parser.add_argument("--schedule-value", default="02:00", help="Schedule value")
        
        # export command
        export_parser = subparsers.add_parser("export", help="Export scan data")
        export_parser.add_argument("--scan-id", help="Scan ID to export")
        export_parser.add_argument("--all", action="store_true", help="Export all scans")
        export_parser.add_argument("--hosts", action="store_true", help="Export hosts only")
        export_parser.add_argument("--findings", action="store_true", help="Export findings only")
        export_parser.add_argument("--format", default="json", 
                                  choices=["json", "csv", "xml", "yaml"])
        export_parser.add_argument("-o", "--output", help="Output file")
        export_parser.add_argument("--anonymize", action="store_true", help="Anonymize data")
        export_parser.add_argument("--compress", action="store_true", help="Compress output")
        
        # import command
        import_parser = subparsers.add_parser("import", help="Import scan data")
        import_parser.add_argument("file", help="File to import")
        import_parser.add_argument("--replace", action="store_true", help="Replace existing data")
        import_parser.add_argument("--no-validate", action="store_true", help="Skip validation")
        
        # anomalies command
        anomalies_parser = subparsers.add_parser("anomalies", help="View detected anomalies")
        anomalies_parser.add_argument("--host", help="Filter by host")
        anomalies_parser.add_argument("--type", help="Filter by type")
        anomalies_parser.add_argument("--severity", help="Filter by severity")
        anomalies_parser.add_argument("--limit", type=int, default=20, help="Max results")
        
        # version command
        subparsers.add_parser("version", help="Show version")
        
        # shell command
        subparsers.add_parser("shell", help="Start interactive shell")
        
        args = parser.parse_args()
        
        # Apply global options
        self.verbose = args.verbose
        self.output_format = args.format
        if args.no_color:
            Colors.disable()
        
        # Execute command
        if args.command is None:
            parser.print_help()
            return 0
        
        cmd_method = getattr(self, f"cmd_{args.command}", None)
        if cmd_method:
            return cmd_method(args)
        else:
            self.print_error(f"Unknown command: {args.command}")
            return 1


def main():
    """Main entry point."""
    cli = LanReconCLI()
    sys.exit(cli.run())


if __name__ == "__main__":
    main()
