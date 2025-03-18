"""MIT License

Copyright (c) 2025 Segeras

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""


#!/usr/bin/env python3

import argparse
import asyncio
import datetime
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import zipfile
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import configparser
import importlib.util
import html
from pyminizip import compress  # Requires `pyminizip` for password-protected ZIPs

# Configure logging for debugging and user feedback
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class ReportGenerationError(Exception):
    """Custom exception for report generation failures with user-friendly messages."""
    pass

class ReportGenerator:
    """Handles system report generation with advanced options like redaction and plugin support."""

    def __init__(self, output_dir: str, format_type: str = "text", compress: bool = False, zip_password: Optional[str] = None):
        self.output_dir = Path(output_dir)  # Directory where reports will be saved
        self.format_type = format_type.lower()  # Output format (text, json, html)
        self.compress = compress  # Whether to compress the report into a ZIP file
        self.zip_password = zip_password  # Optional password for ZIP compression
        self.distro = self._detect_distro()  # Detected Linux distribution
        self.plugin_dir = Path.home() / ".systemreport" / "plugins"  # Directory for user plugins
        # Default redaction patterns for sensitive data
        self.redact_patterns = {
            "MAC": r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}",  # Matches MAC addresses
            "IP": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",  # Matches IPv4 addresses
            "IPv6": r"([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}",  # Matches IPv6 addresses
            "Serial": r"Serial.*?: .*",  # Matches serial numbers
            "UUID": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"  # Matches UUIDs
        }
        self.config = self._load_config()  # Load configuration settings

    def _load_config(self) -> configparser.ConfigParser:
        """Load configuration from ~/.systemreport.conf, creating it with defaults if it doesn't exist."""
        config = configparser.ConfigParser()
        config_file = Path.home() / ".systemreport.conf"
        if config_file.exists():
            config.read(config_file)
        else:
            # Default configuration values
            config["DEFAULT"] = {
                "output_dir": str(Path.home() / "reports"),
                "censorship": "necessary",
                "verbosity": "default",
                "format": "text",
                "compress": "no",
                "zip_password": ""
            }
            with config_file.open("w") as f:
                config.write(f)
        return config

    async def run_command(self, command: str) -> str:
        """Run a shell command asynchronously and provide detailed error messages if it fails."""
        cmd_name = command.split()[0]  # Extract the command name for existence check
        if not shutil.which(cmd_name):
            return f"[Command not found: {cmd_name}]"  # Early exit if command doesn't exist
        try:
            # Create a subprocess to run the command asynchronously
            proc = await asyncio.create_subprocess_shell(
                command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()  # Wait for command completion
            if proc.returncode == 0:
                return stdout.decode().rstrip()  # Return successful output
            else:
                # Return detailed error with return code and stderr for debugging
                return f"[Error running '{command}': Return code {proc.returncode}, Stderr: {stderr.decode().rstrip()}]"
        except Exception as e:
            return f"[Exception running '{command}': {str(e)}]"  # Catch unexpected errors

    def _detect_distro(self) -> str:
        """Detect the Linux distribution by reading /etc/os-release."""
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("ID="):
                        return line.strip().split("=")[1].strip('"').lower()  # Extract and normalize distro ID
        return "unknown"  # Fallback if detection fails

    def _get_package_commands(self) -> List[str]:
        """Return package listing and update commands based on the detected Linux distribution."""
        pkg_commands = []  # Commands to list installed packages
        update_commands = []  # Commands to check for updates
        
        # Check for Arch-based distributions
        if self.distro in ["arch", "manjaro", "endeavouros"]:
            pkg_commands.append("pacman -Qe")
            update_commands.append("pacman -Qu")
            if shutil.which("yay"):
                pkg_commands.append("yay -Qe")
        
        # Check for Fedora, CentOS, or RHEL
        elif self.distro in ["fedora", "centos", "rhel"]:
            pkg_commands.append("dnf list --installed")
            update_commands.append("dnf check-update")
        
        # Check for Ubuntu, Debian, or Linux Mint
        elif self.distro in ["ubuntu", "debian", "linuxmint"]:
            pkg_commands.append("dpkg -l")
            update_commands.append("apt list --upgradable")
        
        # Check for openSUSE distributions
        elif self.distro in ["opensuse", "opensuse-tumbleweed"]:
            pkg_commands.append("zypper se -i")
            update_commands.append("zypper lu")
        
        # If the distribution is not recognized
        else:
            pkg_commands.append("echo 'Package manager not recognized'")
            update_commands.append("echo 'Update check not supported'")
        
        # Add commands for additional package managers if installed
        if shutil.which("flatpak"):
            pkg_commands.append("flatpak list")
        if shutil.which("snap"):
            pkg_commands.append("snap list")
        
        return pkg_commands + update_commands

    def _load_plugins(self) -> Dict[str, str]:
        """Load plugins from ~/.systemreport/plugins/ and handle any loading errors gracefully."""
        plugin_data = {}
        self.plugin_dir.mkdir(parents=True, exist_ok=True)
        for plugin_file in self.plugin_dir.glob("*.py"):
            try:
                spec = importlib.util.spec_from_file_location(plugin_file.stem, plugin_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                if hasattr(module, "collect_data"):
                    plugin_data[plugin_file.stem] = module.collect_data()
                else:
                    logger.warning(f"Plugin '{plugin_file.stem}' does not have a 'collect_data' function.")
            except Exception as e:
                logger.error(f"Failed to load plugin '{plugin_file.stem}': {str(e)}")
        return plugin_data

    def redact_text(self, text: str, level: str, command: str, custom_patterns: List[str]) -> str:
        """Redact sensitive information from command output based on censorship level and custom patterns."""
        if level == "none" or (level == "necessary" and command == "neofetch"):
            return text
        elif level == "necessary":
            patterns = list(self.redact_patterns.values()) + custom_patterns
            for pattern in patterns:
                flags = re.IGNORECASE if "Serial" in pattern else 0
                text = re.sub(pattern, "[REDACTED]", text, flags=flags)
            return text
        elif level == "over":
            return "[FULL OUTPUT REDACTED]"
        return text

    def clean_output(self, text: str) -> str:
        """Clean command output by removing ANSI codes and extra whitespace."""
        text = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', text)
        return "\n".join(line.rstrip() for line in text.splitlines() if line.strip())

    async def generate_report(self, censorship: str, verbosity: str, custom_commands: List[str], custom_patterns: List[str], performance: bool) -> Dict[str, str]:
        """Generate the system report based on specified options."""
        basic_safe = ["uname -r", "lscpu", "free -h", "df -h --total", "uptime", "neofetch"]
        hardware_safe = ["lspci", "lsusb", "dmidecode -t bios", "lsblk -o NAME,SIZE,TYPE,MOUNTPOINT", "sensors"]
        sensitive = ["ip a", "ss -tuln", "dmidecode -t system", "lsof -i", "who", "last -n 10"]
        logs = ["journalctl -b --no-pager | tail -n 100"] if not os.path.exists("/var/log/syslog") else ["tail -n 100 /var/log/syslog"]
        services = ["systemctl list-units --type=service --no-pager | head -n 50"]
        disk_health = ["smartctl -a /dev/sda"] if shutil.which("smartctl") else []
        performance_metrics = ["iostat -d 1 2", "top -bn1 | head -n 20"] if performance and shutil.which("iostat") else []

        commands = basic_safe if censorship == "over" else (
            basic_safe + (hardware_safe if verbosity != "summary" else []) + 
            (sensitive + self._get_package_commands() + logs + services + disk_health + performance_metrics if verbosity == "verbose" else [])
        )
        commands.extend(custom_commands)

        report_data = {}
        tasks = [self.run_command(cmd) for cmd in commands]
        results = await asyncio.gather(*tasks)

        for cmd, result in zip(commands, results):
            cleaned = self.clean_output(result)
            redacted = self.redact_text(cleaned, censorship, cmd, custom_patterns)
            report_data[cmd] = redacted
            logger.debug(f"Processed command: {cmd}")

        report_data["plugins"] = self._load_plugins()
        return report_data

    def save_report(self, report_data: Dict[str, str], censorship: str, verbosity: str) -> str:
        """Save the report in the specified format after ensuring the output directory is writable."""
        now = datetime.datetime.now()
        time_str = now.strftime('%H-%M-%S')
        date_str = now.strftime('%Y-%m-%d')
        suffix = f"{censorship}_{verbosity}"
        file_name = f"system_report_{date_str}_{time_str}_{suffix}"
        file_path = self.output_dir / (file_name + (".json" if self.format_type == "json" else ".html" if self.format_type == "html" else ".txt"))

        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            raise ReportGenerationError(f"Cannot create output directory '{self.output_dir}': Permission denied.")

        if not os.access(self.output_dir, os.W_OK):
            raise ReportGenerationError(f"Output directory '{self.output_dir}' is not writable.")

        if self.format_type == "json":
            content = json.dumps({
                "metadata": {"generated": now.isoformat(), "distro": self.distro, "censorship": censorship, "verbosity": verbosity},
                "data": report_data
            }, indent=2)
        elif self.format_type == "html":
            content = self._generate_html(report_data, now, censorship, verbosity)
        else:
            header = f"""SYSTEM INFORMATION REPORT
Generated: {now.strftime('%Y-%m-%d %H:%M:%S')}
Distribution: {self.distro.capitalize()}
Censorship: {censorship.capitalize()}
Verbosity: {verbosity.capitalize()}
"""
            content = header + "\n".join(f"{'-' * 20} {cmd.upper()} {'-' * 20}\n{output}" for cmd, output in report_data.items() if cmd != "plugins") + \
                      "\n" + "\n".join(f"{'-' * 20} PLUGIN: {name.upper()} {'-' * 20}\n{data}" for name, data in report_data.get("plugins", {}).items())

        with file_path.open("w") as f:
            f.write(content)

        if self.compress:
            zip_path = self.output_dir / f"{file_name}.zip"
            if self.zip_password:
                compress(str(file_path), None, str(zip_path), self.zip_password, 5)
            else:
                with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.write(file_path, file_path.name)
            file_path.unlink()
            return str(zip_path)
        return str(file_path)

    def _generate_html(self, report_data: Dict[str, str], now: datetime.datetime, censorship: str, verbosity: str) -> str:
        """Generate HTML report content with styled output."""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>System Report - {now.strftime('%Y-%m-%d %H:%M:%S')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; }}
        pre {{ background: #f4f4f4; padding: 10px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>System Information Report</h1>
    <p><strong>Generated:</strong> {now.strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p><strong>Distribution:</strong> {self.distro.capitalize()}</p>
    <p><strong>Censorship:</strong> {censorship.capitalize()}</p>
    <p><strong>Verbosity:</strong> {verbosity.capitalize()}</p>
"""
        for cmd, output in report_data.items():
            if cmd != "plugins":
                html_content += f"<h2>{html.escape(cmd.upper())}</h2><pre>{html.escape(output)}</pre>"
        for name, data in report_data.get("plugins", {}).items():
            html_content += f"<h2>Plugin: {html.escape(name.upper())}</h2><pre>{html.escape(str(data))}</pre>"
        html_content += "</body></html>"
        return html_content

class Scheduler:
    """Manages scheduling of report generation using systemd or cron with support for multiple instances."""

    @staticmethod
    def schedule_task(script_path: str, output_dir: str, boot: bool, interval: Optional[int], args: List[str], instance_name: str) -> None:
        """Schedule a new instance of the report generator with a unique name using systemd or cron."""
        if os.path.exists("/run/systemd/system"):
            # Use unique service and timer names based on instance_name for systemd
            service_name = f"system_report_{instance_name}.service"
            timer_name = f"system_report_{instance_name}.timer"
            service_content = f"""
[Unit]
Description=System Report Generation - {instance_name}
After=network.target

[Service]
Type=oneshot
ExecStart={script_path} -o {output_dir} {' '.join(args)}

[Install]
WantedBy=multi-user.target
"""
            with open(f"/etc/systemd/system/{service_name}", "w") as f:
                f.write(service_content)
            if boot or interval:
                timer_content = f"""
[Unit]
Description=Timer for System Report - {instance_name}

[Timer]
"""
                if boot:
                    timer_content += "OnBootSec=0\n"
                if interval:
                    timer_content += f"OnUnitActiveSec={interval}h\n"
                timer_content += f"""
Unit={service_name}

[Install]
WantedBy=timers.target
"""
                with open(f"/etc/systemd/system/{timer_name}", "w") as f:
                    f.write(timer_content)
                subprocess.run(["systemctl", "daemon-reload"], check=True)
                subprocess.run(["systemctl", "enable", timer_name], check=True)
                subprocess.run(["systemctl", "start", timer_name], check=True)
            logger.info(f"Scheduled report generation: instance={instance_name}, boot={boot}, interval={interval}h")
        else:
            # Fallback to cron (single instance support only)
            logger.warning("Systemd not detected. Using cron (multiple instances not supported).")
            cron_cmd = f"{script_path} -o {output_dir} {' '.join(args)}"
            cron_line = f"0 */{interval} * * * {cron_cmd}" if interval else f"@reboot {cron_cmd}"
            subprocess.run(f"(crontab -l 2>/dev/null; echo '{cron_line}') | crontab -", shell=True)

    @staticmethod
    def list_instances():
        """List all active scheduled report instances when using systemd."""
        if os.path.exists("/run/systemd/system"):
            timer_files = Path("/etc/systemd/system").glob("system_report_*.timer")
            for timer_file in timer_files:
                instance_name = timer_file.stem.replace("system_report_", "").replace(".timer", "")
                config = configparser.ConfigParser()
                config.read(timer_file)
                on_boot = config.get("Timer", "OnBootSec", fallback="Not set")
                on_interval = config.get("Timer", "OnUnitActiveSec", fallback="Not set")
                print(f"Instance: {instance_name}")
                print(f"  OnBootSec: {on_boot}")
                print(f"  OnUnitActiveSec: {on_interval}")
        else:
            print("Systemd not detected. Cannot list scheduled instances with cron.")

    @staticmethod
    def stop_instance(instance_name: str):
        """Stop and disable a specific scheduled instance when using systemd."""
        if os.path.exists("/run/systemd/system"):
            timer_name = f"system_report_{instance_name}.timer"
            service_name = f"system_report_{instance_name}.service"
            subprocess.run(["systemctl", "stop", timer_name], check=False)
            subprocess.run(["systemctl", "disable", timer_name], check=False)
            subprocess.run(["systemctl", "stop", service_name], check=False)
            subprocess.run(["systemctl", "disable", service_name], check=False)
            logger.info(f"Stopped and disabled instance '{instance_name}'")
        else:
            logger.warning("Systemd not detected. Cannot stop scheduled instance with cron.")

    @staticmethod
    def stop_all_instances():
        """Stop and disable all scheduled report instances when using systemd."""
        if os.path.exists("/run/systemd/system"):
            timer_files = Path("/etc/systemd/system").glob("system_report_*.timer")
            for timer_file in timer_files:
                instance_name = timer_file.stem.replace("system_report_", "").replace(".timer", "")
                Scheduler.stop_instance(instance_name)
            logger.info("Stopped and disabled all scheduled instances")
        else:
            logger.warning("Systemd not detected. Cannot stop all scheduled instances with cron.")

def interactive_mode() -> Tuple[str, str, str, bool, List[str], List[str], bool, Optional[str]]:
    """Interactive CLI mode for configuring the report generation."""
    print("Welcome to System Report Generator v2.2 Interactive Mode!")
    output_dir = input("Enter output directory: ").strip()
    censorship = input("Censorship level (none/necessary/over) [necessary]: ").strip() or "necessary"
    verbosity = input("Verbosity level (summary/default/verbose) [default]: ").strip() or "default"
    compress = input("Compress report? (yes/no) [no]: ").strip().lower() == "yes"
    zip_password = input("Set ZIP password (leave blank for none): ").strip() if compress else None
    custom = input("Enter custom commands (comma-separated, or leave blank): ").strip()
    custom_commands = [cmd.strip() for cmd in custom.split(",")] if custom else []
    patterns = input("Enter custom redaction patterns (comma-separated regex, or leave blank): ").strip()
    custom_patterns = [p.strip() for p in patterns.split(",")] if patterns else []
    performance = input("Include performance metrics? (yes/no) [no]: ").strip().lower() == "yes"
    return output_dir, censorship, verbosity, compress, custom_commands, custom_patterns, performance, zip_password

def show_help_menu():
    """Display an interactive help menu for the System Report Generator."""
    def print_general_usage():
        print("""
General Usage:
- Run the script with: python3 systemreport_generator.py [options]
- Use --help to see all available command-line options
- Configuration settings can be customized in ~/.systemreport.conf
- Use --interactive for interactive configuration of report generation
- Use --help-menu for this interactive help menu
""")

    def print_report_generation_help():
        print("""
Report Generation:
- Output formats: text, json, html
  - Use --format [text|json|html] to specify the format
- Redaction levels: none, necessary, over
  - Use --uncensored for no redaction
  - Use --censored for full redaction
  - Default is 'necessary' redaction of sensitive information
- Verbosity levels: summary, default, verbose
  - Use --brief for summary output
  - Use --verbose for detailed output
  - Default is 'default' verbosity
- Custom commands: Add extra commands to run with --custom-commands "cmd1,cmd2"
- Custom redaction patterns: Add regex patterns with --redact-patterns "pattern1,pattern2"
- Performance metrics: Include with --performance
""")

    def print_scheduling_help():
        print("""
Scheduling:
- Schedule report generation with --schedule [instance_name] [boot] [interval_hours]
  - instance_name: Optional name for the scheduled instance (auto-generated if omitted)
  - boot: Run at boot time
  - interval_hours: Run every specified hours
  - Example: --schedule my_instance boot 24
- List scheduled instances with --list-schedules
- Stop a specific instance with --stop-schedule instance_name
- Stop all instances with --stop-all-schedules
- Scheduling requires root privileges and uses systemd when available
""")

    def print_plugins_help():
        print("""
Plugins:
- Plugins are Python modules in ~/.systemreport/plugins/
- Each plugin should have a collect_data() function that returns a string
- Plugins can be used to collect custom data for the report
- Example plugin:
  def collect_data():
      return "Custom data"
""")

    while True:
        print("\nHelp Menu:")
        print("1. General Usage")
        print("2. Report Generation")
        print("3. Scheduling")
        print("4. Plugins")
        print("5. Exit")
        choice = input("Enter your choice: ").strip()
        if choice == "1":
            print_general_usage()
        elif choice == "2":
            print_report_generation_help()
        elif choice == "3":
            print_scheduling_help()
        elif choice == "4":
            print_plugins_help()
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")

async def main():
    parser = argparse.ArgumentParser(description="System Report Generator v2.2 - Advanced system information tool.")
    parser.add_argument("-o", "--output", help="Output directory for the report")
    parser.add_argument("-u", "--uncensored", action="store_true", help="No redaction")
    parser.add_argument("-c", "--censored", action="store_true", help="Fully censored output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Detailed output")
    parser.add_argument("-b", "--brief", action="store_true", help="Brief output")
    parser.add_argument("--format", choices=["text", "json", "html"], default="text", help="Output format (text/json/html)")
    parser.add_argument("--compress", action="store_true", help="Compress report into a .zip file")
    parser.add_argument("--zip-password", help="Password for ZIP compression")
    parser.add_argument("--schedule", nargs="*", help="Schedule: --schedule [instance_name] [boot] [interval_hours]")
    parser.add_argument("--list-schedules", action="store_true", help="List all scheduled report instances")
    parser.add_argument("--stop-schedule", help="Stop a specific scheduled instance by name")
    parser.add_argument("--stop-all-schedules", action="store_true", help="Stop all scheduled report instances")
    parser.add_argument("--custom-commands", help="Comma-separated custom commands to run")
    parser.add_argument("--redact-patterns", help="Comma-separated custom redaction patterns (regex)")
    parser.add_argument("--performance", action="store_true", help="Include performance metrics")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--help-menu", action="store_true", help="Show interactive help menu")
    args = parser.parse_args()

    # Handle interactive help menu
    if args.help_menu:
        show_help_menu()
        sys.exit(0)

    # Handle scheduling management (requires root privileges)
    if args.list_schedules or args.stop_schedule or args.stop_all_schedules or args.schedule:
        if os.geteuid() != 0:
            logger.error("Scheduling management requires root privileges.")
            sys.exit(1)
        if args.list_schedules:
            Scheduler.list_instances()
            sys.exit(0)
        elif args.stop_schedule:
            Scheduler.stop_instance(args.stop_schedule)
            sys.exit(0)
        elif args.stop_all_schedules:
            Scheduler.stop_all_instances()
            sys.exit(0)
        elif args.schedule:
            # Parse schedule arguments
            if len(args.schedule) == 0:
                parser.error("--schedule requires at least one argument")
            instance_name = None
            boot = False
            interval = None
            if args.schedule[0].lower() == "boot":
                boot = True
                if len(args.schedule) > 1 and args.schedule[1].isdigit():
                    interval = int(args.schedule[1])
            elif args.schedule[0].isdigit():
                interval = int(args.schedule[0])
            else:
                instance_name = args.schedule[0]
                if len(args.schedule) > 1 and args.schedule[1].lower() == "boot":
                    boot = True
                    if len(args.schedule) > 2 and args.schedule[2].isdigit():
                        interval = int(args.schedule[2])
                elif len(args.schedule) > 1 and args.schedule[1].isdigit():
                    interval = int(args.schedule[1])
            if not boot and interval is None:
                parser.error("Invalid --schedule arguments")
            # Generate instance_name if not provided
            if instance_name is None:
                instance_name = f"instance_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
            # Sanitize instance_name to ensure valid file names
            instance_name = re.sub(r'\W+', '_', instance_name)
            # Prepare script arguments for scheduling
            script_args = [f"--{args.censorship}", f"--{args.verbosity}", "--format", args.format]
            if args.compress:
                script_args.append("--compress")
            if args.zip_password:
                script_args.append(f"--zip-password {args.zip_password}")
            if args.custom_commands:
                script_args.append(f"--custom-commands {args.custom_commands}")
            if args.redact_patterns:
                script_args.append(f"--redact-patterns {args.redact_patterns}")
            if args.performance:
                script_args.append("--performance")
            Scheduler.schedule_task(os.path.abspath(__file__), args.output or "", boot, interval, script_args, instance_name)
            logger.info(f"Scheduled instance '{instance_name}'")
            sys.exit(0)

    # Proceed with report generation
    config = ReportGenerator(args.output or "").config["DEFAULT"]

    if args.interactive:
        output_dir, censorship, verbosity, compress, custom_commands, custom_patterns, performance, zip_password = interactive_mode()
    else:
        output_dir = args.output or config.get("output_dir")
        compress = args.compress or config.getboolean("compress", fallback=False)
        zip_password = args.zip_password or config.get("zip_password", fallback=None)
        custom_commands = args.custom_commands.split(",") if args.custom_commands else []
        custom_patterns = args.redact_patterns.split(",") if args.redact_patterns else []
        performance = args.performance

        if sum([args.uncensored, args.censored]) > 1 or sum([args.verbose, args.brief]) > 1:
            parser.error("Conflicting flags detected.")
        censorship = "over" if args.censored else "none" if args.uncensored else config.get("censorship", "necessary")
        verbosity = "verbose" if args.verbose else "summary" if args.brief else config.get("verbosity", "default")

    generator = ReportGenerator(output_dir, args.format or config.get("format", "text"), compress, zip_password)
    logger.info("Generating report...")
    report_data = await generator.generate_report(censorship, verbosity, custom_commands, custom_patterns, performance)
    file_path = generator.save_report(report_data, censorship, verbosity)
    logger.info(f"Report saved to: {file_path}")

if __name__ == "__main__":
    asyncio.run(main())