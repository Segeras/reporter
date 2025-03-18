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
            # pacman -Qe lists explicitly installed packages
            pkg_commands.append("pacman -Qe")
            # pacman -Qu lists available updates
            update_commands.append("pacman -Qu")
            # If yay (AUR helper) is installed, list explicitly installed AUR packages
            if shutil.which("yay"):
                pkg_commands.append("yay -Qe")
        
        # Check for Fedora, CentOS, or RHEL
        elif self.distro in ["fedora", "centos", "rhel"]:
            # dnf list --installed shows all installed packages
            pkg_commands.append("dnf list --installed")
            # dnf check-update lists available updates
            update_commands.append("dnf check-update")
        
        # Check for Ubuntu, Debian, or Linux Mint
        elif self.distro in ["ubuntu", "debian", "linuxmint"]:
            # dpkg -l lists all installed packages
            pkg_commands.append("dpkg -l")
            # apt list --upgradable shows packages with available updates
            update_commands.append("apt list --upgradable")
        
        # Check for openSUSE distributions
        elif self.distro in ["opensuse", "opensuse-tumbleweed"]:
            # zypper se -i lists installed packages
            pkg_commands.append("zypper se -i")
            # zypper lu lists available updates
            update_commands.append("zypper lu")
        
        # If the distribution is not recognized
        else:
            pkg_commands.append("echo 'Package manager not recognized'")
            update_commands.append("echo 'Update check not supported'")
        
        # Add commands for additional package managers if installed
        if shutil.which("flatpak"):
            # flatpak list shows installed flatpak applications
            pkg_commands.append("flatpak list")
        if shutil.which("snap"):
            # snap list shows installed snap packages
            pkg_commands.append("snap list")
        
        # Combine package listing and update commands into a single list
        return pkg_commands + update_commands

    def _load_plugins(self) -> Dict[str, str]:
        """Load plugins from ~/.systemreport/plugins/ and handle any loading errors gracefully."""
        plugin_data = {}  # Dictionary to store plugin output
        self.plugin_dir.mkdir(parents=True, exist_ok=True)  # Ensure plugin directory exists
        for plugin_file in self.plugin_dir.glob("*.py"):  # Iterate over Python files in plugin dir
            try:
                # Dynamically import the plugin module
                spec = importlib.util.spec_from_file_location(plugin_file.stem, plugin_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                if hasattr(module, "collect_data"):
                    # Call the plugin's collect_data function if it exists
                    plugin_data[plugin_file.stem] = module.collect_data()
                else:
                    logger.warning(f"Plugin '{plugin_file.stem}' does not have a 'collect_data' function.")
            except Exception as e:
                # Log errors but continue loading other plugins
                logger.error(f"Failed to load plugin '{plugin_file.stem}': {str(e)}")
        return plugin_data

    def redact_text(self, text: str, level: str, command: str, custom_patterns: List[str]) -> str:
        """Redact sensitive information from command output based on censorship level and custom patterns."""
        # If censorship is 'none' or if 'necessary' but command is 'neofetch', skip redaction
        if level == "none" or (level == "necessary" and command == "neofetch"):
            return text
        # For 'necessary' censorship, apply predefined and custom redaction patterns
        elif level == "necessary":
            # Combine default patterns (MAC, IP, etc.) with user-provided custom patterns
            patterns = list(self.redact_patterns.values()) + custom_patterns
            for pattern in patterns:
                # Replace matches with '[REDACTED]' using regex substitution
                # Use case-insensitive matching for 'Serial' pattern to catch variations
                flags = re.IGNORECASE if "Serial" in pattern else 0
                text = re.sub(pattern, "[REDACTED]", text, flags=flags)
            return text
        # For 'over' censorship, redact the entire output
        elif level == "over":
            return "[FULL OUTPUT REDACTED]"
        # Fallback: return original text if censorship level is invalid
        return text

    def clean_output(self, text: str) -> str:
        """Clean command output by removing ANSI codes and extra whitespace."""
        text = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', text)  # Remove ANSI escape codes
        return "\n".join(line.rstrip() for line in text.splitlines() if line.strip())  # Trim whitespace

    async def generate_report(self, censorship: str, verbosity: str, custom_commands: List[str], custom_patterns: List[str], performance: bool) -> Dict[str, str]:
        """Generate the system report based on specified options."""
        # Define command sets based on verbosity and censorship levels
        basic_safe = ["uname -r", "lscpu", "free -h", "df -h --total", "uptime", "neofetch"]
        hardware_safe = ["lspci", "lsusb", "dmidecode -t bios", "lsblk -o NAME,SIZE,TYPE,MOUNTPOINT", "sensors"]
        sensitive = ["ip a", "ss -tuln", "dmidecode -t system", "lsof -i", "who", "last -n 10"]
        logs = ["journalctl -b --no-pager | tail -n 100"] if not os.path.exists("/var/log/syslog") else ["tail -n 100 /var/log/syslog"]
        services = ["systemctl list-units --type=service --no-pager | head -n 50"]
        disk_health = ["smartctl -a /dev/sda"] if shutil.which("smartctl") else []
        performance_metrics = ["iostat -d 1 2", "top -bn1 | head -n 20"] if performance and shutil.which("iostat") else []

        # Select commands based on verbosity and censorship
        commands = basic_safe if censorship == "over" else (
            basic_safe + (hardware_safe if verbosity != "summary" else []) + 
            (sensitive + self._get_package_commands() + logs + services + disk_health + performance_metrics if verbosity == "verbose" else [])
        )
        commands.extend(custom_commands)  # Add user-specified commands

        report_data = {}
        tasks = [self.run_command(cmd) for cmd in commands]  # Create async tasks for all commands
        results = await asyncio.gather(*tasks)  # Run commands concurrently

        # Process results and apply redaction
        for cmd, result in zip(commands, results):
            cleaned = self.clean_output(result)
            redacted = self.redact_text(cleaned, censorship, cmd, custom_patterns)
            report_data[cmd] = redacted
            logger.debug(f"Processed command: {cmd}")

        report_data["plugins"] = self._load_plugins()  # Add plugin data
        return report_data

    def save_report(self, report_data: Dict[str, str], censorship: str, verbosity: str) -> str:
        """Save the report in the specified format after ensuring the output directory is writable."""
        now = datetime.datetime.now()
        time_str = now.strftime('%H-%M-%S')
        date_str = now.strftime('%Y-%m-%d')
        suffix = f"{censorship}_{verbosity}"
        file_name = f"system_report_{date_str}_{time_str}_{suffix}"
        file_path = self.output_dir / (file_name + (".json" if self.format_type == "json" else ".html" if self.format_type == "html" else ".txt"))

        # Ensure the output directory exists
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)  # Create directory if it doesn't exist
        except PermissionError:
            raise ReportGenerationError(f"Cannot create output directory '{self.output_dir}': Permission denied.")

        # Check if the directory is writable
        if not os.access(self.output_dir, os.W_OK):
            raise ReportGenerationError(f"Output directory '{self.output_dir}' is not writable. Please check permissions or specify a different path.")

        # Generate report content based on format
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

        # Write the report to file
        with file_path.open("w") as f:
            f.write(content)

        # Compress the report if requested
        if self.compress:
            zip_path = self.output_dir / f"{file_name}.zip"
            if self.zip_password:
                compress(str(file_path), None, str(zip_path), self.zip_password, 5)  # Level 5 compression
            else:
                with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.write(file_path, file_path.name)
            file_path.unlink()  # Remove the original file after compression
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
    """Manages scheduling of report generation using systemd or cron."""

    @staticmethod
    def schedule_task(script_path: str, output_dir: str, boot: bool, interval: Optional[int], args: List[str]) -> None:
        """Schedule the script to run at boot or at specified intervals."""
        if os.path.exists("/run/systemd/system"):
            service_name = "system_report.service"
            service_content = f"""
[Unit]
Description=System Report Generation
After=network.target

[Service]
Type=oneshot
ExecStart={script_path} -o {output_dir} {' '.join(args)}

[Install]
WantedBy=multi-user.target
"""
            with open(f"/etc/systemd/system/{service_name}", "w") as f:
                f.write(service_content)
            if boot:
                subprocess.run(["systemctl", "enable", service_name], check=True)
            if interval:
                timer_name = "system_report.timer"
                timer_content = f"""
[Unit]
Description=Timer for System Report

[Timer]
OnBootSec=0
OnUnitActiveSec={interval}h
Unit={service_name}

[Install]
WantedBy=timers.target
"""
                with open(f"/etc/systemd/system/{timer_name}", "w") as f:
                    f.write(timer_content)
                subprocess.run(["systemctl", "enable", timer_name], check=True)
                subprocess.run(["systemctl", "start", timer_name], check=True)
            logger.info(f"Scheduled report generation: boot={boot}, interval={interval}h")
        else:
            logger.warning("Systemd not detected. Using cron.")
            cron_cmd = f"{script_path} -o {output_dir} {' '.join(args)}"
            cron_line = f"0 */{interval} * * * {cron_cmd}" if interval else f"@reboot {cron_cmd}"
            subprocess.run(f"(crontab -l 2>/dev/null; echo '{cron_line}') | crontab -", shell=True)

def interactive_mode() -> Tuple[str, str, str, bool, List[str], List[str], bool, Optional[str]]:
    """Interactive CLI mode for configuring the report generation."""
    print("Welcome to System Report Generator v2.1 Interactive Mode!")
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

async def main():
    parser = argparse.ArgumentParser(description="System Report Generator v2.1 - Advanced system information tool.")
    parser.add_argument("-o", "--output", help="Output directory for the report")
    parser.add_argument("-u", "--uncensored", action="store_true", help="No redaction")
    parser.add_argument("-c", "--censored", action="store_true", help="Fully censored output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Detailed output")
    parser.add_argument("-b", "--brief", action="store_true", help="Brief output")
    parser.add_argument("--format", choices=["text", "json", "html"], default="text", help="Output format (text/json/html)")
    parser.add_argument("--compress", action="store_true", help="Compress report into a .zip file")
    parser.add_argument("--zip-password", help="Password for ZIP compression")
    parser.add_argument("--schedule", nargs="*", help="Schedule: --schedule [boot] [interval_hours]")
    parser.add_argument("--custom-commands", help="Comma-separated custom commands to run")
    parser.add_argument("--redact-patterns", help="Comma-separated custom redaction patterns (regex)")
    parser.add_argument("--performance", action="store_true", help="Include performance metrics")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    args = parser.parse_args()

    # Load defaults from config
    config = ReportGenerator(args.output or "").config["DEFAULT"]

    # Determine settings from args or config
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

    # Handle scheduling if requested
    if args.schedule:
        if os.geteuid() != 0:
            logger.error("Scheduling requires root privileges.")
            sys.exit(1)
        boot = "boot" in args.schedule
        interval = int(args.schedule[1]) if len(args.schedule) > 1 and args.schedule[1].isdigit() else None
        script_args = [f"--{censorship}", f"--{verbosity}", "--format", args.format or config.get("format", "text")]
        if compress: script_args.append("--compress")
        if zip_password: script_args.append(f"--zip-password {zip_password}")
        if custom_commands: script_args.append(f"--custom-commands {','.join(custom_commands)}")
        if custom_patterns: script_args.append(f"--redact-patterns {','.join(custom_patterns)}")
        if performance: script_args.append("--performance")
        Scheduler.schedule_task(os.path.abspath(__file__), output_dir, boot, interval, script_args)
        return

    # Generate and save the report
    generator = ReportGenerator(output_dir, args.format or config.get("format", "text"), compress, zip_password)
    logger.info("Generating report...")
    report_data = await generator.generate_report(censorship, verbosity, custom_commands, custom_patterns, performance)
    file_path = generator.save_report(report_data, censorship, verbosity)
    logger.info(f"Report saved to: {file_path}")

if __name__ == "__main__":
    asyncio.run(main())