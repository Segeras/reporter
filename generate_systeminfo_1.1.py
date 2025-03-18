#!/usr/bin/env python3

import subprocess
import datetime
import os
import re
import argparse
import shutil
import platform
import sys

def run_command(command):
    """Run a shell command and return its output, handling errors gracefully."""
    cmd_name = command.split()[0]
    if not shutil.which(cmd_name):
        return f"[Command not found: {cmd_name}]"
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.rstrip()
    except subprocess.CalledProcessError as e:
        return f"[Error running {command}: {e.stderr.rstrip()}]"

def redact_text(text, level, command, redact_usernames=False):
    """Redact sensitive information based on the specified level and command."""
    if level == "none":
        return text
    elif level == "redacted":
        text = re.sub(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', '[MAC REDACTED]', text)
        text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP REDACTED]', text)
        text = re.sub(r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}', '[IPv6 REDACTED]', text)
        text = re.sub(r'Serial.*?: .*', 'Serial: [REDACTED]', text, flags=re.IGNORECASE)
        text = re.sub(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '[UUID REDACTED]', text)
        if redact_usernames:
            text = re.sub(r'\b[a-zA-Z0-9]{1,32}\b', 'user', text)
        return text
    elif level == "censored":
        return "[OUTPUT EXCLUDED]"
    return text

def detect_distro():
    """Detect the Linux distribution."""
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("ID="):
                    return line.strip().split("=")[1].strip('"').lower()
    return platform.system().lower() if platform.system() else "unknown"

def get_package_commands(distro):
    """Return package listing commands based on the detected distro."""
    commands = []
    if distro in ["arch", "manjaro", "endeavouros"]:
        commands.append("pacman -Qe")
    elif distro in ["fedora", "centos", "rhel"]:
        commands.append("dnf list --installed")
    elif distro in ["ubuntu", "debian", "linuxmint"]:
        commands.append("dpkg -l")
    elif distro in ["opensuse", "opensuse-tumbleweed"]:
        commands.append("zypper se -i")
    else:
        commands.append("echo 'Package manager not recognized'")
    if shutil.which("flatpak"):
        commands.append("flatpak list")
    if shutil.which("snap"):
        commands.append("snap list")
    return commands

def format_section_header(command):
    """Create a visually appealing section header."""
    return f"\n{'-' * 20} {command.upper()} {'-' * 20}\n"

def clean_output(text):
    """Clean up command output by removing ANSI codes and extra whitespace."""
    text = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', text)
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    return "\n".join(lines)

def schedule_on_boot(script_path, output_dir):
    """Schedule the script to run at boot using systemd."""
    service_content = f"""
[Unit]
Description=Generate system report on boot
After=network.target

[Service]
Type=oneshot
ExecStart={script_path} -o {output_dir}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
    service_path = "/etc/systemd/system/system_report_boot.service"
    with open(service_path, "w") as f:
        f.write(service_content)
    subprocess.run(["systemctl", "enable", "system_report_boot.service"], check=True)
    print("Scheduled to generate report at boot.")

def schedule_periodic(script_path, output_dir, interval_hours):
    """Schedule the script to run periodically using systemd timer."""
    service_content = f"""
[Unit]
Description=Generate system report periodically

[Service]
Type=oneshot
ExecStart={script_path} -o {output_dir}
"""
    timer_content = f"""
[Unit]
Description=Run system report every {interval_hours} hours

[Timer]
OnBootSec=0
OnUnitActiveSec={interval_hours}h
Unit=system_report_periodic.service

[Install]
WantedBy=timers.target
"""
    service_path = "/etc/systemd/system/system_report_periodic.service"
    timer_path = "/etc/systemd/system/system_report_periodic.timer"
    with open(service_path, "w") as f:
        f.write(service_content)
    with open(timer_path, "w") as f:
        f.write(timer_content)
    subprocess.run(["systemctl", "enable", "system_report_periodic.timer"], check=True)
    subprocess.run(["systemctl", "start", "system_report_periodic.timer"], check=True)
    print(f"Scheduled to generate report every {interval_hours} hours.")

def stop_scheduling():
    """Stop and disable all scheduled report generation."""
    boot_service = "/etc/systemd/system/system_report_boot.service"
    periodic_service = "/etc/systemd/system/system_report_periodic.service"
    periodic_timer = "/etc/systemd/system/system_report_periodic.timer"
    stopped_any = False

    if os.path.exists(boot_service):
        try:
            subprocess.run(["systemctl", "disable", "system_report_boot.service"], check=True)
            subprocess.run(["systemctl", "stop", "system_report_boot.service"], check=True)
            os.remove(boot_service)
            print("Stopped and removed boot-time report generation.")
            stopped_any = True
        except subprocess.CalledProcessError as e:
            print(f"Error stopping boot schedule: {e}")

    if os.path.exists(periodic_timer):
        try:
            subprocess.run(["systemctl", "disable", "system_report_periodic.timer"], check=True)
            subprocess.run(["systemctl", "stop", "system_report_periodic.timer"], check=True)
            os.remove(periodic_timer)
            if os.path.exists(periodic_service):
                os.remove(periodic_service)
            print("Stopped and removed periodic report generation.")
            stopped_any = True
        except subprocess.CalledProcessError as e:
            print(f"Error stopping periodic schedule: {e}")

    if not stopped_any:
        print("No scheduled report generation found to stop.")

def main():
    parser = argparse.ArgumentParser(description="Generate a system information report.")
    parser.add_argument("-o", "--output", help="Directory to save the report (required except with --help)")
    parser.add_argument("-u", "--uncensored", action="store_true", help="Uncensored verbose mode: show everything including logs without redaction")
    parser.add_argument("-r", "--redacted-verbose", action="store_true", help="Redacted verbose mode: redact sensitive data, show logs, use real usernames")
    parser.add_argument("-v", "--verbose", action="store_true", help="Redacted verbose mode: redact sensitive data, show logs, use 'user'")
    parser.add_argument("-c", "--censored", action="store_true", help="Censored brief mode: no logs, exclude sensitive info, use 'user'")
    parser.add_argument("--schedule", nargs='*', help="Schedule report generation: --schedule [boot] [interval_hours] or --schedule stop")
    parser.add_argument("--help", action="store_true", help="Display detailed help information")
    args = parser.parse_args()

    if args.help:
        print("""
SYSTEM REPORT GENERATOR
=======================
This script generates a system information report with configurable modes.

**Modes:**
- **-u, --uncensored**: Uncensored verbose mode (no redaction, includes logs).
- **-r, --redacted-verbose**: Redacted verbose mode (redacts sensitive data, includes logs, real usernames).
- **-v, --verbose**: Redacted verbose mode (redacts sensitive data, includes logs, uses 'user').
- **-c, --censored**: Censored brief mode (no logs, excludes sensitive info, uses 'user').
- **No flag**: Default mode (redacted, no logs, uses 'user').

**Scheduling (systemd-based systems only):**
- **--schedule boot**: Generate report at system boot.
- **--schedule <interval_hours>**: Generate report every <interval_hours> hours.
- **--schedule boot <interval_hours>**: Generate report at boot and every <interval_hours> hours.
- **--schedule stop**: Stop and remove all scheduled report generation.
- For non-systemd systems, manual configuration is required (e.g., via /etc/rc.local or cron).

**Usage:**
- Specify output directory with `-o` (required except with --help).
- Example: `./script.py -o /path/to/dir -v` for verbose redacted report.
- Example: `./script.py -o /path/to/dir --schedule boot 2` to schedule at boot and every 2 hours.
- Example: `./script.py --schedule stop` to stop all scheduling.
""")
        sys.exit(0)

    if args.schedule:
        if os.geteuid() != 0:
            print("Error: Please run as root (e.g., with sudo) to manage scheduling.")
            sys.exit(1)
        script_path = os.path.abspath(__file__)
        schedule_args = args.schedule

        if "stop" in schedule_args:
            if len(schedule_args) > 1:
                print("Error: '--schedule stop' does not accept additional arguments.")
                sys.exit(1)
            stop_scheduling()
            sys.exit(0)

        if not args.output:
            parser.error("Output directory is required for scheduling")

        if not os.path.exists('/run/systemd/system'):
            print("Systemd not detected. Automatic scheduling is not supported.")
            print("To run the script on boot manually, add the following to /etc/rc.local or your init system's boot process:")
            print(f"    {script_path} -o {args.output}")
            print("For periodic scheduling, use cron or another scheduler.")
            sys.exit(1)

        # Parse scheduling arguments
        at_boot = False
        interval = None
        if "boot" in schedule_args:
            at_boot = True
            schedule_args.remove("boot")
        if schedule_args:
            try:
                interval = int(schedule_args[0])
                if interval <= 0:
                    raise ValueError
            except (ValueError, IndexError):
                print("Error: Interval must be a positive integer.")
                sys.exit(1)

        # Apply scheduling
        if at_boot and interval is None:
            schedule_on_boot(script_path, args.output)
        elif interval is not None and not at_boot:
            schedule_periodic(script_path, args.output, interval)
        elif at_boot and interval is not None:
            schedule_on_boot(script_path, args.output)
            schedule_periodic(script_path, args.output, interval)
        else:
            print("Error: Invalid scheduling arguments. Use --help for usage.")
            sys.exit(1)
        sys.exit(0)

    if not args.output:
        parser.error("Output directory is required for report generation")

    # Mode selection logic
    if sum([args.uncensored, args.redacted_verbose, args.verbose, args.censored]) > 1:
        parser.error("Only one of -u, -r, -v, -c can be used at a time.")
    if args.uncensored:
        censorship = "none"
        verbosity = "verbose"
        redact_usernames = False
    elif args.redacted_verbose:
        censorship = "redacted"
        verbosity = "verbose"
        redact_usernames = False
    elif args.verbose:
        censorship = "redacted"
        verbosity = "verbose"
        redact_usernames = True
    elif args.censored:
        censorship = "censored"
        verbosity = "summary"
        redact_usernames = True
    else:
        censorship = "redacted"
        verbosity = "default"
        redact_usernames = True

    # Generate report filename
    now = datetime.datetime.now()
    time_str = now.strftime('%H:%M:%S')
    date_str = now.strftime('%Y-%m-%d')
    mode_suffix = {
        "none": "_uncensored_verbose",
        "redacted": "_redacted_verbose" if verbosity == "verbose" else "_redacted_default",
        "censored": "_censored_brief"
    }[censorship]
    file_name = f"system_report_{date_str}_{time_str}{mode_suffix}.txt"
    file_path = os.path.join(args.output, file_name)

    # Detect distribution and gather commands
    distro = detect_distro()
    basic_safe = ["uname -r", "lscpu", "free -h", "df -h --total", "uptime", "neofetch"]
    hardware_safe = ["lspci", "lsusb", "dmidecode -t bios", "lsblk -o NAME,SIZE,TYPE,MOUNTPOINT", "sensors"]
    sensitive = ["ip a", "ss -tuln", "dmidecode -t system", "lsof -i", 
                 "journalctl -b --no-pager | tail -n 50" if shutil.which("journalctl") else "tail -n 50 /var/log/syslog || tail -n 50 /var/log/messages", 
                 "ps aux --sort=-%mem | head -n 20", "who", "last -n 10"]
    if verbosity == "summary":
        commands = basic_safe
    elif verbosity == "default":
        commands = basic_safe + hardware_safe
    else:
        commands = basic_safe + hardware_safe + sensitive
        commands.extend(get_package_commands(distro))
    redact_level = censorship

    # Generate report
    display_mode = {
        "none": "Uncensored Verbose",
        "redacted": "Redacted Verbose" if verbosity == "verbose" else "Redacted Default",
        "censored": "Censored Brief"
    }[censorship]
    output = f"""SYSTEM INFORMATION REPORT
Generated: {now.strftime('%Y-%m-%d %H:%M:%S')}
Distribution: {distro.capitalize()}
Mode: {display_mode}

This report provides a system overview based on the selected mode.
"""
    for cmd in commands:
        raw_output = run_command(cmd)
        cleaned_output = clean_output(raw_output)
        redacted_output = redact_text(cleaned_output, redact_level, cmd, redact_usernames=redact_usernames)
        output += format_section_header(cmd)
        output += redacted_output + "\n"

    # Save report
    os.makedirs(args.output, exist_ok=True)
    with open(file_path, "w") as f:
        f.write(output)
    print(f"Report saved to: {file_path} (Mode: {display_mode})")

if __name__ == "__main__":
    main()