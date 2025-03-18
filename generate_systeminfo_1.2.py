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
    """Run a shell command and return its output."""
    cmd_name = command.split()[0]
    if not shutil.which(cmd_name):
        return f"[Command not found: {cmd_name}]"
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.rstrip()
    except subprocess.CalledProcessError as e:
        return f"[Error running {command}: {e.stderr.rstrip()}]"

def redact_text(text, level, command, redact_usernames=False):
    """Redact sensitive information based on the specified level."""
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
    """Return package listing commands based on the distro."""
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
    """Create a section header."""
    return f"\n{'-' * 20} {command.upper()} {'-' * 20}\n"

def clean_output(text):
    """Clean up command output."""
    text = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', text)
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    return "\n".join(lines)

def parse_schedule_args(args):
    """Parse schedule arguments."""
    if not args:
        print("Error: --schedule requires at least '-boot' or an interval.")
        sys.exit(1)
    boot = "-boot" in args
    if boot:
        args.remove("-boot")
    interval = None
    for arg in args[:]:
        if arg.isdigit():
            interval = int(arg)
            args.remove(arg)
            break
    mode_flag = None
    if args and args[0].startswith("-"):
        mode_flag = args[0]
        if mode_flag not in ["-u", "-r", "-v", "-c"]:
            print("Error: Invalid mode flag. Must be one of -u, -r, -v, -c.")
            sys.exit(1)
    if not boot and interval is None:
        print("Error: Must specify at least '-boot' or an interval.")
        sys.exit(1)
    return boot, interval, mode_flag

def schedule_instance(instance_id, output_dir, boot, interval, mode_flag):
    """Schedule a specific instance."""
    service_name = f"system_report_instance_{instance_id}.service"
    service_path = f"/etc/systemd/system/{service_name}"
    exec_start = f"systemreport -o {output_dir}"
    if mode_flag:
        exec_start += f" {mode_flag}"
    service_content = f"""
[Unit]
Description=System Report Generation Instance {instance_id}
After=network.target

[Service]
Type=oneshot
ExecStart={exec_start}

[Install]
WantedBy=multi-user.target
"""
    with open(service_path, "w") as f:
        f.write(service_content)
    if boot:
        subprocess.run(["systemctl", "enable", service_name], check=True)
    if interval:
        timer_name = f"system_report_instance_{instance_id}.timer"
        timer_path = f"/etc/systemd/system/{timer_name}"
        timer_content = f"""
[Unit]
Description=Timer for System Report Generation Instance {instance_id}

[Timer]
OnUnitActiveSec={interval}h
Unit={service_name}

[Install]
WantedBy=timers.target
"""
        with open(timer_path, "w") as f:
            f.write(timer_content)
        subprocess.run(["systemctl", "enable", timer_name], check=True)
        subprocess.run(["systemctl", "start", timer_name], check=True)
    print(f"Scheduled instance {instance_id} with output to {output_dir}")
    if boot:
        print("- At boot")
    if interval:
        print(f"- Every {interval} hours")
    if mode_flag:
        print(f"- Mode: {mode_flag}")

def stop_instance(instance_id):
    """Stop a specific instance."""
    service_name = f"system_report_instance_{instance_id}.service"
    timer_name = f"system_report_instance_{instance_id}.timer"
    service_path = f"/etc/systemd/system/{service_name}"
    timer_path = f"/etc/systemd/system/{timer_name}"
    stopped = False
    if os.path.exists(service_path):
        try:
            subprocess.run(["systemctl", "disable", service_name], check=True)
            subprocess.run(["systemctl", "stop", service_name], check=True)
            os.remove(service_path)
            stopped = True
        except subprocess.CalledProcessError as e:
            print(f"Error stopping service for instance {instance_id}: {e}")
    if os.path.exists(timer_path):
        try:
            subprocess.run(["systemctl", "disable", timer_name], check=True)
            subprocess.run(["systemctl", "stop", timer_name], check=True)
            os.remove(timer_path)
            stopped = True
        except subprocess.CalledProcessError as e:
            print(f"Error stopping timer for instance {instance_id}: {e}")
    if stopped:
        print(f"Stopped instance {instance_id}")
    else:
        print(f"No schedule found for instance {instance_id}")

def stop_all_schedules():
    """Stop all scheduled instances."""
    for instance_id in range(4):
        stop_instance(instance_id)
    print("All scheduled report generations have been stopped.")

def main():
    parser = argparse.ArgumentParser(
        description="Generate a system information report.\n"
                    "Supports manual report generation and up to 4 scheduled instances.\n"
                    "Run as root (e.g., with sudo) for scheduling operations.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-o", "--output", help="Directory to save the report (required for manual generation and scheduling)")
    parser.add_argument("-u", "--uncensored", action="store_true", help="Uncensored verbose mode: no redaction, includes logs")
    parser.add_argument("-v", "--verbose", action="store_true", help="Redacted verbose mode: redacts sensitive data, includes logs, uses real usernames")
    parser.add_argument("-r", "--redacted-verbose", action="store_true", help="Redacted verbose mode: redacts sensitive data, includes logs, uses 'user' instead of usernames")
    parser.add_argument("-c", "--censored", action="store_true", help="Censored brief mode: no logs, excludes sensitive info, uses 'user'")
    parser.add_argument("--schedule", nargs="*", help="Manage instance 0:\n"
                                                     "- Schedule: --schedule [-boot] [<interval_hours>] [-u|-v|-r|-c]\n"
                                                     "- Stop: --schedule -stop\n"
                                                     "- Stop all: --schedule -stopall")
    parser.add_argument("--schedule1", nargs="*", help="Manage instance 1:\n"
                                                      "- Schedule: --schedule1 [-boot] [<interval_hours>] [-u|-v|-r|-c]\n"
                                                      "- Stop: --schedule1 -stop")
    parser.add_argument("--schedule2", nargs="*", help="Manage instance 2:\n"
                                                      "- Schedule: --schedule2 [-boot] [<interval_hours>] [-u|-v|-r|-c]\n"
                                                      "- Stop: --schedule2 -stop")
    parser.add_argument("--schedule3", nargs="*", help="Manage instance 3:\n"
                                                      "- Schedule: --schedule3 [-boot] [<interval_hours>] [-u|-v|-r|-c]\n"
                                                      "- Stop: --schedule3 -stop")
    args = parser.parse_args()

    # Handle scheduling
    if args.schedule or args.schedule1 or args.schedule2 or args.schedule3:
        if os.geteuid() != 0:
            print("Error: Please run as root (e.g., with sudo) to manage scheduling.")
            sys.exit(1)
        instances = {
            "schedule": 0,
            "schedule1": 1,
            "schedule2": 2,
            "schedule3": 3
        }
        for flag, instance_id in instances.items():
            schedule_args = getattr(args, flag)
            if schedule_args:
                if schedule_args == ["-stop"]:
                    stop_instance(instance_id)
                    sys.exit(0)
                elif schedule_args == ["-stopall"] and flag == "schedule":
                    stop_all_schedules()
                    sys.exit(0)
                else:
                    if not args.output:
                        print("Error: --schedule requires -o <output_dir>")
                        sys.exit(1)
                    boot, interval, mode_flag = parse_schedule_args(schedule_args)
                    schedule_instance(instance_id, args.output, boot, interval, mode_flag)
                    sys.exit(0)

    # Manual report generation
    if not args.output:
        parser.error("Output directory is required for report generation")

    # Mode selection
    modes = sum([args.uncensored, args.redacted_verbose, args.verbose, args.censored])
    if modes > 1:
        parser.error("Only one of -u, -v, -r, -c can be used at a time.")
    if args.uncensored:
        censorship, verbosity, redact_usernames = "none", "verbose", False
    elif args.verbose:
        censorship, verbosity, redact_usernames = "redacted", "verbose", False
    elif args.redacted_verbose:
        censorship, verbosity, redact_usernames = "redacted", "verbose", True
    elif args.censored:
        censorship, verbosity, redact_usernames = "censored", "summary", True
    else:
        censorship, verbosity, redact_usernames = "redacted", "default", True

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

    # Gather commands
    distro = detect_distro()
    basic_safe = ["uname -r", "lscpu", "free -h", "df -h --total", "uptime", "neofetch"]
    hardware_safe = ["lspci", "lsusb", "dmidecode -t bios", "lsblk -o NAME,SIZE,TYPE,MOUNTPOINT", "sensors"]
    sensitive = ["ip a", "ss -tuln", "dmidecode -t system", "lsof -i",
                 "journalctl -b --no-pager | tail -n 50" if shutil.which("journalctl") else "tail -n 50 /var/log/syslog || tail -n 50 /var/log/messages",
                 "ps aux --sort=-%mem | head -n 20", "who", "last -n 10"]
    commands = basic_safe + (hardware_safe if verbosity != "summary" else []) + (sensitive + get_package_commands(distro) if verbosity == "verbose" else [])

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
        redacted_output = redact_text(cleaned_output, censorship, cmd, redact_usernames)
        output += format_section_header(cmd) + redacted_output + "\n"

    # Save report
    os.makedirs(args.output, exist_ok=True)
    with open(file_path, "w") as f:
        f.write(output)
    print(f"Report saved to: {file_path} (Mode: {display_mode})")

if __name__ == "__main__":
    main()