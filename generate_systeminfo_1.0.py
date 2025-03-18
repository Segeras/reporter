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

def redact_text(text, level, command):
    """Redact sensitive information based on the specified level and command."""
    if level == "none" or (level == "necessary" and command == "neofetch"):
        return text
    elif level == "necessary":
        text = re.sub(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', '[MAC REDACTED]', text)
        text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP REDACTED]', text)
        text = re.sub(r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}', '[IPv6 REDACTED]', text)
        text = re.sub(r'Serial.*?: .*', 'Serial: [REDACTED]', text, flags=re.IGNORECASE)
        text = re.sub(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '[UUID REDACTED]', text)
        return text
    elif level == "over":
        return "[FULL OUTPUT REDACTED]"
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
        if shutil.which("yay"):
            commands.append("yay -Qe")
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
    """Clean up command output."""
    text = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', text)
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    return "\n".join(lines)

def install_dependencies(distro, output_dir):
    """Install or update dependencies based on the distribution, using the output directory."""
    dependencies = {
        "arch": ["neofetch", "inxi", "lm_sensors", "smartmontools", "wireless_tools", "lsof"],
        "ubuntu": ["neofetch", "inxi", "lm-sensors", "smartmontools", "wireless-tools", "lsof"],
        "fedora": ["neofetch", "inxi", "lm_sensors", "smartmontools", "wireless_tools", "lsof"],
        "opensuse": ["neofetch", "inxi", "lm_sensors", "smartmontools", "wireless_tools", "lsof"]
    }
    if distro in dependencies:
        print(f"Installing dependencies for {distro} in {output_dir}...")
        if distro == "arch":
            subprocess.run(["sudo", "pacman", "-S", "--noconfirm"] + dependencies[distro])
        elif distro == "ubuntu":
            subprocess.run(["sudo", "apt", "install", "-y"] + dependencies[distro])
        elif distro == "fedora":
            subprocess.run(["sudo", "dnf", "install", "-y"] + dependencies[distro])
        elif distro == "opensuse":
            subprocess.run(["sudo", "zypper", "install", "-y"] + dependencies[distro])
    else:
        print("Unsupported distribution for automatic dependency installation.")

def main():
    # Argument parser setup
    parser = argparse.ArgumentParser(description="Generate a system information report.")
    parser.add_argument("-o", "--output", help="Directory to save the report or for dependency updates (required except with --help-me)")
    parser.add_argument("-u", "--uncensored", action="store_true", help="Uncensored mode")
    parser.add_argument("-c", "--censored", action="store_true", help="Censored brief mode")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    parser.add_argument("-b", "--brief", action="store_true", help="Brief mode")
    parser.add_argument("--update", action="store_true", help="Install or update dependencies (requires output directory)")
    parser.add_argument("--help-me", action="store_true", help="Display detailed help information")
    args = parser.parse_args()

    # Handle help command (does not require output directory)
    if args.help_me:
        print("""
SYSTEM REPORT GENERATOR
=======================
This script generates a detailed system information report with configurable censorship and verbosity levels.

**Features:**
- **Censorship Levels**: Uncensored (no redaction), Redacted (sensitive data hidden), Censored (minimal output)
- **Verbosity Levels**: Brief (basic info), Default (standard info), Verbose (detailed info)
- Cross-platform compatibility for major Linux distributions
- Automatic dependency installation or update

**Usage:**
- **Required except with --help-me**: Specify the output directory with `-o` or `--output` for report generation or updates
- Combine flags: `-uv` (uncensored verbose), `-u` (uncensored default), `-ub` (uncensored brief), `-v` (redacted verbose), no flag (redacted default), `-b` (redacted brief), `-c` (censored brief)
- Use `--update` to install or update dependencies (requires output directory)
- Use `--help-me` for this help message (no output directory needed)

**Examples:**
- `./script.py -o /path/to/dir` : Redacted default report
- `./script.py -o /path/to/dir -v` : Redacted verbose report
- `./script.py -o /path/to/dir -b` : Redacted brief report
- `./script.py -o /path/to/dir -u` : Uncensored default report
- `./script.py -o /path/to/dir -uv` : Uncensored verbose report
- `./script.py -o /path/to/dir -ub` : Uncensored brief report
- `./script.py -o /path/to/dir -c` : Censored brief report
- `./script.py -o /path/to/dir --update` : Install/update dependencies
""")
        sys.exit(0)

    # Check if output directory is provided for update or report generation
    if not args.output and (args.update or not args.help_me):
        parser.error("Output directory is required for report generation or dependency updates")

    # Handle update command
    if args.update:
        distro = detect_distro()
        install_dependencies(distro, args.output)
        sys.exit(0)

    # Validate flag combinations for report generation
    valid_combinations = {
        (False, False, False, False),  # No flag: redacted default
        (False, False, True, False),   # -v: redacted verbose
        (False, False, False, True),   # -b: redacted brief
        (True, False, False, False),   # -u: uncensored default
        (True, False, True, False),    # -uv: uncensored verbose
        (True, False, False, True),    # -ub: uncensored brief
        (False, True, False, False)    # -c: censored brief
    }
    current_combination = (args.uncensored, args.censored, args.verbose, args.brief)
    if current_combination not in valid_combinations:
        parser.error("Invalid flag combination. Use --help-me for usage information.")

    # Determine censorship and verbosity
    if args.censored:
        censorship = "over"
        verbosity = "summary"
    else:
        if args.uncensored:
            censorship = "none"
        else:
            censorship = "necessary"
        if args.verbose:
            verbosity = "verbose"
        elif args.brief:
            verbosity = "summary"
        else:
            verbosity = "default"

    # Generate filename with ":" in time
    now = datetime.datetime.now()
    time_str = now.strftime('%H:%M:%S')
    date_str = now.strftime('%Y-%m-%d')
    censorship_suffix = {"none": "_uncensored", "necessary": "_redacted", "over": "_censored"}[censorship]
    verbosity_suffix = {"summary": "_brief", "verbose": "_verbose", "default": ""}[verbosity]
    file_name = f"system_report_{date_str}_{time_str}{censorship_suffix}{verbosity_suffix}.txt"
    file_path = os.path.join(args.output, file_name)

    # Detect distribution
    distro = detect_distro()

    # Define command lists
    basic_safe = ["uname -r", "lscpu", "free -h", "df -h --total", "uptime", "neofetch"]
    hardware_safe = ["lspci", "lsusb", "dmidecode -t bios", "lsblk -o NAME,SIZE,TYPE,MOUNTPOINT", "sensors"]
    sensitive = ["ip a", "ss -tuln", "dmidecode -t system", "lsof -i", "journalctl -b --no-pager | tail -n 50", "ps aux --sort=-%mem | head -n 20", "who", "last -n 10"]

    # Select commands based on censorship and verbosity
    if censorship == "over":
        commands = basic_safe  # Censored brief
    else:
        if verbosity == "summary":
            commands = basic_safe
        elif verbosity == "default":
            commands = basic_safe + hardware_safe
        else:  # verbose
            commands = basic_safe + hardware_safe + sensitive
        if verbosity in ["default", "verbose"]:
            commands.extend(get_package_commands(distro))

    # Set redaction level
    redact_level = "none" if censorship == "over" else censorship

    # Generate report
    display_censorship = {"none": "Uncensored", "necessary": "Redacted", "over": "Censored"}[censorship]
    display_verbosity = {"summary": "Brief", "default": "Default", "verbose": "Verbose"}[verbosity]
    output = f"""SYSTEM INFORMATION REPORT
Generated: {now.strftime('%Y-%m-%d %H:%M:%S')}
Distribution: {distro.capitalize()}
Censorship Level: {display_censorship}
Verbosity Level: {display_verbosity}

This report provides a system overview. Sensitive data may be redacted or excluded based on settings.
"""

    for cmd in commands:
        raw_output = run_command(cmd)
        cleaned_output = clean_output(raw_output)
        redacted_output = redact_text(cleaned_output, redact_level, cmd)
        output += format_section_header(cmd)
        output += redacted_output + "\n"

    # Ensure output directory exists
    os.makedirs(args.output, exist_ok=True)

    # Write to file
    with open(file_path, "w") as f:
        f.write(output)

    print(f"Report saved to: {file_path} (Censorship: {display_censorship}, Verbosity: {display_verbosity})")

if __name__ == "__main__":
    main()