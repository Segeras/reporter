```markdown
# reporter v0.2.3-beta - Comprehensive System Reporting Tool

**reporter** is a powerful, customizable command-line utility designed to generate detailed system reports on Linux environments. Tailored for system administrators, support technicians, and security professionals, it streamlines the collection, redaction, and presentation of system information. With support for multiple output formats, redaction levels, plugins, and scheduling, **reporter** adapts to diverse use cases, from troubleshooting to auditing.

## Overview

**reporter** is a Python-based tool that simplifies gathering and presenting system data on Linux systems. It collects information from built-in commands (e.g., `uname`, `lsblk`, `df`), optional tools (e.g., `neofetch`, `smartmontools`), and custom plugins or commands. Users can adjust detail levels, redact sensitive data, and export reports in text, JSON, or HTML formats, with optional ZIP compression and password protection.

Ideal for:
- Quick system snapshots for troubleshooting.
- Automated routine system checks.
- Detailed audits with privacy controls.
- Extensible functionality via plugins.

## Key Features

- **Flexible Output**: Export reports as plain text, JSON, or HTML.
- **Redaction Control**: Options include none, necessary, or over redaction levels.
- **Detail Levels**: Choose summary, default, or verbose verbosity.
- **Compression**: Save reports as ZIP files, optionally password-protected.
- **Extensibility**: Add custom Python plugins for specialized data collection.
- **Custom Commands**: Integrate output from user-specified commands.
- **Redaction Patterns**: Apply regex patterns for targeted data masking.
- **Performance Metrics**: Include system performance data (e.g., from `iostat`, `top`).
- **Scheduling**: Automate reports using `systemd` or `cron`.

## Installation

### Prerequisites

Ensure your system meets these requirements:
- **Operating System**: Any Linux distribution (tested on Ubuntu, Debian, Fedora, Arch, openSUSE).
- **Python**: Version 3.6 or higher.
- **Git**: Required to clone the repository.
- **System Dependencies**:
  - Core: `python3`, `python3-pip`, `git`, `python3-dev`, `zlib1g-dev`.
  - Optional: `neofetch`, `smartmontools`, `sysstat`, `lsof`, `pciutils`, `usbutils`, `lm-sensors`, `flatpak`, `snapd`.
- **Python Package**: `pyminizip` for password-protected ZIP files.

### Step-by-Step Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Segeras/reporter.git
   cd reporter
   ```

2. Run the installation script:
   ```bash
   chmod +x install_reporter.py
   ./install_reporter.py
   ```
   The script:
   - Detects your distribution and uses the appropriate package manager (`apt`, `dnf`, `pacman`, etc.).
   - Installs required dependencies.
   - Installs `pyminizip`.
   - Copies the application to `~/reporter` (customizable).
   - Creates a configuration directory at `~/.reporter`.
   - Adds a symlink to `/usr/local/bin/reporter`.

   Optional flags:
   - `--install-dir /path/to/install`: Specify a custom install directory.
   - `--no-symlink`: Skip symlink creation.

3. Verify installation:
   ```bash
   reporter --help
   ```
   If unsuccessful, run directly:
   ```bash
   ~/reporter/reporter_2.3.py --help
   ```

### Troubleshooting Installation

- Dependency issues:
   ```bash
   sudo apt install python3 git neofetch  # Debian/Ubuntu
   sudo pacman -S python git neofetch    # Arch
   sudo dnf install python3 git neofetch # Fedora
   ```
- `pyminizip` errors:
   ```bash
   python3 -m pip install pyminizip
   sudo apt install python3-dev zlib1g-dev  # Debian/Ubuntu
   ```
- Permission denied:
   ```bash
   sudo ./install_reporter.py
   ```

## Functionality

### Report Generation

**reporter** collects data from:
- Hardware (e.g., CPU, memory, disks).
- Software (e.g., OS version, packages).
- Network (e.g., IP addresses, interfaces).
- Optional tools (e.g., `neofetch`, `smartmontools`).

### Redaction Options

Three levels of redaction:
- `none`: Full disclosure.
- `necessary`: Masks common sensitive data (e.g., IPs, MACs).
- `over`: Redacts output from sensitive commands (e.g., `who`, `last`).
- Custom regex patterns for additional control.

### Output Formats

- **Text**: Plain and script-friendly.
- **JSON**: Structured for programmatic use.
- **HTML**: Styled for easy sharing.

### Customization Features

- **Verbosity**: Summary, default, or verbose.
- **Compression**: ZIP output with optional encryption.
- **Plugins**: Extend with Python scripts.
- **Custom Commands**: Include specific command outputs.

## How to Use reporter

### Basic Usage

Generate a default report:
```bash
reporter
```
Output: Text file in `~/reports` with necessary redaction.

### Command-Line Options

Customize with:
- `-o, --output <directory>`: Set output directory.
- `-u, --uncensored`: No redaction.
- `-c, --censored`: Maximum redaction.
- `-v, --verbose`: Full details.
- `-b, --brief`: Summary only.
- `--format <text|json|html>`: Output format.
- `--compress`: ZIP the report.
- `--zip-password <password>`: Encrypt ZIP file.
- `--custom-commands "cmd1,cmd2"`: Add command outputs.
- `--redact-patterns "pattern1,pattern2"`: Custom regex redaction.
- `--performance`: Include performance metrics.
- `--interactive`: Step-by-step mode.
- `--help-menu`: Interactive help.

See `reporter --help` for all options.

### Practical Examples

- Detailed report:
   ```bash
   reporter --verbose --uncensored --output /tmp/reports
   ```
- Secure HTML report:
   ```bash
   reporter --format html --compress --zip-password "secure123"
   ```
- Custom commands:
   ```bash
   reporter --custom-commands "uptime,who" --redact-patterns "user.*"
   ```
- Scheduled report:
   ```bash
   sudo reporter --schedule daily_report boot 24
   ```

## Configuration

### Configuration File

Settings are stored in `~/.reporter.conf`:
```ini
[DEFAULT]
output_dir = ~/reports
censorship = necessary
verbosity = default
format = text
compress = no
zip_password =
```

### Customizing Settings

Edit the file to adjust defaults (e.g., output directory, redaction level).

## Extending with Plugins

### What Are Plugins?

Python scripts in `~/.reporter/plugins/` that extend **reporter**’s data collection.

### Creating a Plugin

Add a file (e.g., `my_plugin.py`):
```python
def collect_data():
    return "This is custom plugin data"
```

### Example Plugin

Capture kernel version:
```python
import subprocess
def collect_data():
    return subprocess.getoutput("uname -r")
```

## Scheduling Reports

### Using systemd

- Schedule:
   ```bash
   sudo reporter --schedule nightly boot 24
   ```
- List schedules:
   ```bash
   sudo reporter --list-schedules
   ```
- Stop a schedule:
   ```bash
   sudo reporter --stop-schedule nightly
   ```
- Stop all:
   ```bash
   sudo reporter --stop-all-schedules
   ```

### Using cron

Fallback for non-systemd systems; configured via the install script.

## Implementation and Integration

- **Automated Monitoring**: Schedule periodic health checks.
- **Custom Data Collection**: Use plugins or commands for tailored reports.
- **Secure Sharing**: Compress and encrypt reports for distribution.
- **CI/CD Integration**: Embed in pipelines for system state logging.

## Troubleshooting

- “command not found”:
   ```bash
   sudo ln -sf ~/reporter/reporter_2.3.py /usr/local/bin/reporter
   ```
- Missing tools:
   Install manually (e.g., `sudo apt install neofetch`).
- ZIP issues:
   Verify `pyminizip` and `zlib1g-dev`.

## Contributing

Contributions are welcome! Fork the repository, submit pull requests, or file issues on GitHub.

## License

**reporter** is licensed under the MIT License. See the `LICENSE` file for details.
