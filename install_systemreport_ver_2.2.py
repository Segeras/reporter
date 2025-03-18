#!/usr/bin/env python3

import os
import sys
import subprocess
import shutil
from pathlib import Path
import argparse

# Constants
REPO_URL = "https://github.com/Segeras/systemreport_generator.git"
DEFAULT_INSTALL_DIR = str(Path.home() / "systemreport_generator")
SCRIPT_NAME = "systemreport_generator.py"  # Assuming this is the main script name
BIN_DIR = "/usr/local/bin"
CONFIG_DIR = Path.home() / ".systemreport"

def parse_arguments():
    """Parse command-line arguments for customization."""
    parser = argparse.ArgumentParser(description="Install systemreport_2.2.py from GitHub")
    parser.add_argument(
        "--install-dir",
        default=DEFAULT_INSTALL_DIR,
        help="Directory where the software will be installed (default: ~/systemreport_generator)"
    )
    parser.add_argument(
        "--no-symlink",
        action="store_true",
        help="Skip creating a symlink in /usr/local/bin"
    )
    return parser.parse_args()

def detect_distribution():
    """Detect the Linux distribution by reading /etc/os-release."""
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("ID="):
                    return line.strip().split("=")[1].strip('"').lower()
    print("Warning: Could not detect distribution. Assuming generic Linux.")
    return "unknown"

def install_system_dependencies(distro):
    """Install system dependencies based on the detected distribution."""
    print("Installing system dependencies...")
    base_packages = ["python3", "python3-pip", "git"]
    optional_packages = [
        "neofetch", "smartmontools", "sysstat", "lsof",
        "pciutils", "usbutils", "lm-sensors", "flatpak", "snapd"
    ]
    packages = base_packages + optional_packages

    if distro in ["ubuntu", "debian", "linuxmint", "pop", "raspbian"]:
        subprocess.run(["sudo", "apt-get", "update"], check=True)
        subprocess.run(["sudo", "apt-get", "install", "-y"] + packages, check=False)
    elif distro in ["fedora", "rhel", "centos"]:
        subprocess.run(["sudo", "dnf", "install", "-y"] + packages, check=False)
    elif distro in ["arch", "manjaro", "endeavouros"]:
        subprocess.run(["sudo", "pacman", "-Sy", "--noconfirm"] + packages, check=False)
    elif distro in ["opensuse", "suse", "opensuse-tumbleweed"]:
        subprocess.run(["sudo", "zypper", "install", "-y"] + packages, check=False)
    else:
        print("Unknown distribution detected. Attempting generic installation...")
        for pkg in packages:
            if shutil.which("apt-get"):
                subprocess.run(["sudo", "apt-get", "install", "-y", pkg], check=False)
            elif shutil.which("dnf"):
                subprocess.run(["sudo", "dnf", "install", "-y", pkg], check=False)
            elif shutil.which("pacman"):
                subprocess.run(["sudo", "pacman", "-S", "--noconfirm", pkg], check=False)
            elif shutil.which("zypper"):
                subprocess.run(["sudo", "zypper", "install", "-y", pkg], check=False)
            else:
                print("Error: No supported package manager found. Please install dependencies manually:")
                print("Required: python3, python3-pip, git")
                print("Optional: neofetch, smartmontools, sysstat, lsof, pciutils, usbutils, lm-sensors, flatpak, snapd")
                sys.exit(1)
    print("System dependencies installation completed.")

def install_python_dependencies():
    """Install required Python dependencies."""
    print("Installing Python dependencies...")
    try:
        import pyminizip
    except ImportError:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "pyminizip", "--user"],
            check=False
        )
        if result.returncode != 0:
            print("Warning: Failed to install pyminizip with user privileges. Attempting system-wide...")
            subprocess.run(["sudo", sys.executable, "-m", "pip", "install", "pyminizip"], check=True)
    print("Python dependencies installed.")

def clone_repository(install_dir):
    """Clone the GitHub repository to the specified directory."""
    print(f"Cloning repository to {install_dir}...")
    if os.path.exists(install_dir):
        print(f"Removing existing directory {install_dir}...")
        shutil.rmtree(install_dir)
    subprocess.run(["git", "clone", REPO_URL, install_dir], check=True)
    script_path = Path(install_dir) / SCRIPT_NAME
    if not script_path.exists():
        print(f"Error: {SCRIPT_NAME} not found in the cloned repository.")
        sys.exit(1)
    script_path.chmod(0o755)  # Make the script executable
    print("Repository cloned successfully.")

def setup_configuration():
    """Set up the configuration directory and default config file."""
    print(f"Setting up configuration in {CONFIG_DIR}...")
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    (CONFIG_DIR / "plugins").mkdir(exist_ok=True)
    config_file = CONFIG_DIR / "config.conf"
    if not config_file.exists():
        with config_file.open("w") as f:
            f.write(
                "[DEFAULT]\n"
                "output_dir = ~/reports\n"
                "censorship = necessary\n"
                "verbosity = default\n"
                "format = text\n"
                "compress = no\n"
                "zip_password =\n"
            )
    print("Configuration setup completed.")

def create_symlink(install_dir, no_symlink):
    """Create a symlink in /usr/local/bin for easy access."""
    if no_symlink:
        print("Skipping symlink creation as per user request.")
        return
    print("Creating symlink...")
    script_path = Path(install_dir) / SCRIPT_NAME
    symlink_path = Path(BIN_DIR) / "systemreport"
    if symlink_path.exists():
        if symlink_path.is_symlink():
            symlink_path.unlink()
        else:
            print(f"Error: {symlink_path} exists and is not a symlink. Please remove it manually.")
            return
    if os.access(BIN_DIR, os.W_OK):
        symlink_path.symlink_to(script_path)
        print(f"Symlink created at {symlink_path}")
    else:
        print(f"Warning: No write permission to {BIN_DIR}. Run with sudo to create symlink, or create it manually:")
        print(f"sudo ln -sf {script_path} {symlink_path}")

def verify_installation(install_dir):
    """Verify that the installation was successful."""
    print("Verifying installation...")
    script_path = Path(install_dir) / SCRIPT_NAME
    symlink_path = Path(BIN_DIR) / "systemreport"
    if script_path.exists() and os.access(script_path, os.X_OK):
        print("Script installed successfully.")
        if symlink_path.exists():
            print("Symlink verified. You can run 'systemreport' from anywhere.")
        else:
            print(f"Run the script directly with: {script_path}")
    else:
        print("Error: Installation failed. Script not found or not executable.")
        sys.exit(1)

def main():
    """Main function to orchestrate the installation process."""
    print("Starting installation of systemreport_2.2.py...")
    args = parse_arguments()
    install_dir = args.install_dir

    distro = detect_distribution()
    print(f"Detected distribution: {distro}")

    install_system_dependencies(distro)
    install_python_dependencies()
    clone_repository(install_dir)
    setup_configuration()
    create_symlink(install_dir, args.no_symlink)
    verify_installation(install_dir)

    print("Installation complete! See the README for usage instructions.")

if __name__ == "__main__":
    main()