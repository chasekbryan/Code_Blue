#!/usr/bin/env python3
"""
code_blue
===========

Comprehensive vulnerability and configuration scanner for Fedora systems.

This tool attempts to analyse as much software‑based state as possible on
the host it runs on.  It gathers system information, enumerates installed
packages, checks for outstanding security updates, examines file system
permissions, inspects network services and, where present, delegates
additional checks to third party auditing tools such as Lynis, OpenSCAP
and the CVE Binary Tool.  Results are collected into a single log file
for ease of review.

The program is designed to be opportunistic.  If an external tool is
installed it will be used; otherwise the corresponding section of the
report will be skipped.  This approach mirrors the behaviour of Lynis,
which "only use[s] and test[s] the components that it can find" and
therefore runs with almost no dependencies【913769379717053†L85-L96】.

Copyright © 2025 code_blue contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Creation date: 2025‑08‑13 (ISO 8601)
"""

import datetime
import json
import os
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple
import sys
import threading
import itertools
import time

# Ensure that common system directories are in PATH so that binaries like
# lynis, rkhunter, chkrootkit, cve-bin-tool and pip-audit can be located even
# when running under a restricted environment (e.g. sudo).  Some package
# managers install into /usr/sbin or /usr/local/sbin, while pip installs
# scripts into /usr/local/bin.  Without these directories, ``shutil.which``
# would fail to locate the executables.  Append missing directories to PATH.
# Build a list of directories that should be on PATH when searching for
# executables.  In addition to the standard system locations this list
# includes the invoking user's local bin directory when running under
# sudo.  Many Python tools (e.g. pip‑audit) are installed into
# ~/.local/bin for the non‑root user and would otherwise be invisible
# when the script is executed with sudo.  The SUDO_USER environment
# variable identifies the original user.  If present, expand its home
# directory and append the .local/bin path.  Duplicates are filtered out
# when constructing the final PATH.
_default_dirs: List[str] = [
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
]
_sudo_user = os.environ.get("SUDO_USER")
if _sudo_user:
    try:
        from pathlib import Path
        sudo_home = Path("~" + _sudo_user).expanduser()
        sudo_local_bin = str(sudo_home / ".local" / "bin")
        if sudo_local_bin not in _default_dirs:
            _default_dirs.insert(0, sudo_local_bin)
    except Exception:
        pass
current_path = os.environ.get("PATH", "")
for _d in _default_dirs:
    if _d not in current_path.split(os.pathsep):
        current_path = current_path + os.pathsep + _d if current_path else _d
os.environ["PATH"] = current_path

def run_cmd_with_fallbacks(cmd_lists, **popen_kwargs):
    """
    cmd_lists: list of candidate argv lists (e.g., [["cve-bin-tool","--version"],
                                                    [sys.executable,"-m","cve_bin_tool","--version"]])
    Tries each until one executes successfully. Returns (exitcode, stdout, stderr, used_cmd).
    """
    for argv in cmd_lists:
        try:
            # If the first element is not the Python executable, ensure it exists in PATH.
            if argv[0] != sys.executable and shutil.which(argv[0]) is None:
                continue
            proc = subprocess.run(argv, capture_output=True, text=True, **popen_kwargs)
            # Consider the command usable if it executed at all (return code >=0)
            # or produced any output on stdout/stderr.  Many scanners return
            # non-zero exit codes to indicate findings; these should not be
            # treated as failures.
            if proc.returncode >= 0 or proc.stdout or proc.stderr:
                return proc.returncode, proc.stdout, proc.stderr, argv
        except FileNotFoundError:
            continue
        except Exception:
            continue
    return None, "", "", None


def start_spinner(message: str = "Scanning") -> threading.Event:
    """Start a simple console spinner in a background thread.

    The spinner writes a rotating character (e.g. '-','/','\\') to standard
    output alongside the provided message.  It returns a threading.Event
    object that can be set to stop the spinner.  When the stop event is
    signalled the spinner cleans up the line.
    """
    stop_event = threading.Event()

    def spin():
        for char in itertools.cycle(['-', '/', '\\']):
            if stop_event.is_set():
                break
            sys.stdout.write(f"\r{message}... {char}")
            sys.stdout.flush()
            time.sleep(0.1)
        # Clear the line when finished
        sys.stdout.write("\r" + " " * (len(message) + 5) + "\r")
        sys.stdout.flush()

    thread = threading.Thread(target=spin, daemon=True)
    thread.start()
    return stop_event



def run_cmd(cmd: List[str], timeout: int = 60) -> Tuple[str, str, int]:
    """Run a command and capture its output.

    Returns a tuple of (stdout, stderr, returncode).  If the command
    fails to execute, stderr will contain the exception message and
    returncode will be -1.
    """
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as exc:  # pragma: no cover - defensive fallback
        return "", str(exc), -1


def command_exists(command: str) -> bool:
    """Return True if *command* exists in the user's PATH."""
    return shutil.which(command) is not None


def get_os_info() -> str:
    """Return a human readable description of the operating system."""
    # Try to parse /etc/os-release first (available on most modern Linux
    # distributions, including Fedora).  Fall back to lsb_release and uname.
    os_release_path = "/etc/os-release"
    info = []
    if os.path.isfile(os_release_path):
        with open(os_release_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("NAME="):
                    info.append(line.strip().split("=", 1)[1].strip('"'))
                elif line.startswith("VERSION="):
                    info.append(line.strip().split("=", 1)[1].strip('"'))
    # Additional kernel details
    uname_out, _, _ = run_cmd(["uname", "-r"])
    if uname_out:
        info.append(f"kernel {uname_out}")
    return " ".join(info) if info else "Unknown OS"


def get_security_updates() -> List[Dict[str, str]]:
    """Return a list of security updates available via DNF.

    Each entry in the returned list contains keys: 'advisory', 'package'
    and 'arch'.  This function relies on the DNF command `updateinfo list
    sec` which lists security notices; according to the Linux Audit blog
    this command enumerates packages with security updates【165402070898409†L73-L83】.  If
    DNF is not installed or returns no output, an empty list is returned.
    """
    updates = []
    if not command_exists("dnf"):
        return updates
    # Ensure the metadata is up to date
    run_cmd(["dnf", "-q", "makecache", "--refresh"])
    stdout, stderr, rc = run_cmd(["dnf", "-q", "updateinfo", "list", "sec"])
    if rc != 0 or not stdout:
        return updates
    for line in stdout.splitlines():
        # Typical format: FEDORA-2025-1234567     Important/Sec.  package.arch
        parts = line.split()
        if len(parts) >= 3:
            advisory = parts[0]
            pkg_arch = parts[-1]
            # package.arch may be 'openssl.x86_64'
            pkg, _, arch = pkg_arch.rpartition(".")
            updates.append({"advisory": advisory, "package": pkg, "arch": arch})
    return updates


def get_installed_packages() -> List[str]:
    """Return a list of installed RPM packages."""
    packages = []
    # Prefer rpm because it is available even when DNF isn't
    if command_exists("rpm"):
        stdout, _, rc = run_cmd(["rpm", "-qa"])
        if rc == 0:
            packages = stdout.splitlines()
    elif command_exists("dnf"):
        stdout, _, rc = run_cmd(["dnf", "-q", "list", "installed"])
        if rc == 0:
            # Skip header lines
            for line in stdout.splitlines():
                if "." in line:
                    packages.append(line.split()[0])
    return packages


def run_lynis_scan(report_dir: str) -> Optional[Dict[str, object]]:
    """Run a Lynis audit if possible and return detailed results.

    The return value is a dictionary containing at least these keys:

      - ``warnings``: a list of warning messages (may be empty)
      - ``suggestions``: a list of suggestion messages (may be empty)
      - ``rc``: the return code from the Lynis process (or None if not run)
      - ``stdout``: raw standard output from the process
      - ``stderr``: raw standard error from the process
      - ``cmd``: the command used (list of arguments)
      - ``error`` (optional): descriptive string if the audit could not be performed

    This richer return structure allows the caller to report issues when Lynis
    executes but fails to produce a report (e.g. missing dependencies) or
    when the executable is not present at all.
    """
    report_file = os.path.join(report_dir, "lynis-report.dat")
    log_file = os.path.join(report_dir, "lynis.log")
    candidates = [
        [
            "lynis",
            "audit",
            "system",
            "--quiet",
            "--no-colors",
            f"--log-file={log_file}",
            f"--report-file={report_file}",
        ]
    ]
    os.makedirs(report_dir, exist_ok=True)
    rc, stdout, stderr, used_cmd = run_cmd_with_fallbacks(candidates, timeout=900)
    result: Dict[str, object] = {
        "warnings": [],
        "suggestions": [],
        "rc": rc,
        "stdout": stdout.strip() if stdout else "",
        "stderr": stderr.strip() if stderr else "",
        "cmd": " ".join(used_cmd) if used_cmd else "",
    }
    if rc is None:
        result["error"] = "lynis executable not found"
        return result
    # If the report file exists, parse it for warnings and suggestions
    if os.path.exists(report_file):
        try:
            with open(report_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("warning"):  # e.g. warning[]=WRN-XXXX Some message
                        parts = line.split("=", 1)
                        if len(parts) == 2:
                            result["warnings"].append(parts[1])
                    elif line.startswith("suggestion"):
                        parts = line.split("=", 1)
                        if len(parts) == 2:
                            result["suggestions"].append(parts[1])
        except Exception as e:
            result["error"] = f"Failed to read Lynis report: {e}"
            return result
        return result
    # If no report file was produced but there is stdout/stderr, return those
    if result["stdout"] or result["stderr"]:
        result["error"] = "Lynis ran but did not produce a report file"
        return result
    # Otherwise indicate that no output was produced
    result["error"] = "Lynis produced no output"
    return result


def run_cve_bin_tool_scan(scan_dir: str, output_json: str) -> Dict[str, object]:
    """Run cve-bin-tool and return a dictionary of results.

    The CVE Binary Tool scans binaries to identify known vulnerable components using
    data from NVD, Red Hat, OSV and other sources【233125942066929†L98-L129】.  This function
    attempts to invoke the tool and returns a dictionary with keys:

      - ``findings``: a list of dictionaries, each containing 'component',
        'version' and 'cves' (may be empty if no vulnerabilities were found)
      - ``rc``: return code from the process (or None if not run)
      - ``stdout``: raw standard output
      - ``stderr``: raw standard error
      - ``cmd``: the command used
      - ``error`` (optional): descriptive error message if the scan failed
    """
    result: Dict[str, object] = {
        "findings": [],
        "rc": None,
        "stdout": "",
        "stderr": "",
        "cmd": "",
    }
    # Use only the standalone binary; the module can't be invoked directly via -m
    candidates = [
        ["cve-bin-tool", "--report", "json", "--output", output_json, "--quiet", scan_dir],
    ]
    # Ensure the parent directory exists
    os.makedirs(os.path.dirname(output_json), exist_ok=True)
    rc, stdout, stderr, used_cmd = run_cmd_with_fallbacks(candidates, timeout=1800)
    result["rc"] = rc
    result["stdout"] = stdout.strip() if stdout else ""
    result["stderr"] = stderr.strip() if stderr else ""
    result["cmd"] = " ".join(used_cmd) if used_cmd else ""
    if rc is None:
        result["error"] = "cve-bin-tool executable not found"
        return result
    # Wait a moment for the report file to be written
    time.sleep(2)
    data = None
    if os.path.isfile(output_json):
        try:
            with open(output_json, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            result["error"] = f"Failed to parse JSON report: {e}"
            return result
    elif result["stdout"]:
        # Some versions may emit JSON to stdout instead of writing a file
        try:
            data = json.loads(result["stdout"])
        except Exception:
            data = None
    if data is None:
        result["error"] = "No report produced by cve-bin-tool"
        return result
    # Parse vulnerabilities
    for file_entry in data.get("files", []):
        for comp in file_entry.get("components", []):
            name = comp.get("component", "unknown")
            version = comp.get("version", "unknown")
            cves = comp.get("cve_number", []) or comp.get("cves", [])
            if cves:
                result["findings"].append({
                    "component": name,
                    "version": version,
                    "cves": ",".join(cves) if isinstance(cves, list) else str(cves),
                })
    return result


def run_pip_audit_scan() -> Dict[str, object]:
    """Scan Python packages using pip-audit and return a dictionary of results.

    The returned dictionary contains:

      - ``findings``: list of dictionaries with 'package', 'version', 'vulns'
        (empty if no vulnerabilities were found)
      - ``rc``: return code
      - ``stdout``: raw standard output
      - ``stderr``: raw standard error
      - ``cmd``: command used
      - ``error`` (optional): error description if the scan failed
    """
    result: Dict[str, object] = {
        "findings": [],
        "rc": None,
        "stdout": "",
        "stderr": "",
        "cmd": "",
    }
    candidates = [
        ["pip-audit", "-f", "json"],
        [sys.executable, "-m", "pip_audit", "-f", "json"],
    ]
    rc, stdout, stderr, used_cmd = run_cmd_with_fallbacks(candidates, timeout=900)
    result["rc"] = rc
    result["stdout"] = stdout.strip() if stdout else ""
    result["stderr"] = stderr.strip() if stderr else ""
    result["cmd"] = " ".join(used_cmd) if used_cmd else ""
    if rc is None:
        result["error"] = "pip-audit executable not found"
        return result
    # If there is no stdout, either there are no vulnerabilities or an error occurred.
    if not result["stdout"]:
        # pip-audit returns exit code 0 when no vulnerabilities are found, 1 when some are found.
        # If there is no output on stdout but rc is 0 or 1, assume no vulnerabilities were found.
        if rc in (0, 1):
            return result  # empty findings
        # Otherwise, treat any stderr as an error message
        result["error"] = result["stderr"] or "No output from pip-audit"
        return result
    raw = result["stdout"]
    parsed_items: List[Dict[str, object]] = []
    # pip-audit may emit one JSON object per line or a JSON array.  Try array first.
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            parsed_items = data
        elif isinstance(data, dict):
            # Single dict result
            parsed_items = [data]
        elif isinstance(data, str):
            # String result like "No known vulnerabilities found"
            # treat as no vulnerabilities
            return result
    except Exception:
        # Attempt to parse line by line; ignore lines that cannot be parsed
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    parsed_items.append(item)
            except Exception:
                # Non JSON line; skip
                continue
        if not parsed_items:
            # If nothing parsed and rc indicates no vulnerabilities, return
            if rc in (0, 1):
                return result
            result["error"] = "Failed to parse pip-audit output"
            return result
    # Extract findings from parsed items
    for item in parsed_items:
        # Some versions produce keys 'name', 'version', and 'vulns'; others use 'package'
        pkg = item.get("name") or item.get("package")
        version = item.get("version") or item.get("current_version")
        vulns_list = []
        vulns_field = item.get("vulns") or item.get("vulnerabilities")
        if isinstance(vulns_field, list):
            for v in vulns_field:
                # Each vulnerability may be dict with 'id' or string
                if isinstance(v, dict):
                    vid = v.get("id") or v.get("cve") or v.get("advisory")
                    if vid:
                        vulns_list.append(str(vid))
                else:
                    vulns_list.append(str(v))
        elif isinstance(vulns_field, dict):
            vid = vulns_field.get("id") or vulns_field.get("cve") or vulns_field.get("advisory")
            if vid:
                vulns_list.append(str(vid))
        # Add entry if vulnerabilities found
        if vulns_list:
            result["findings"].append({
                "package": pkg or "unknown",
                "version": version or "unknown",
                "vulns": ",".join(vulns_list),
            })
    return result


def run_rkhunter_scan() -> Optional[str]:
    """Run Rootkit Hunter (rkhunter) if available and return its output.

    Rootkit Hunter is a shell script that scans for rootkits, backdoors and
    related security issues on a Linux system【715406127971549†L110-L147】.  When available it can
    compare MD5 hashes, look for default files used by rootkits, check for
    wrong file permissions for binaries, look for suspicious strings in
    kernel modules and search for hidden files/folders【715406127971549†L142-L147】.  If rkhunter
    is not installed or fails to run, return None.
    """
    # Run rkhunter in check mode; --sk skips key checks for faster scanning; --nocolors
    # disables ANSI codes; --rwo outputs only warnings (report warnings only).
    candidates = [
        ["rkhunter", "--check", "--sk", "--nocolors", "--rwo"],
        ["rkhunter", "--check", "--sk", "--rwo"],
    ]
    rc, stdout, stderr, used_cmd = run_cmd_with_fallbacks(candidates, timeout=900)
    # If the command isn't found at all, report as unavailable
    if rc is None:
        return None
    # Combine stdout and stderr; some versions of rkhunter print
    # warnings to stderr only
    output = (stdout or "") + ("\n" + stderr if stderr else "")
    # If rkhunter ran successfully but produced no output (no warnings
    # or findings), return an empty string rather than None.  The
    # caller can interpret this as "no issues found".
    return output.strip()


def run_chkrootkit_scan() -> Optional[str]:
    """Run chkrootkit if available and return its output.

    chkrootkit scans the system for signs of rootkits and can detect over 70
    different rootkits【342608795493696†L75-L88】.  If the program is not installed or fails
    to execute, return None.
    """
    candidates = [
        ["chkrootkit", "-q"],  # quiet mode reduces noise while still reporting infections
        ["chkrootkit"],
    ]
    rc, stdout, stderr, used_cmd = run_cmd_with_fallbacks(candidates, timeout=600)
    # If chkrootkit isn't available, indicate as such
    if rc is None:
        return None
    output = (stdout or "") + ("\n" + stderr if stderr else "")
    # As with rkhunter, treat empty output from a successful run as an
    # indication that no rootkits were detected.  Return an empty
    # string rather than None.
    return output.strip()


def run_rpm_verify() -> Optional[List[str]]:
    """Verify installed RPM files against the RPM database.

    Running ``rpm -Va`` checks all installed packages for unexpected changes
    to file attributes (size, mode, checksum, etc.) and reports any
    discrepancies.  If rpm is unavailable or the verification produces no
    output, return None.  Otherwise return a list of the first 100 lines
    of the verification output.
    """
    if not command_exists("rpm"):
        return None
    stdout, stderr, rc = run_cmd(["rpm", "-Va"], timeout=900)
    if rc != 0:
        # If rpm returns non‑zero but still produces output, capture it
        combined = (stdout or "") + ("\n" + stderr if stderr else "")
        lines = [line for line in combined.strip().splitlines() if line]
        return lines[:100] if lines else None
    if not stdout:
        return None
    lines = [line for line in stdout.splitlines() if line.strip()]
    return lines[:100] if lines else None


def get_cron_jobs() -> Optional[List[str]]:
    """Return a list of cron jobs scheduled on the system.

    This function inspects /etc/crontab and the directories under
    /etc/cron.{hourly,daily,weekly,monthly,d,job}.  It also queries the
    current user's crontab via the ``crontab -l`` command.  If no cron
    entries can be found or cron is not available, return None.
    """
    cron_entries: List[str] = []
    # System-wide crontab
    sys_crontab = "/etc/crontab"
    if os.path.exists(sys_crontab):
        try:
            with open(sys_crontab, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        cron_entries.append(f"/etc/crontab: {stripped}")
        except Exception:
            pass
    # Cron directories
    cron_dirs = [
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/etc/cron.d",
    ]
    for d in cron_dirs:
        if os.path.isdir(d):
            try:
                for entry in os.listdir(d):
                    if entry.startswith('.'):
                        continue
                    cron_entries.append(f"{d}/{entry}")
            except Exception:
                pass
    # Current user's crontab
    if command_exists("crontab"):
        user_cron_out, user_cron_err, rc = run_cmd(["crontab", "-l"])
        if rc == 0 and user_cron_out:
            for line in user_cron_out.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    cron_entries.append(f"(user crontab): {stripped}")
    return cron_entries if cron_entries else None


def get_suspicious_users() -> Optional[List[str]]:
    """Return a list of potentially suspicious user accounts.

    This function examines /etc/passwd to find users with UID 0 (root
    equivalents) besides root and users without a valid login shell (e.g.
    /bin/false, /usr/sbin/nologin).  It returns descriptive strings.  If no
    such accounts are found, return None.
    """
    suspects: List[str] = []
    try:
        with open("/etc/passwd", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) < 7:
                    continue
                user, _, uid, _, _, home, shell = parts
                try:
                    uid_num = int(uid)
                except ValueError:
                    continue
                # Check for non-root UID 0 accounts
                if uid_num == 0 and user != "root":
                    suspects.append(f"User {user} has UID 0 (root equivalence)")
                # Check for users with no login shell
                if shell in ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false"):
                    suspects.append(f"User {user} has no login shell ({shell})")
    except Exception:
        return None
    return suspects if suspects else None


def find_special_files() -> Dict[str, List[str]]:
    """Search for SUID/SGID and world writable files.

    Returns a dictionary with keys 'suid', 'sgid', 'world_writable_files'
    and 'world_writable_dirs'.  Each value is a list of file paths.  To
    limit the size of the report, only the first 50 entries for each
    category are returned; the counts are provided separately.  Running
    these commands may require root privileges to traverse all
    directories.
    """
    categories: Dict[str, List[str]] = {
        "suid": [],
        "sgid": [],
        "world_writable_files": [],
        "world_writable_dirs": [],
    }
    # Determine whether we can use -perm /4000 for SUID; use xdev to
    # stay on current filesystem.  Capture output quietly.
    find_cmds = {
        "suid": ["find", "/", "-xdev", "-type", "f", "-perm", "-04000", "-print"],
        "sgid": ["find", "/", "-xdev", "-type", "f", "-perm", "-02000", "-print"],
        "world_writable_files": ["find", "/", "-xdev", "-type", "f", "-perm", "-0002", "-print"],
        "world_writable_dirs": ["find", "/", "-xdev", "-type", "d", "-perm", "-0002", "-print"],
    }
    for key, cmd in find_cmds.items():
        stdout, _, rc = run_cmd(cmd, timeout=120)
        if rc == 0 and stdout:
            files = stdout.splitlines()
            categories[key] = files[:50]  # limit output
        else:
            categories[key] = []
    return categories


def get_open_ports() -> List[str]:
    """Return a list of open listening sockets.

    Uses `ss -tulpn` if available, falling back to `netstat -tulpn`.  Only
    lines that indicate a listening socket are returned.  The output
    includes the protocol, local address and port, and associated
    process.
    """
    lines: List[str] = []
    if command_exists("ss"):
        stdout, _, rc = run_cmd(["ss", "-tulpn"])
        if rc == 0:
            for line in stdout.splitlines():
                if "LISTEN" in line.upper():
                    lines.append(line.strip())
            return lines
    if command_exists("netstat"):
        stdout, _, rc = run_cmd(["netstat", "-tulpn"])
        if rc == 0:
            for line in stdout.splitlines():
                if "LISTEN" in line.upper():
                    lines.append(line.strip())
    return lines


def generate_report() -> str:
    """Generate the vulnerability report and return the path to the log file."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name = f"code_blue_report_{timestamp}.log"
    report_path = os.path.abspath(report_name)
    with open(report_path, "w", encoding="utf-8") as report:
        report.write("Code Blue Vulnerability Report\n")
        report.write(f"Generated on: {datetime.datetime.now().isoformat()}\n\n")
        # System information
        report.write("== System Information ==\n")
        report.write(f"Operating system: {get_os_info()}\n")
        user = os.getenv("USER", "unknown")
        report.write(f"Executed as user: {user}\n")
        if os.geteuid() != 0:
            report.write("WARNING: Not running as root. Some checks may be incomplete.\n")
        report.write("\n")
        # Installed packages
        report.write("== Installed Packages ==\n")
        pkgs = get_installed_packages()
        report.write(f"Total packages: {len(pkgs)}\n")
        # Do not list all packages to avoid huge log size; optionally list first 20
        if pkgs:
            report.write("Sample packages (first 20):\n")
            for pkg in pkgs[:20]:
                report.write(f"  {pkg}\n")
        report.write("\n")
        # Security updates
        report.write("== Pending Security Updates (DNF) ==\n")
        sec_updates = get_security_updates()
        if not sec_updates:
            report.write("No security updates found or DNF unavailable.\n")
        else:
            for upd in sec_updates:
                report.write(
                    f"  {upd['package']} ({upd['arch']}) – advisory {upd['advisory']}\n"
                )
        report.write("\n")
        # Lynis scan
        report.write("== Lynis Audit ==\n")
        lynis_results = run_lynis_scan("/tmp/code_blue_lynis")
        # run_lynis_scan always returns a dict; if the executable is missing
        # rc will be None and an error key will be present.  Handle these
        # conditions explicitly.
        if lynis_results is None:
            report.write("Lynis not available or no results produced.\n")
        else:
            err = lynis_results.get("error")
            if err:
                report.write(f"Lynis error: {err}\n")
            warnings = lynis_results.get("warnings", [])
            suggestions = lynis_results.get("suggestions", [])
            if warnings:
                report.write(f"Warnings ({len(warnings)}):\n")
                for w in warnings:
                    report.write(f"  {w}\n")
            if suggestions:
                report.write(f"Suggestions ({len(suggestions)}):\n")
                for s in suggestions:
                    report.write(f"  {s}\n")
            if not warnings and not suggestions and not err:
                report.write("No warnings or suggestions from Lynis.\n")
        report.write("\n")
        # CVE Binary Tool scan
        report.write("== CVE Binary Tool Scan ==\n")
        cve_results = run_cve_bin_tool_scan("/usr", "/tmp/code_blue_cve_results.json")
        if cve_results is None:
            report.write(
                "CVE Binary Tool not available or scan could not be performed.\n"
            )
        else:
            err = cve_results.get("error")
            findings = cve_results.get("findings", [])
            if err:
                report.write(f"CVE Binary Tool error: {err}\n")
            elif not findings:
                report.write("No vulnerable components detected by cve-bin-tool.\n")
            else:
                report.write(f"Findings ({len(findings)}):\n")
                for finding in findings:
                    component = finding.get("component", "unknown")
                    version = finding.get("version", "unknown")
                    cves = finding.get("cves", "")
                    report.write(
                        f"  {component} {version} – CVEs: {cves}\n"
                    )
        report.write("\n")
        # pip-audit scan
        report.write("== Python Package Vulnerabilities (pip-audit) ==\n")
        pip_audit_results = run_pip_audit_scan()
        if pip_audit_results is None:
            report.write("pip-audit not available or scan could not be performed.\n")
        else:
            err = pip_audit_results.get("error")
            findings = pip_audit_results.get("findings", [])
            if err:
                report.write(f"pip-audit error: {err}\n")
            elif not findings:
                report.write("No vulnerable Python packages detected.\n")
            else:
                report.write(f"Vulnerable packages ({len(findings)}):\n")
                for entry in findings:
                    package = entry.get("package", "unknown")
                    version = entry.get("version", "unknown")
                    vulns = entry.get("vulns", "")
                    report.write(
                        f"  {package} {version} – CVEs: {vulns}\n"
                    )
        report.write("\n")
        # File permission checks
        report.write("== Special File Permissions ==\n")
        perm_findings = find_special_files()
        report.write(
            f"SUID files (showing up to 50 of {len(perm_findings.get('suid', []))} found):\n"
        )
        for path in perm_findings.get("suid", []):
            report.write(f"  {path}\n")
        report.write(
            f"SGID files (showing up to 50 of {len(perm_findings.get('sgid', []))} found):\n"
        )
        for path in perm_findings.get("sgid", []):
            report.write(f"  {path}\n")
        report.write(
            f"World writable files (showing up to 50 of {len(perm_findings.get('world_writable_files', []))} found):\n"
        )
        for path in perm_findings.get("world_writable_files", []):
            report.write(f"  {path}\n")
        report.write(
            f"World writable directories (showing up to 50 of {len(perm_findings.get('world_writable_dirs', []))} found):\n"
        )
        for path in perm_findings.get("world_writable_dirs", []):
            report.write(f"  {path}\n")
        report.write("\n")
        # Open ports
        report.write("== Open Listening Ports ==\n")
        ports = get_open_ports()
        if not ports:
            report.write("No listening ports detected or netstat/ss unavailable.\n")
        else:
            for line in ports:
                report.write(f"  {line}\n")
        report.write("\n")

        # Rootkit Hunter scan
        report.write("== Rootkit Hunter (rkhunter) ==\n")
        rk = run_rkhunter_scan()
        if rk is None:
            report.write("rkhunter not available or not installed.\n")
        else:
            # If the output is empty, indicate that no issues were found.
            if rk.strip() == "":
                report.write("No rootkit warnings found by rkhunter.\n")
            else:
                lines = rk.splitlines()
                report.write(f"Output (showing up to 200 of {len(lines)} lines):\n")
                for ln in lines[:200]:
                    report.write(f"  {ln}\n")
        report.write("\n")

        # chkrootkit scan
        report.write("== chkrootkit Scan ==\n")
        ck = run_chkrootkit_scan()
        if ck is None:
            report.write("chkrootkit not available or not installed.\n")
        else:
            if ck.strip() == "":
                report.write("No rootkit warnings found by chkrootkit.\n")
            else:
                lines = ck.splitlines()
                report.write(f"Output (showing up to 200 of {len(lines)} lines):\n")
                for ln in lines[:200]:
                    report.write(f"  {ln}\n")
        report.write("\n")

        # RPM verification
        report.write("== RPM File Verification ==\n")
        verify_lines = run_rpm_verify()
        if verify_lines is None:
            report.write("rpm verification not available or no discrepancies found.\n")
        else:
            report.write(f"Discrepancies (showing up to {len(verify_lines)} lines):\n")
            for ln in verify_lines:
                report.write(f"  {ln}\n")
        report.write("\n")

        # Cron jobs
        report.write("== Scheduled Cron Jobs ==\n")
        cron_jobs = get_cron_jobs()
        if cron_jobs is None:
            report.write("No cron jobs found or unable to retrieve cron information.\n")
        else:
            for cj in cron_jobs[:100]:
                report.write(f"  {cj}\n")
            if len(cron_jobs) > 100:
                report.write(f"  ... ({len(cron_jobs) - 100} more entries)\n")
        report.write("\n")

        # Suspicious user accounts
        report.write("== Suspicious User Accounts ==\n")
        suspects = get_suspicious_users()
        if suspects is None:
            report.write("No suspicious user accounts detected.\n")
        else:
            for s in suspects:
                report.write(f"  {s}\n")
        report.write("\n")
        # Finishing statement
        report.write("Scan completed.\n")
    return report_path


def main() -> None:
    # Provide visual feedback while the report is being generated.  Start a
    # spinner in the background and stop it when the report is ready.
    spinner_stop = start_spinner("Generating report")
    try:
        report_path = generate_report()
    finally:
        spinner_stop.set()
    print(f"Report generated: {report_path}")


if __name__ == "__main__":
    main()
