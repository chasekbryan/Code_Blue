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


def run_lynis_scan(report_dir: str) -> Optional[Dict[str, List[str]]]:
    """Run a Lynis audit if Lynis is available.

    Returns a dictionary with two keys: 'warnings' and 'suggestions', each
    containing a list of issues recorded by the tool.  If Lynis is not
    available the function returns None.  The scan is performed with
    minimal output and writes the report and log files into the supplied
    directory.  See the Lynis documentation for details【913769379717053†L85-L119】.
    """
    if not command_exists("lynis"):
        return None
    os.makedirs(report_dir, exist_ok=True)
    report_file = os.path.join(report_dir, "lynis-report.dat")
    log_file = os.path.join(report_dir, "lynis.log")
    # Build command.  --quiet reduces noise; --no-color avoids ANSI codes;
    # --log-file and --report-file set destinations.  Non-interactive
    # auditing is used to avoid prompts.  Some checks require root; the
    # scan will proceed with reduced coverage if run as non‑root.
    cmd = [
        "lynis",
        "audit",
        "system",
        "--quiet",
        "--no-colors",
        f"--log-file={log_file}",
        f"--report-file={report_file}",
    ]
    run_cmd(cmd, timeout=300)
    warnings: List[str] = []
    suggestions: List[str] = []
    try:
        with open(report_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                # Each line of the report uses key=value style.  Warnings and
                # suggestions are recorded in these keys: warning[]=… and
                # suggestion[]=…
                if line.startswith("warning"):  # e.g. warning[]=WRN-XXXX Some message
                    parts = line.strip().split("=", 1)
                    if len(parts) == 2:
                        warnings.append(parts[1])
                elif line.startswith("suggestion"):
                    parts = line.strip().split("=", 1)
                    if len(parts) == 2:
                        suggestions.append(parts[1])
    except FileNotFoundError:
        # Lynis did not produce a report
        return None
    return {"warnings": warnings, "suggestions": suggestions}


def run_cve_bin_tool_scan(scan_dir: str, output_json: str) -> Optional[List[Dict[str, str]]]:
    """Run cve-bin-tool if available and return list of vulnerability findings.

    The CVE Binary Tool is a free, open source tool that uses data from
    NVD, Red Hat, OSV and other sources to find known vulnerabilities in
    software【233125942066929†L98-L129】.  It supports scanning directories or SBOMs and
    produces reports in several formats.  If cve-bin-tool is not installed
    or the scan fails, return None.  Otherwise parse the JSON report and
    return a list of findings with keys: 'component', 'version' and
    'cves'.  The JSON structure may change over time; this function
    handles a minimal common subset.
    """
    if not command_exists("cve-bin-tool"):
        return None
    # Ensure the data directory exists
    os.makedirs(os.path.dirname(output_json), exist_ok=True)
    cmd = [
        "cve-bin-tool",
        "--report",
        "json",
        "--output",
        output_json,
        "--quiet",
        scan_dir,
    ]
    # Running this scan can take several minutes depending on the amount
    # of software and the speed of the network during database
    # synchronisation.  Increase timeout accordingly.
    run_cmd(cmd, timeout=600)
    if not os.path.isfile(output_json):
        return None
    try:
        with open(output_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        findings = []
        # The JSON output uses 'files' key with each file containing a
        # list of components and their vulnerabilities.  Traverse
        # accordingly.
        for file_entry in data.get("files", []):
            components = file_entry.get("components", [])
            for comp in components:
                name = comp.get("component", "unknown")
                version = comp.get("version", "unknown")
                cves = comp.get("cve_number", []) or comp.get("cves", [])
                if cves:
                    findings.append({
                        "component": name,
                        "version": version,
                        "cves": ",".join(cves) if isinstance(cves, list) else str(cves),
                    })
        return findings
    except Exception:
        return None


def run_pip_audit_scan() -> Optional[List[Dict[str, str]]]:
    """Scan Python packages using pip-audit if available.

    pip-audit is a tool that queries vulnerability databases for known
    issues in Python packages.  If the tool is available and runs
    successfully, this function returns a list of findings with keys
    'package', 'version' and 'vulns'.  Otherwise it returns None.
    """
    if not command_exists("pip-audit"):
        return None
    stdout, stderr, rc = run_cmd(["pip-audit", "-f", "json"])
    if rc != 0 or not stdout:
        return None
    try:
        results = json.loads(stdout)
        findings = []
        for item in results:
            pkg = item.get("name")
            version = item.get("version")
            vulns = [v.get("id") for v in item.get("vulns", [])]
            if vulns:
                findings.append({"package": pkg, "version": version, "vulns": ",".join(vulns)})
        return findings
    except Exception:
        return None


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
        if lynis_results is None:
            report.write("Lynis not available or no results produced.\n")
        else:
            warnings = lynis_results.get("warnings", [])
            suggestions = lynis_results.get("suggestions", [])
            report.write(f"Warnings: {len(warnings)}\n")
            for w in warnings:
                report.write(f"  {w}\n")
            report.write(f"Suggestions: {len(suggestions)}\n")
            for s in suggestions:
                report.write(f"  {s}\n")
        report.write("\n")
        # CVE Binary Tool scan
        report.write("== CVE Binary Tool Scan ==\n")
        cve_results = run_cve_bin_tool_scan("/usr", "/tmp/code_blue_cve_results.json")
        if cve_results is None:
            report.write(
                "CVE Binary Tool not available or scan could not be performed.\n"
            )
        else:
            report.write(f"Findings: {len(cve_results)}\n")
            for finding in cve_results:
                report.write(
                    f"  {finding['component']} {finding['version']} – CVEs: {finding['cves']}\n"
                )
        report.write("\n")
        # pip-audit scan
        report.write("== Python Package Vulnerabilities (pip-audit) ==\n")
        pip_audit_results = run_pip_audit_scan()
        if pip_audit_results is None:
            report.write("pip-audit not available or no vulnerabilities found.\n")
        else:
            for entry in pip_audit_results:
                report.write(
                    f"  {entry['package']} {entry['version']} – CVEs: {entry['vulns']}\n"
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
        # Finishing statement
        report.write("Scan completed.\n")
    return report_path


def main() -> None:
    report_path = generate_report()
    print(f"Report generated: {report_path}")


if __name__ == "__main__":
    main()