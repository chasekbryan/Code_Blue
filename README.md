# Code_Blue
Code_Blue is a Fedora Linux security auditing tool

code_blue is a GPL-3.0-licensed, host-based vulnerability and configuration scanner for Fedora that produces a single, dated log of findings. It inventories the system and RPM packages, checks for pending security advisories via DNF, looks for risky permissions (SUID/SGID and world-writable paths), lists listening ports, and—if available—runs Lynis, the CVE Binary Tool, and pip-audit for deeper checks. Run it with python3 code_blue.py (preferably as root for complete coverage); it writes results to code_blue_report_YYYYMMDD_HHMMSS.log in the current directory. No destructive actions are taken.

```bash
python3 code_blue.py
``` 
