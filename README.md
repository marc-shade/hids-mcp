# Host-based IDS MCP Server

Host-based Intrusion Detection System for monitoring local system security.

## Features

- **Auth Log Analysis**: Failed logins, brute force detection, privilege escalation
- **Process Monitoring**: Suspicious processes, unusual activity patterns
- **File Integrity**: Detect unauthorized changes to critical files
- **Network Connections**: Monitor active connections, detect backdoors
- **Port Scan Detection**: Identify reconnaissance activity
- **User Activity**: Login patterns, privilege usage, sudo commands

## Tools

| Tool | Description |
|------|-------------|
| `analyze_auth_logs` | Parse auth/secure logs for security events |
| `detect_brute_force` | Find brute force login attempts |
| `check_suspicious_processes` | Identify suspicious running processes |
| `monitor_network_connections` | Check active network connections |
| `check_listening_ports` | Find all listening services |
| `check_file_integrity` | Verify critical file checksums |
| `get_user_activity` | Analyze user login/logout patterns |
| `generate_security_report` | Comprehensive host security report |

## Monitored Log Files

- `/var/log/auth.log` (Debian/Ubuntu)
- `/var/log/secure` (RHEL/Fedora)
- `/var/log/messages`
- `/var/log/syslog`

## Suspicious Process Indicators

- Hidden processes (names starting with .)
- Processes from /tmp or /dev/shm
- Processes with deleted executables
- Known malware process names
- Unusual parent-child relationships
