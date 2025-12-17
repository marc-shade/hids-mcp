# Host-based IDS MCP Server

[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)
[![Python-3.10+](https://img.shields.io/badge/Python-3.10%2B-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Part of Agentic System](https://img.shields.io/badge/Part_of-Agentic_System-brightgreen)](https://github.com/marc-shade/agentic-system-oss)

> **Host-based intrusion detection system integration.**

Part of the [Agentic System](https://github.com/marc-shade/agentic-system-oss) - a 24/7 autonomous AI framework with persistent memory.

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
---

## Part of the MCP Ecosystem

This server integrates with other MCP servers for comprehensive AGI capabilities:

| Server | Purpose |
|--------|---------|
| [enhanced-memory-mcp](https://github.com/marc-shade/enhanced-memory-mcp) | 4-tier persistent memory with semantic search |
| [agent-runtime-mcp](https://github.com/marc-shade/agent-runtime-mcp) | Persistent task queues and goal decomposition |
| [agi-mcp](https://github.com/marc-shade/agi-mcp) | Full AGI orchestration with 21 tools |
| [cluster-execution-mcp](https://github.com/marc-shade/cluster-execution-mcp) | Distributed task routing across nodes |
| [node-chat-mcp](https://github.com/marc-shade/node-chat-mcp) | Inter-node AI communication |
| [ember-mcp](https://github.com/marc-shade/ember-mcp) | Production-only policy enforcement |

See [agentic-system-oss](https://github.com/marc-shade/agentic-system-oss) for the complete framework.
