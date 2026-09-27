# NETWATCH
## Network Monitoring, Security Assessment & IDS Platform

NETWATCH is a Python-based network monitoring and defensive security assessment platform designed for authorized networks.

It combines network discovery, port and service scanning, DNS analysis, HTTP/HTTPS analysis, traffic analysis, intrusion detection, firewall analysis, network topology visualization, routing simulation, security assessment, automated PDF reporting, and a web dashboard into a single application.

---

## Project Overview

NETWATCH is designed as a modular cybersecurity and networking project suitable for:

- College / final-year projects
- Networking and cybersecurity demonstrations
- Python portfolio projects
- GitHub portfolios
- Resume projects
- Security assessment demonstrations
- Networking laboratory work
- Technical interviews

The platform follows an observational and defensive security model.

> **Important:** NETWATCH is intended only for networks, systems, and services that you own or have explicit authorization to assess.

---

# Key Features

### 1. Network Discovery

Discovers active IPv4 hosts on an authorized network.

Features include:

- IPv4 subnet handling
- Active host discovery
- ICMP-based reachability checks
- ARP information
- MAC address discovery
- Reverse DNS / hostname resolution
- Response-time measurement
- Local network detection
- Formatted discovery results

---

### 2. Port & Service Scanning

Provides TCP and UDP port scanning capabilities.

Features include:

- Single-port scanning
- Multiple-port scanning
- Port ranges
- Common-port scanning
- Full TCP port scanning
- UDP scanning
- Port state detection
- Service identification
- Response-time measurement
- Scan statistics

Supported states include:

- OPEN
- CLOSED
- FILTERED
- UNREACHABLE
- OPEN|FILTERED

---

### 3. DNS Analysis

Performs read-only DNS analysis.

Supported record types:

- A
- AAAA
- MX
- NS
- CNAME
- TXT

Additional functionality:

- Reverse DNS lookup
- DNS response timing
- Resolver information
- DNS validation
- Structured DNS results

---

### 4. HTTP / HTTPS Analysis

Analyzes authorized web endpoints.

The analyzer checks:

- HTTP status code
- HTTPS usage
- TLS certificate validity
- Redirect behavior
- Server information
- Security headers
- Missing security headers
- Response timing

Observed security-header findings are presented as assessment observations and should be validated in context.

---

### 5. Network Traffic Analyzer

Provides packet-level traffic analysis using Scapy.

Features include:

- Live packet capture
- Configurable capture duration
- Configurable packet limit
- Protocol identification
- TCP analysis
- UDP analysis
- ICMP analysis
- DNS traffic identification
- HTTP traffic identification
- HTTPS traffic identification
- Packet counts
- Byte counts
- Source/destination information

The application analyzes captured traffic without retaining raw packet captures as persistent project state.

---

### 6. IDS / Security Detection

NETWATCH includes a rule-based intrusion detection module.

Detection rules include:

- Port scanning indicators
- Excessive connections
- Suspicious port repetitions
- Unusual connection patterns
- Suspicious protocol usage
- Abnormal traffic volume
- Repeated requests

Alerts include:

- Alert ID
- Timestamp
- Source
- Destination
- Detection type
- Description
- Severity
- Evidence
- Recommended defensive action

IDS alerts are indicators that require validation. They are not automatically treated as proof of malicious activity.

---

### 7. Firewall Analyzer

Provides read-only firewall rule analysis.

The analyzer can identify observations such as:

- Broad port ranges
- Unrestricted destinations
- Duplicate rules
- Blocked sensitive services
- Rule configuration issues

Firewall findings are rule-based observations intended for defensive review.

---

### 8. Network Topology

NETWATCH generates a network topology representation using NetworkX and Matplotlib.

The topology can represent:

```text
Internet
    |
Firewall
    |
Router
    |
+---+---+---+
|   |   |   |
PC  PC  Server