🛡️ Firebox V3: Layer 2 Deep Packet Inspection Engine

Firebox is a high-performance, low-level security appliance written in C. Unlike standard application-layer firewalls, Firebox operates at the Data Link Layer (Layer 2), utilizing raw sockets to intercept, analyze, and filter Ethernet frames before they are processed by the higher-level network stack.
🚀 Key Features

    Protocol-Agnostic Filtering: Utilizes PF_PACKET and ETH_P_ALL to capture all traffic types, including ICMP (Ping), TCP, and UDP.

    Manual Header Dissection: Bypasses standard kernel processing by manually calculating the 14-byte Ethernet offset to access the IPv4 structure.

    Live Audit Logging: Implements a professional logging system that generates ISO-8601 timestamps and source metadata for SIEM ingestion (e.g., Wazuh or Splunk).

    Real-time Threat Mitigation: Employs high-speed string comparison (strcmp) to identify and flag blacklisted identities.

🛠️ Technical Implementation Details
Packet Anatomy & Parsing

Firebox treats the network stream as raw binary data. By mapping the memory buffer to a custom ip_hdr struct, it extracts critical metadata:

    src (Source IP): Extracted via inet_ntoa from the 32-bit in_addr structure.

    dst (Destination IP): Used for egress traffic monitoring.

    Payload Inspection: Prepared for future Deep Packet Inspection (DPI) modules.

Professional Logging Schema

The logging engine is designed for forensic accountability. Each entry follows a standardized format:
[YYYY-MM-DD HH:MM:SS] ACTION: <STATUS> | SOURCE: <IP_ADDRESS>
📥 Installation & Usage
Prerequisites

    Linux-based OS (Ubuntu/Kali/Debian)

    GCC Compiler

    Root privileges (required for SOCK_RAW access)

Build Instructions
Bash

# Clone the repository
git clone https://github.com/lewiskagunya/Firebox.git

# Compile the source code
gcc -O2 firebox_v3.c -o firebox

# Execute with administrative privileges
sudo ./firebox

Testing the Engine

In a separate terminal, monitor the live alerts:
Bash

tail -f firewall_alerts.log

📅 Roadmap

    [x] Layer 2 Raw Socket Integration

    [x] Persistent File Logging

    [ ] Next: Beacon Detector Module (Temporal Analysis for C2 Detection)

    [ ] Next: Multi-IP Blacklist Support (via Linked Lists or Hash Tables)
