# Blockade

**A Simple, Configurable Packet Filtering Firewall**

*Author: Michael Semera*

---

## 📋 Overview

Blockade is a lightweight, educational firewall implementation that demonstrates core packet filtering concepts and rules engine design. It supports configurable rules through JSON or XML files, making it easy to define custom security policies.

## ✨ Features

- **Flexible Rule Configuration**: Load rules from JSON or XML files
- **Multiple Actions**: Allow, deny, or log packets
- **Protocol Support**: TCP, UDP, ICMP, and wildcard matching
- **CIDR Notation**: Support for network ranges (e.g., 192.168.0.0/24)
- **Priority-Based Processing**: Rules are evaluated in priority order
- **Comprehensive Logging**: All firewall events logged to file
- **Statistics Tracking**: Monitor packets processed, allowed, and denied
- **Dynamic Rule Management**: Add/remove rules at runtime

## 🚀 Quick Start

### Installation

No external dependencies required! Uses Python standard library only.

```bash
# Clone or download the project
git clone https://github.com/yourusername/blockade.git
cd blockade

# Run the demo
python blockade.py
```

### Basic Usage

```python
from blockade import Blockade, Packet
from datetime import datetime

# Initialize firewall with JSON config
firewall = Blockade("blockade_config.json", "json")

# Create a test packet
packet = Packet(
    src_ip="10.0.0.5",
    dst_ip="93.184.216.34",
    src_port=54321,
    dst_port=80,
    protocol="tcp",
    payload_size=1024,
    timestamp=datetime.now()
)

# Filter the packet
allowed = firewall.filter_packet(packet)
print(f"Packet {'allowed' if allowed else 'denied'}")

# View statistics
stats = firewall.get_stats()
print(f"Packets processed: {stats['packets_processed']}")
```

## 📝 Configuration Format

### JSON Configuration

```json
{
  "rules": [
    {
      "id": 1,
      "name": "Allow HTTP",
      "action": "allow",
      "protocol": "tcp",
      "src_ip": "any",
      "dst_ip": "any",
      "dst_port": 80,
      "priority": 10,
      "enabled": true
    },
    {
      "id": 2,
      "name": "Block Suspicious Network",
      "action": "deny",
      "protocol": "any",
      "src_ip": "192.168.100.0/24",
      "dst_ip": "any",
      "priority": 5,
      "enabled": true
    }
  ]
}
```

### XML Configuration

```xml
<?xml version="1.0" encoding="UTF-8"?>
<firewall>
  <rule id="1" enabled="true">
    <name>Allow HTTP</name>
    <action>allow</action>
    <protocol>tcp</protocol>
    <src_ip>any</src_ip>
    <dst_ip>any</dst_ip>
    <dst_port>80</dst_port>
    <priority>10</priority>
  </rule>
  <rule id="2" enabled="true">
    <name>Block Suspicious Network</name>
    <action>deny</action>
    <protocol>any</protocol>
    <src_ip>192.168.100.0/24</src_ip>
    <dst_ip>any</dst_ip>
    <priority>5</priority>
  </rule>
</firewall>
```

## 🔧 Rule Parameters

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `id` | int | Unique rule identifier | `1` |
| `name` | string | Descriptive rule name | `"Allow HTTP"` |
| `action` | enum | Action to take: `allow`, `deny`, `log` | `"allow"` |
| `protocol` | enum | Protocol: `tcp`, `udp`, `icmp`, `any` | `"tcp"` |
| `src_ip` | string | Source IP or CIDR range | `"192.168.1.0/24"` |
| `dst_ip` | string | Destination IP or CIDR range | `"10.0.0.1"` |
| `src_port` | int | Source port number | `54321` |
| `dst_port` | int | Destination port number | `80` |
| `priority` | int | Rule priority (lower = higher priority) | `10` |
| `enabled` | bool | Whether rule is active | `true` |

## 🎯 How It Works

### Packet Processing Flow

1. **Packet Reception**: A packet enters the firewall
2. **Rule Evaluation**: Rules are checked in priority order (lowest first)
3. **Match Detection**: Each rule checks if packet matches its criteria
4. **Action Execution**: First matching rule's action is executed
5. **Logging**: Event is logged with details
6. **Statistics Update**: Counters are incremented
7. **Default Deny**: If no rules match, packet is denied

### Matching Logic

A packet matches a rule if ALL of the following conditions are met:
- Rule is enabled
- Protocol matches (or rule uses "any")
- Source IP matches (or rule uses "any")
- Destination IP matches (or rule uses "any")
- Source port matches (if specified)
- Destination port matches (if specified)

## 📊 Example Use Cases

### Web Server Protection

```json
{
  "rules": [
    {
      "id": 1,
      "name": "Allow HTTP",
      "action": "allow",
      "protocol": "tcp",
      "dst_port": 80,
      "priority": 10
    },
    {
      "id": 2,
      "name": "Allow HTTPS",
      "action": "allow",
      "protocol": "tcp",
      "dst_port": 443,
      "priority": 10
    },
    {
      "id": 3,
      "name": "Block All Other Inbound",
      "action": "deny",
      "protocol": "any",
      "priority": 100
    }
  ]
}
```

### Network Segmentation

```json
{
  "rules": [
    {
      "id": 1,
      "name": "Block Guest Network to Internal",
      "action": "deny",
      "protocol": "any",
      "src_ip": "192.168.200.0/24",
      "dst_ip": "10.0.0.0/8",
      "priority": 5
    },
    {
      "id": 2,
      "name": "Allow Internal Communication",
      "action": "allow",
      "protocol": "any",
      "src_ip": "10.0.0.0/8",
      "dst_ip": "10.0.0.0/8",
      "priority": 10
    }
  ]
}
```

### SSH Monitoring

```json
{
  "rules": [
    {
      "id": 1,
      "name": "Log All SSH Attempts",
      "action": "log",
      "protocol": "tcp",
      "dst_port": 22,
      "priority": 5
    },
    {
      "id": 2,
      "name": "Allow SSH from Admin Network",
      "action": "allow",
      "protocol": "tcp",
      "src_ip": "10.1.1.0/24",
      "dst_port": 22,
      "priority": 10
    }
  ]
}
```

## 📈 Statistics and Monitoring

View real-time firewall statistics:

```python
stats = firewall.get_stats()
print(f"Processed: {stats['packets_processed']}")
print(f"Allowed: {stats['packets_allowed']}")
print(f"Denied: {stats['packets_denied']}")
print(f"Logged: {stats['packets_logged']}")
```

All firewall events are automatically logged to `blockade.log` with timestamps and details.

## 🛠️ Advanced Usage

### Dynamic Rule Management

```python
from blockade import Blockade, FirewallRule, Action, Protocol

firewall = Blockade("blockade_config.json")

# Add a new rule at runtime
new_rule = FirewallRule(
    rule_id=99,
    name="Emergency Block",
    action=Action.DENY,
    protocol=Protocol.ANY,
    src_ip="suspicious.attacker.ip",
    dst_ip=None,
    src_port=None,
    dst_port=None,
    priority=1  # Highest priority
)
firewall.engine.add_rule(new_rule)

# Remove a rule
firewall.engine.remove_rule(99)

# List all rules
rules = firewall.engine.list_rules()
for rule in rules:
    print(f"{rule['id']}: {rule['name']}")
```

## 🎓 Educational Value

Blockade demonstrates key concepts in network security:

- **Packet Inspection**: Analyzing packet headers and metadata
- **Rules Engine**: Pattern matching and policy enforcement
- **Priority Handling**: Managing rule precedence
- **Stateless Filtering**: Making decisions based on individual packets
- **Logging and Auditing**: Recording security events
- **Defense in Depth**: Layered security approach

## ⚠️ Limitations

- **Educational Purpose**: Not designed for production use
- **Stateless**: Doesn't track connection state
- **No Deep Packet Inspection**: Only examines headers
- **Limited Protocol Support**: Basic protocol handling
- **No Performance Optimization**: Not optimized for high traffic volumes

## 🔒 Security Notes

This is an educational implementation to demonstrate firewall concepts. For production environments, use established firewall solutions like:
- iptables/nftables (Linux)
- pf (BSD)
- Windows Firewall
- Commercial solutions (Palo Alto, Cisco ASA, etc.)

## 📚 Further Reading

- [Netfilter/iptables Documentation](https://netfilter.org/)
- [RFC 2979 - Firewall Requirements](https://tools.ietf.org/html/rfc2979)
- [CIDR Notation Explained](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing)

## 📄 License

This project is provided as-is for educational purposes.

## 👤 Author

**Michael Semera**

- 💼 LinkedIn: [Michael Semera](https://www.linkedin.com/in/michael-semera-586737295/)
- 🐙 GitHub: [@MichaelKS123](https://github.com/MichaelKS123)
- 📧 Email: michaelsemera15@gmail.com

---

*Blockade - Simple, clean, educational firewall implementation*