#!/usr/bin/env python3
"""
Blockade - A Simple Packet Filtering Firewall
Author: Michael Semera
Description: Configurable firewall with JSON/XML rule support
"""

import json
import xml.etree.ElementTree as ET
import socket
import struct
import ipaddress
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class Action(Enum):
    """Firewall actions for matched packets"""
    ALLOW = "allow"
    DENY = "deny"
    LOG = "log"


class Protocol(Enum):
    """Supported network protocols"""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


@dataclass
class Packet:
    """Represents a network packet"""
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    payload_size: int
    timestamp: datetime


@dataclass
class FirewallRule:
    """Represents a single firewall rule"""
    rule_id: int
    name: str
    action: Action
    protocol: Protocol
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    priority: int = 100
    enabled: bool = True

    def matches(self, packet: Packet) -> bool:
        """Check if packet matches this rule"""
        if not self.enabled:
            return False

        # Protocol check
        if self.protocol != Protocol.ANY and self.protocol.value != packet.protocol:
            return False

        # Source IP check
        if self.src_ip and self.src_ip != "any":
            if not self._ip_matches(packet.src_ip, self.src_ip):
                return False

        # Destination IP check
        if self.dst_ip and self.dst_ip != "any":
            if not self._ip_matches(packet.dst_ip, self.dst_ip):
                return False

        # Source port check
        if self.src_port and packet.src_port != self.src_port:
            return False

        # Destination port check
        if self.dst_port and packet.dst_port != self.dst_port:
            return False

        return True

    @staticmethod
    def _ip_matches(packet_ip: str, rule_ip: str) -> bool:
        """Check if IP matches rule (supports CIDR notation)"""
        try:
            if '/' in rule_ip:
                # CIDR notation
                network = ipaddress.ip_network(rule_ip, strict=False)
                return ipaddress.ip_address(packet_ip) in network
            else:
                # Exact match
                return packet_ip == rule_ip
        except ValueError:
            return False


class RuleEngine:
    """Manages and processes firewall rules"""

    def __init__(self):
        self.rules: List[FirewallRule] = []
        self.logger = self._setup_logger()
        self.stats = {
            "packets_processed": 0,
            "packets_allowed": 0,
            "packets_denied": 0,
            "packets_logged": 0
        }

    @staticmethod
    def _setup_logger() -> logging.Logger:
        """Configure logging for firewall events"""
        logger = logging.getLogger("Blockade")
        logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler("blockade.log")
        handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger

    def load_rules_from_json(self, filepath: str) -> None:
        """Load firewall rules from JSON configuration file"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            self.rules.clear()
            for rule_data in data.get("rules", []):
                rule = FirewallRule(
                    rule_id=rule_data["id"],
                    name=rule_data["name"],
                    action=Action(rule_data["action"]),
                    protocol=Protocol(rule_data.get("protocol", "any")),
                    src_ip=rule_data.get("src_ip"),
                    dst_ip=rule_data.get("dst_ip"),
                    src_port=rule_data.get("src_port"),
                    dst_port=rule_data.get("dst_port"),
                    priority=rule_data.get("priority", 100),
                    enabled=rule_data.get("enabled", True)
                )
                self.rules.append(rule)
            
            # Sort by priority (lower number = higher priority)
            self.rules.sort(key=lambda r: r.priority)
            self.logger.info(f"Loaded {len(self.rules)} rules from {filepath}")
            
        except Exception as e:
            self.logger.error(f"Error loading JSON rules: {e}")
            raise

    def load_rules_from_xml(self, filepath: str) -> None:
        """Load firewall rules from XML configuration file"""
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            
            self.rules.clear()
            for rule_elem in root.findall("rule"):
                rule = FirewallRule(
                    rule_id=int(rule_elem.get("id")),
                    name=rule_elem.find("name").text,
                    action=Action(rule_elem.find("action").text),
                    protocol=Protocol(rule_elem.find("protocol").text),
                    src_ip=rule_elem.find("src_ip").text if rule_elem.find("src_ip") is not None else None,
                    dst_ip=rule_elem.find("dst_ip").text if rule_elem.find("dst_ip") is not None else None,
                    src_port=int(rule_elem.find("src_port").text) if rule_elem.find("src_port") is not None else None,
                    dst_port=int(rule_elem.find("dst_port").text) if rule_elem.find("dst_port") is not None else None,
                    priority=int(rule_elem.find("priority").text) if rule_elem.find("priority") is not None else 100,
                    enabled=rule_elem.get("enabled", "true").lower() == "true"
                )
                self.rules.append(rule)
            
            self.rules.sort(key=lambda r: r.priority)
            self.logger.info(f"Loaded {len(self.rules)} rules from {filepath}")
            
        except Exception as e:
            self.logger.error(f"Error loading XML rules: {e}")
            raise

    def process_packet(self, packet: Packet) -> Tuple[Action, Optional[str]]:
        """Process a packet through the firewall rules"""
        self.stats["packets_processed"] += 1
        
        # Check each rule in priority order
        for rule in self.rules:
            if rule.matches(packet):
                action = rule.action
                
                # Log the match
                log_msg = (
                    f"Rule '{rule.name}' (ID: {rule.rule_id}) matched - "
                    f"Action: {action.value.upper()} | "
                    f"{packet.protocol.upper()} {packet.src_ip}:{packet.src_port} -> "
                    f"{packet.dst_ip}:{packet.dst_port}"
                )
                
                if action == Action.ALLOW:
                    self.stats["packets_allowed"] += 1
                    self.logger.info(f"ALLOWED - {log_msg}")
                elif action == Action.DENY:
                    self.stats["packets_denied"] += 1
                    self.logger.warning(f"DENIED - {log_msg}")
                elif action == Action.LOG:
                    self.stats["packets_logged"] += 1
                    self.logger.info(f"LOGGED - {log_msg}")
                
                return action, rule.name
        
        # Default action: deny (if no rules match)
        self.stats["packets_denied"] += 1
        default_msg = (
            f"No rule matched - DEFAULT DENY | "
            f"{packet.protocol.upper()} {packet.src_ip}:{packet.src_port} -> "
            f"{packet.dst_ip}:{packet.dst_port}"
        )
        self.logger.warning(default_msg)
        return Action.DENY, "default_deny"

    def get_statistics(self) -> Dict:
        """Return firewall statistics"""
        return self.stats.copy()

    def add_rule(self, rule: FirewallRule) -> None:
        """Add a new rule to the firewall"""
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)
        self.logger.info(f"Added rule: {rule.name} (ID: {rule.rule_id})")

    def remove_rule(self, rule_id: int) -> bool:
        """Remove a rule by ID"""
        for i, rule in enumerate(self.rules):
            if rule.rule_id == rule_id:
                removed_rule = self.rules.pop(i)
                self.logger.info(f"Removed rule: {removed_rule.name} (ID: {rule_id})")
                return True
        return False

    def list_rules(self) -> List[Dict]:
        """Return a list of all rules"""
        return [
            {
                "id": rule.rule_id,
                "name": rule.name,
                "action": rule.action.value,
                "protocol": rule.protocol.value,
                "src_ip": rule.src_ip or "any",
                "dst_ip": rule.dst_ip or "any",
                "src_port": rule.src_port or "any",
                "dst_port": rule.dst_port or "any",
                "priority": rule.priority,
                "enabled": rule.enabled
            }
            for rule in self.rules
        ]


class Blockade:
    """Main firewall class"""

    def __init__(self, config_file: str = None, config_type: str = "json"):
        self.engine = RuleEngine()
        
        if config_file:
            self.load_config(config_file, config_type)

    def load_config(self, filepath: str, config_type: str = "json") -> None:
        """Load configuration from file"""
        if config_type.lower() == "json":
            self.engine.load_rules_from_json(filepath)
        elif config_type.lower() == "xml":
            self.engine.load_rules_from_xml(filepath)
        else:
            raise ValueError(f"Unsupported config type: {config_type}")

    def filter_packet(self, packet: Packet) -> bool:
        """
        Filter a packet through the firewall
        Returns True if allowed, False if denied
        """
        action, rule_name = self.engine.process_packet(packet)
        return action == Action.ALLOW

    def get_stats(self) -> Dict:
        """Get firewall statistics"""
        return self.engine.get_statistics()

    def show_rules(self) -> None:
        """Display all loaded rules"""
        rules = self.engine.list_rules()
        print("\n" + "="*80)
        print("BLOCKADE FIREWALL RULES")
        print("="*80)
        for rule in rules:
            status = "✓" if rule["enabled"] else "✗"
            print(f"\n[{status}] Rule {rule['id']}: {rule['name']}")
            print(f"    Action: {rule['action'].upper()}")
            print(f"    Protocol: {rule['protocol'].upper()}")
            print(f"    Source: {rule['src_ip']}:{rule['src_port']}")
            print(f"    Destination: {rule['dst_ip']}:{rule['dst_port']}")
            print(f"    Priority: {rule['priority']}")
        print("="*80 + "\n")


def main():
    """Demonstration of Blockade firewall"""
    print("╔════════════════════════════════════════╗")
    print("║     BLOCKADE - Simple Firewall         ║")
    print("║        by Michael Semera               ║")
    print("╚════════════════════════════════════════╝\n")

    # Create sample configuration
    sample_config = {
        "rules": [
            {
                "id": 1,
                "name": "Allow HTTP",
                "action": "allow",
                "protocol": "tcp",
                "src_ip": "any",
                "dst_ip": "any",
                "dst_port": 80,
                "priority": 10
            },
            {
                "id": 2,
                "name": "Allow HTTPS",
                "action": "allow",
                "protocol": "tcp",
                "src_ip": "any",
                "dst_ip": "any",
                "dst_port": 443,
                "priority": 10
            },
            {
                "id": 3,
                "name": "Block Suspicious Network",
                "action": "deny",
                "protocol": "any",
                "src_ip": "192.168.100.0/24",
                "dst_ip": "any",
                "priority": 5
            },
            {
                "id": 4,
                "name": "Log SSH Attempts",
                "action": "log",
                "protocol": "tcp",
                "src_ip": "any",
                "dst_ip": "any",
                "dst_port": 22,
                "priority": 20
            }
        ]
    }

    # Save sample config
    with open("blockade_config.json", "w") as f:
        json.dump(sample_config, f, indent=2)

    # Initialize firewall
    firewall = Blockade("blockade_config.json", "json")
    firewall.show_rules()

    # Test packets
    test_packets = [
        Packet("10.0.0.5", "93.184.216.34", 54321, 80, "tcp", 1024, datetime.now()),
        Packet("10.0.0.5", "93.184.216.34", 54322, 443, "tcp", 2048, datetime.now()),
        Packet("192.168.100.50", "10.0.0.1", 12345, 8080, "tcp", 512, datetime.now()),
        Packet("172.16.0.10", "10.0.0.1", 55555, 22, "tcp", 256, datetime.now()),
        Packet("10.0.0.20", "8.8.8.8", 33333, 9999, "udp", 128, datetime.now()),
    ]

    print("\nTesting packet filtering:\n")
    print("-" * 80)
    
    for i, pkt in enumerate(test_packets, 1):
        allowed = firewall.filter_packet(pkt)
        status = "✓ ALLOWED" if allowed else "✗ DENIED"
        print(f"{i}. {status} - {pkt.protocol.upper()} from {pkt.src_ip}:{pkt.src_port} "
              f"to {pkt.dst_ip}:{pkt.dst_port}")

    print("-" * 80)
    
    # Show statistics
    stats = firewall.get_stats()
    print("\n\nFirewall Statistics:")
    print("=" * 40)
    print(f"Total Packets Processed: {stats['packets_processed']}")
    print(f"Packets Allowed: {stats['packets_allowed']}")
    print(f"Packets Denied: {stats['packets_denied']}")
    print(f"Packets Logged: {stats['packets_logged']}")
    print("=" * 40)
    print("\nDetailed logs saved to: blockade.log")


if __name__ == "__main__":
    main()
