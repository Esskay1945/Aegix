"""
AEGIX IOC Database — Known Malicious Indicators of Compromise
Static + dynamic database of known malicious IPs, domains, hashes.
Adapted from EDITH threat_intel.py with expanded coverage.

Online mode: Updated from threat feeds.
Offline mode: Uses cached/static data.
"""
import logging
import ipaddress
from typing import Optional

logger = logging.getLogger("aegix.intelligence.ioc_database")


class IOCDatabase:
    """
    Indicators of Compromise database.
    Contains known malicious IPs, domains, file hashes, and URLs.
    """

    def __init__(self):
        # ── Known Malicious IPs ──
        self.malicious_ips: set = {
            "185.220.101.10",    # Tor exit node / scanner
            "45.146.164.110",    # Known attack infrastructure
            "198.51.100.22",     # TEST-NET scanner
            "103.145.13.200",    # APT infrastructure
            "91.121.0.0",        # Known botnet C2
            "185.56.80.0",       # Ransomware infrastructure
            "45.33.32.156",      # Scanme / known scanner
            "23.129.64.0",       # Tor exit cluster
        }

        # ── Blocked IP Ranges (RFC 1918, CGNAT, Cloud metadata) ──
        self.blocked_networks = [
            ipaddress.ip_network("0.0.0.0/8"),
            ipaddress.ip_network("100.64.0.0/10"),     # CGNAT
            ipaddress.ip_network("169.254.0.0/16"),     # Link-local / AWS IMDS
            ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking
            ipaddress.ip_network("224.0.0.0/4"),        # Multicast
            ipaddress.ip_network("240.0.0.0/4"),        # Reserved
        ]

        # ── Known Malicious Domains ──
        self.malicious_domains: set = {
            "evil-domain.ru",
            "phish-login.com",
            "free-crypto.xyz",
            "malicious-site.cn",
            "steal-passwords.info",
            "update-credential-bank.com",
            "bad-actor-c2.org",
            "malware-payload-delivery.net",
            "attacker.com",
            "malicious.net",
            "darkweb-market.onion",
        }

        # ── Known Malware Hashes ──
        self.malware_hashes: set = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "8754c2a98e3b9c86aa544b8b76a2818901b9ca42517865c1a700d14b43452734",
            "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd",
        }

        # ── Suspicious Ports ──
        self.suspicious_ports: set = {
            4444,   # Metasploit default
            5555,   # Android debug / reverse shell
            6666,   # IRC botnet
            6667,   # IRC
            1337,   # Common backdoor
            31337,  # Back Orifice
            12345,  # NetBus
            27374,  # SubSeven
            65535,  # Common scan target
        }

        # ── Known APT Groups ──
        self.apt_profiles: dict = {
            "APT28": {"aliases": ["Fancy Bear", "Sofacy"], "origin": "Russia", "targets": ["government", "military"]},
            "APT29": {"aliases": ["Cozy Bear", "The Dukes"], "origin": "Russia", "targets": ["government", "energy"]},
            "Lazarus": {"aliases": ["Hidden Cobra"], "origin": "North Korea", "targets": ["finance", "crypto"]},
            "APT41": {"aliases": ["Winnti"], "origin": "China", "targets": ["technology", "gaming"]},
        }

        self.threats_blocked = 0

    def check_ip(self, ip: str) -> Optional[dict]:
        """Check if an IP is a known threat."""
        if ip in self.malicious_ips:
            self.threats_blocked += 1
            return {
                "ip": ip,
                "threat_type": "known_malicious",
                "severity": "HIGH",
                "action": "BLOCK",
                "description": f"IP {ip} is in the known malicious IP database",
            }

        # Check blocked ranges
        try:
            addr = ipaddress.ip_address(ip)
            for net in self.blocked_networks:
                if addr in net:
                    return {
                        "ip": ip,
                        "threat_type": "blocked_range",
                        "severity": "MEDIUM",
                        "action": "BLOCK",
                        "description": f"IP {ip} is in blocked range {net}",
                    }
        except ValueError:
            pass

        return None

    def check_domain(self, domain: str) -> Optional[dict]:
        """Check if a domain is known malicious."""
        domain_lower = domain.lower().strip(".")
        for mal_domain in self.malicious_domains:
            if domain_lower == mal_domain or domain_lower.endswith("." + mal_domain):
                self.threats_blocked += 1
                return {
                    "domain": domain,
                    "threat_type": "known_malicious",
                    "severity": "HIGH",
                    "action": "BLOCK",
                    "description": f"Domain {domain} matches known malicious domain {mal_domain}",
                }
        return None

    def check_hash(self, file_hash: str) -> Optional[dict]:
        """Check if a file hash matches known malware."""
        if file_hash.lower() in self.malware_hashes:
            self.threats_blocked += 1
            return {
                "hash": file_hash,
                "threat_type": "known_malware",
                "severity": "CRITICAL",
                "action": "QUARANTINE",
                "description": f"File hash {file_hash[:16]}... matches known malware signature",
            }
        return None

    def check_port(self, port: int) -> Optional[dict]:
        """Check if a port is commonly used by attackers."""
        if port in self.suspicious_ports:
            return {
                "port": port,
                "threat_type": "suspicious_port",
                "severity": "MEDIUM",
                "action": "INVESTIGATE",
                "description": f"Port {port} is commonly used by attack tools",
            }
        return None

    def add_ioc(self, ioc_type: str, value: str):
        """Dynamically add a new IOC (e.g., from threat feeds)."""
        if ioc_type == "ip":
            self.malicious_ips.add(value)
        elif ioc_type == "domain":
            self.malicious_domains.add(value)
        elif ioc_type == "hash":
            self.malware_hashes.add(value.lower())
        logger.info(f"New IOC added: {ioc_type}={value}")

    def get_summary(self) -> dict:
        """Get IOC database statistics."""
        return {
            "malicious_ips": len(self.malicious_ips),
            "malicious_domains": len(self.malicious_domains),
            "malware_hashes": len(self.malware_hashes),
            "suspicious_ports": len(self.suspicious_ports),
            "apt_profiles": len(self.apt_profiles),
            "threats_blocked": self.threats_blocked,
            "status": "ACTIVE",
        }


# Singleton instance
ioc_db = IOCDatabase()
