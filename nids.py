import scapy.all as scapy
from scapy.layers import http
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RS, ICMPv6ND_RA
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP
from scapy.layers.ipsec import ESP
from scapy.layers.l2 import GRE
import json
import os
import re
import threading
import time
from datetime import datetime
import ipaddress
import socket
import struct
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('NIDS')

class PacketCapture:
    def __init__(self, callback_log=None, callback_threat=None, callback_stats=None):
        """Initialize the packet capture system"""
        self.interface = None
        self.filter_str = ""
        self.promisc = True
        self.running = False
        self.packet_count = 0
        self.start_time = None
        
        # Callbacks for GUI integration
        self.callback_log = callback_log
        self.callback_threat = callback_threat
        self.callback_stats = callback_stats
        
        # Statistics
        self.stats = {
            "total_packets": 0,
            "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
            "active_ips": set(),
            "port_scan_detection": {},
            "dos_detection": {}
        }
        
        # Load signatures
        self.signatures_file = "signatures.json"
        self.signatures = self.load_signatures()
        
        # Blacklist
        self.blacklist_file = "blacklist.json"
        self.blacklist = self.load_blacklist()
        
        # Thread lock for thread safety
        self.lock = threading.Lock()

    def configure(self, interface, filter_str="", promisc=True):
        """Configure the packet capture settings"""
        self.interface = interface
        self.filter_str = filter_str
        self.promisc = promisc
        self.log(f"Configured capture on interface {interface} with filter '{filter_str}'", level="info")

    def load_signatures(self):
        """Load attack signatures from file"""
        try:
            if os.path.exists(self.signatures_file):
                with open(self.signatures_file, 'r') as f:
                    return json.load(f)
            else:
                # Create default signatures if file doesn't exist
                default_signatures = {
                    "sql_injection": [
                        {
                            "pattern": "SELECT.*FROM",
                            "description": "Basic SQL SELECT injection attempt",
                            "severity": "medium"
                        },
                        {
                            "pattern": "UNION.*SELECT",
                            "description": "SQL UNION injection attempt",
                            "severity": "high"
                        },
                        {
                            "pattern": "DROP.*TABLE",
                            "description": "SQL DROP TABLE attempt",
                            "severity": "critical"
                        },
                        {
                            "pattern": "INSERT.*INTO",
                            "description": "SQL INSERT injection attempt",
                            "severity": "high"
                        },
                        {
                            "pattern": "DELETE.*FROM",
                            "description": "SQL DELETE injection attempt",
                            "severity": "critical"
                        }
                    ],
                    "xss": [
                        {
                            "pattern": "<script>",
                            "description": "Basic XSS script tag",
                            "severity": "medium"
                        },
                        {
                            "pattern": "javascript:",
                            "description": "JavaScript protocol handler",
                            "severity": "medium"
                        },
                        {
                            "pattern": "onerror=",
                            "description": "XSS using onerror handler",
                            "severity": "high"
                        },
                        {
                            "pattern": "onload=",
                            "description": "XSS using onload handler",
                            "severity": "high"
                        }
                    ],
                    "port_scan": [
                        {
                            "pattern": "threshold:10:60",
                            "description": "More than 10 ports scanned in 60 seconds",
                            "severity": "medium"
                        },
                        {
                            "pattern": "threshold:50:10",
                            "description": "More than 50 ports scanned in 10 seconds",
                            "severity": "high"
                        }
                    ],
                    "dos": [
                        {
                            "pattern": "threshold:100:10",
                            "description": "More than 100 packets in 10 seconds from same source",
                            "severity": "high"
                        },
                        {
                            "pattern": "threshold:1000:60",
                            "description": "More than 1000 packets in 60 seconds from same source",
                            "severity": "critical"
                        }
                    ],
                    "command_injection": [
                        {
                            "pattern": "\\;.*\\w+",
                            "description": "Command injection with semicolon",
                            "severity": "high"
                        },
                        {
                            "pattern": "\\|.*\\w+",
                            "description": "Command injection with pipe",
                            "severity": "high"
                        },
                        {
                            "pattern": "\\&.*\\w+",
                            "description": "Command injection with ampersand",
                            "severity": "high"
                        },
                        {
                            "pattern": "\\`.*\\`",
                            "description": "Command injection with backticks",
                            "severity": "critical"
                        }
                    ],
                    "path_traversal": [
                        {
                            "pattern": "\\.\\./",
                            "description": "Directory traversal attempt",
                            "severity": "medium"
                        },
                        {
                            "pattern": "%2e%2e%2f",
                            "description": "Encoded directory traversal",
                            "severity": "medium"
                        },
                        {
                            "pattern": "\\.\\.\\\\",
                            "description": "Windows directory traversal",
                            "severity": "medium"
                        }
                    ],
                    "web_shell": [
                        {
                            "pattern": "(?:eval|exec|system|passthru)\\s*\\(",
                            "description": "PHP shell function",
                            "severity": "critical"
                        },
                        {
                            "pattern": "shell_exec\\s*\\(",
                            "description": "PHP shell_exec function",
                            "severity": "critical"
                        },
                        {
                            "pattern": "wscript\\.shell",
                            "description": "Windows script shell",
                            "severity": "critical"
                        }
                    ],
                    "buffer_overflow": [
                        {
                            "pattern": "A{1000,}",
                            "description": "Large repeated character sequence (possible buffer overflow)",
                            "severity": "high"
                        }
                    ],
                    "ldap_injection": [
                        {
                            "pattern": "\\).*\\(",
                            "description": "LDAP injection attempt",
                            "severity": "high"
                        },
                        {
                            "pattern": "\\*\\).*\\(",
                            "description": "LDAP wildcard injection",
                            "severity": "critical"
                        }
                    ],
                    "xml_injection": [
                        {
                            "pattern": "<!\\[CDATA\\[",
                            "description": "XML CDATA injection attempt",
                            "severity": "high"
                        },
                        {
                            "pattern": "<!DOCTYPE",
                            "description": "XML DOCTYPE injection attempt",
                            "severity": "high"
                        }
                    ],
                    "csrf": [
                        {
                            "pattern": "<img src=[^>]+onerror=",
                            "description": "Potential CSRF attack",
                            "severity": "medium"
                        }
                    ],
                    "ssi_injection": [
                        {
                            "pattern": "<!--#exec",
                            "description": "Server Side Include injection",
                            "severity": "critical"
                        }
                    ],
                    "file_inclusion": [
                        {
                            "pattern": "\\?[^=]+=\\.\\./",
                            "description": "Local file inclusion attempt",
                            "severity": "high"
                        },
                        {
                            "pattern": "\\?[^=]+=http[s]?://",
                            "description": "Remote file inclusion attempt",
                            "severity": "critical"
                        }
                    ]
                }
                
                with open(self.signatures_file, 'w') as f:
                    json.dump(default_signatures, f, indent=4)
                    
                return default_signatures
        except Exception as e:
            self.log(f"Error loading signatures: {str(e)}", level="error")
            return {}

    def save_signatures(self):
        """Save signatures to file"""
        try:
            with open(self.signatures_file, 'w') as f:
                json.dump(self.signatures, f, indent=4)
        except Exception as e:
            self.log(f"Error saving signatures: {str(e)}", level="error")

    def load_blacklist(self):
        """Load IP blacklist from file"""
        try:
            if os.path.exists(self.blacklist_file):
                with open(self.blacklist_file, 'r') as f:
                    return json.load(f)
            else:
                # Create empty blacklist if file doesn't exist
                with open(self.blacklist_file, 'w') as f:
                    json.dump({"ips": []}, f, indent=4)
                return {"ips": []}
        except Exception as e:
            self.log(f"Error loading blacklist: {str(e)}", level="error")
            return {"ips": []}

    def save_blacklist(self):
        """Save blacklist to file"""
        try:
            with open(self.blacklist_file, 'w') as f:
                json.dump(self.blacklist, f, indent=4)
        except Exception as e:
            self.log(f"Error saving blacklist: {str(e)}", level="error")

    def add_to_blacklist(self, ip):
        """Add an IP to the blacklist"""
        with self.lock:
            if ip not in self.blacklist["ips"]:
                self.blacklist["ips"].append(ip)
                self.save_blacklist()
                self.log(f"Added {ip} to blacklist", level="info")

    def is_blacklisted(self, ip):
        """Check if an IP is blacklisted"""
        return ip in self.blacklist["ips"]

    def add_signature(self, category, pattern, description, severity):
        """Add a new signature"""
        with self.lock:
            if category not in self.signatures:
                self.signatures[category] = []
                
            # Check if pattern already exists
            for sig in self.signatures[category]:
                if sig["pattern"] == pattern:
                    sig["description"] = description
                    sig["severity"] = severity
                    self.save_signatures()
                    return
                    
            # Add new signature
            self.signatures[category].append({
                "pattern": pattern,
                "description": description,
                "severity": severity
            })
            
            self.save_signatures()

    def delete_signature(self, category, pattern):
        """Delete a signature"""
        with self.lock:
            if category in self.signatures:
                self.signatures[category] = [sig for sig in self.signatures[category] 
                                           if sig["pattern"] != pattern]
                self.save_signatures()

    def get_signatures(self):
        """Get all signatures as a flat list"""
        result = []
        for category, sigs in self.signatures.items():
            for sig in sigs:
                result.append({
                    "category": category,
                    "pattern": sig["pattern"],
                    "description": sig["description"],
                    "severity": sig["severity"]
                })
        return result

    def start_capture(self):
        """Start packet capture"""
        if not self.interface:
            self.log("No interface specified", level="error")
            return
            
        self.running = True
        self.packet_count = 0
        self.start_time = time.time()
        
        # Reset statistics
        self.stats = {
            "total_packets": 0,
            "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
            "active_ips": set(),
            "port_scan_detection": {},
            "dos_detection": {}
        }
        
        try:
            # Handle Windows interface names
            interface_name = self.interface
            if os.name == 'nt' and ":" in self.interface:
                # Extract the interface name after the label (e.g., "Wi-Fi: Intel(R) Dual Band Wireless-AC 8260")
                interface_name = self.interface.split(":", 1)[1].strip()
                self.log(f"Using Windows interface: {interface_name}", level="info")
            
            self.log(f"Starting capture on {interface_name} with filter: {self.filter_str}", level="info")
            scapy.sniff(
                iface=interface_name,
                filter=self.filter_str,
                prn=self.process_packet,
                store=False,
                stop_filter=lambda p: not self.running
            )
        except Exception as e:
            self.log(f"Error in packet capture: {str(e)}", level="error")
            self.running = False

    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        self.log("Stopping packet capture", level="info")

    def process_packet(self, packet):
        """Process a captured packet"""
        if not self.running:
            return True
            
        with self.lock:
            self.packet_count += 1
            self.stats["total_packets"] += 1
            
            # Extract basic packet information
            src_ip = self.get_src_ip(packet)
            dst_ip = self.get_dst_ip(packet)
            protocol = self.get_protocol(packet)
            
            # Update protocol stats
            if protocol in self.stats["protocols"]:
                self.stats["protocols"][protocol] += 1
            else:
                self.stats["protocols"]["Other"] += 1
                
            # Update active IPs
            if src_ip:
                self.stats["active_ips"].add(src_ip)
            if dst_ip:
                self.stats["active_ips"].add(dst_ip)
                
            # Check blacklist
            if src_ip and self.is_blacklisted(src_ip):
                self.detect_threat({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "type": "Blacklisted IP detected",
                    "severity": "high"
                })
                
            # Detect port scanning
            if src_ip and dst_ip:
                self.detect_port_scan(src_ip, dst_ip, packet)
                
            # Detect DoS attacks
            if src_ip:
                self.detect_dos(src_ip)
                
            # Analyze packet payload for signatures
            self.analyze_payload(packet, src_ip, dst_ip, protocol)
            
            # Update stats via callback
            if self.callback_stats:
                stats_copy = {
                    "total_packets": self.stats["total_packets"],
                    "protocols": dict(self.stats["protocols"]),
                    "active_ips": list(self.stats["active_ips"])
                }
                self.callback_stats(stats_copy)
                
            # Every 100 packets, log a status update
            if self.packet_count % 100 == 0:
                elapsed = time.time() - self.start_time
                pps = self.packet_count / elapsed if elapsed > 0 else 0
                self.log(f"Captured {self.packet_count} packets ({pps:.2f} packets/sec)", level="info")
                
        return False  # Continue capturing

    def get_src_ip(self, packet):
        """Extract source IP from packet"""
        if scapy.IP in packet:
            return packet[scapy.IP].src
        return None

    def get_dst_ip(self, packet):
        """Extract destination IP from packet"""
        if scapy.IP in packet:
            return packet[scapy.IP].dst
        return None

    def get_protocol(self, packet):
        """Determine the protocol of the packet"""
        if scapy.TCP in packet:
            # Check for common TCP protocols
            tcp_port = packet[scapy.TCP].dport if packet[scapy.TCP].dport < packet[scapy.TCP].sport else packet[scapy.TCP].sport
            
            # Web protocols
            if tcp_port == 80:
                return "HTTP"
            elif tcp_port == 443:
                return "HTTPS"
            elif tcp_port == 8080:
                return "HTTP-ALT"
            elif tcp_port == 8443:
                return "HTTPS-ALT"
            
            # Remote access and file transfer
            elif tcp_port == 22:
                return "SSH"
            elif tcp_port == 23:
                return "TELNET"
            elif tcp_port == 21:
                return "FTP"
            elif tcp_port == 20:
                return "FTP-DATA"
            elif tcp_port == 989 or tcp_port == 990:
                return "FTPS"
            elif tcp_port == 3389:
                return "RDP"
            elif tcp_port == 5900:
                return "VNC"
            
            # Email protocols
            elif tcp_port == 25:
                return "SMTP"
            elif tcp_port == 587:
                return "SMTP-TLS"
            elif tcp_port == 465:
                return "SMTPS"
            elif tcp_port == 110:
                return "POP3"
            elif tcp_port == 995:
                return "POP3S"
            elif tcp_port == 143:
                return "IMAP"
            elif tcp_port == 993:
                return "IMAPS"
            
            # Database protocols
            elif tcp_port == 1433:
                return "MSSQL"
            elif tcp_port == 3306:
                return "MYSQL"
            elif tcp_port == 5432:
                return "POSTGRESQL"
            elif tcp_port == 27017 or tcp_port == 27018:
                return "MONGODB"
            elif tcp_port == 6379:
                return "REDIS"
            elif tcp_port == 1521:
                return "ORACLE"
            
            # Messaging and media
            elif tcp_port == 5222:
                return "XMPP"
            elif tcp_port == 1935:
                return "RTMP"
            elif tcp_port == 554:
                return "RTSP"
            
            # Directory services
            elif tcp_port == 389:
                return "LDAP"
            elif tcp_port == 636:
                return "LDAPS"
            
            # Version control
            elif tcp_port == 9418:
                return "GIT"
            
            # Misc/Other
            elif tcp_port == 53:
                return "DNS-TCP"
            elif tcp_port == 161:
                return "SNMP-TCP"
            elif tcp_port == 179:
                return "BGP"
            elif tcp_port == 445:
                return "SMB"
            elif tcp_port == 135 or tcp_port == 137 or tcp_port == 138 or tcp_port == 139:
                return "NETBIOS"
            elif tcp_port == 1194:
                return "OPENVPN"
            elif tcp_port == 1723:
                return "PPTP"
            elif tcp_port == 5061 or tcp_port == 5060:
                return "SIP"
            
            # IoT and Industrial protocols
            elif tcp_port == 1883 or tcp_port == 8883:
                return "MQTT"
            elif tcp_port == 502:
                return "MODBUS"
            elif tcp_port == 44818:
                return "ETHERNET/IP"
            
            else:
                return "TCP"
        
        elif scapy.UDP in packet:
            # Check for common UDP protocols
            udp_port = packet[scapy.UDP].dport if packet[scapy.UDP].dport < packet[scapy.UDP].sport else packet[scapy.UDP].sport
            
            # Common UDP protocols
            if udp_port == 53:
                return "DNS"
            elif udp_port == 67 or udp_port == 68:
                return "DHCP"
            elif udp_port == 69:
                return "TFTP"
            elif udp_port == 123:
                return "NTP"
            elif udp_port == 161:
                return "SNMP"
            elif udp_port == 162:
                return "SNMPTRAP"
            elif udp_port == 500:
                return "IPSEC"
            elif udp_port == 514:
                return "SYSLOG"
            elif udp_port == 520:
                return "RIP"
            elif udp_port == 1194:
                return "OPENVPN-UDP"
            elif udp_port == 1701:
                return "L2TP"
            elif udp_port == 1812 or udp_port == 1813:
                return "RADIUS"
            elif udp_port == 1900:
                return "SSDP"
            elif udp_port == 4500:
                return "IPSEC-NAT"
            elif udp_port == 5353:
                return "MDNS"
            elif udp_port == 5060 or udp_port == 5061:
                return "SIP-UDP"
            
            # Voice and video
            elif (udp_port >= 10000 and udp_port <= 20000) or (udp_port >= 16384 and udp_port <= 32767):
                return "RTP/VOIP"
            
            # Gaming protocols
            elif udp_port == 3074:
                return "XBOX-LIVE"
            elif udp_port == 3478 or udp_port == 3479:
                return "STUN/TURN"
            
            else:
                return "UDP"
        
        # Other common protocols
        elif scapy.ICMP in packet:
            icmp_type = packet[scapy.ICMP].type
            if icmp_type == 0:
                return "ICMP-ECHO-REPLY"
            elif icmp_type == 3:
                return "ICMP-DEST-UNREACH"
            elif icmp_type == 5:
                return "ICMP-REDIRECT"
            elif icmp_type == 8:
                return "ICMP-ECHO"
            elif icmp_type == 11:
                return "ICMP-TIME-EXCEEDED"
            else:
                return "ICMP"
        
        elif scapy.ARP in packet:
            if packet[scapy.ARP].op == 1:
                return "ARP-REQUEST"
            elif packet[scapy.ARP].op == 2:
                return "ARP-REPLY"
            else:
                return "ARP"
        
        elif scapy.DNS in packet:
            return "DNS"
        
        elif scapy.DHCP in packet:
            return "DHCP"
        
        elif scapy.IPv6 in packet:
            if scapy.ICMPv6EchoRequest in packet:
                return "ICMPv6-ECHO-REQUEST"
            elif scapy.ICMPv6EchoReply in packet:
                return "ICMPv6-ECHO-REPLY"
            elif scapy.ICMPv6ND_NS in packet:
                return "ICMPv6-ND-NS"
            elif scapy.ICMPv6ND_NA in packet:
                return "ICMPv6-ND-NA"
            elif scapy.ICMPv6ND_RS in packet:
                return "ICMPv6-ND-RS"
            elif scapy.ICMPv6ND_RA in packet:
                return "ICMPv6-ND-RA"
            else:
                return "IPv6"
        
        # VPN and tunneling protocols
        elif packet.haslayer(scapy.GRE):
            return "GRE"
        
        elif packet.haslayer(scapy.ESP):
            return "IPSEC-ESP"
        
        else:
            return "Other"

    def detect_port_scan(self, src_ip, dst_ip, packet):
        """Detect potential port scanning activity"""
        # Initialize tracking for this source IP if not exists
        if src_ip not in self.stats["port_scan_detection"]:
            self.stats["port_scan_detection"][src_ip] = {
                "targets": {},
                "last_reset": time.time()
            }
            
        # Reset counters if time window has passed
        current_time = time.time()
        if current_time - self.stats["port_scan_detection"][src_ip]["last_reset"] > 60:
            self.stats["port_scan_detection"][src_ip]["targets"] = {}
            self.stats["port_scan_detection"][src_ip]["last_reset"] = current_time
            
        # Track destination ports for each target
        if dst_ip not in self.stats["port_scan_detection"][src_ip]["targets"]:
            self.stats["port_scan_detection"][src_ip]["targets"][dst_ip] = set()
            
        # Add destination port if TCP or UDP
        if scapy.TCP in packet:
            self.stats["port_scan_detection"][src_ip]["targets"][dst_ip].add(packet[scapy.TCP].dport)
        elif scapy.UDP in packet:
            self.stats["port_scan_detection"][src_ip]["targets"][dst_ip].add(packet[scapy.UDP].dport)
            
        # Check for port scan threshold
        for target, ports in self.stats["port_scan_detection"][src_ip]["targets"].items():
            if len(ports) >= 10:  # Threshold from signature
                self.detect_threat({
                    "src_ip": src_ip,
                    "dst_ip": target,
                    "protocol": "Multiple",
                    "type": "Port Scan Detected",
                    "details": f"Scanned {len(ports)} ports in 60 seconds",
                    "severity": "medium"
                })
                # Reset after detection to avoid repeated alerts
                self.stats["port_scan_detection"][src_ip]["targets"][target] = set()

    def detect_dos(self, src_ip):
        """Detect potential DoS attacks"""
        # Initialize tracking for this source IP if not exists
        if src_ip not in self.stats["dos_detection"]:
            self.stats["dos_detection"][src_ip] = {
                "count": 0,
                "first_packet": time.time(),
                "alerted": False
            }
        # Update packet count
        self.stats["dos_detection"][src_ip]["count"] += 1
        
        # Check time window
        current_time = time.time()
        time_window = current_time - self.stats["dos_detection"][src_ip]["first_packet"]
        
        # If time window exceeded, reset counter
        if time_window > 10:  # 10 seconds window from signature
            self.stats["dos_detection"][src_ip] = {
                "count": 1,
                "first_packet": current_time,
                "alerted": False
            }
        # Check for DoS threshold
        elif (self.stats["dos_detection"][src_ip]["count"] > 100 and  # Threshold from signature
              not self.stats["dos_detection"][src_ip]["alerted"]):
            self.detect_threat({
                "src_ip": src_ip,
                "dst_ip": "Multiple",
                "protocol": "Multiple",
                "type": "Potential DoS Attack",
                "details": f"{self.stats['dos_detection'][src_ip]['count']} packets in {time_window:.2f} seconds",
                "severity": "high"
            })
            self.stats["dos_detection"][src_ip]["alerted"] = True

    def analyze_payload(self, packet, src_ip, dst_ip, protocol):
        """Analyze packet payload for attack signatures"""
        # Extract payload
        payload = self.extract_payload(packet)
        if not payload:
            return
            
        # Check against signatures
        for category, signatures in self.signatures.items():
            # Skip port_scan and dos categories as they're handled separately
            if category in ["port_scan", "dos"]:
                continue
                
            for signature in signatures:
                pattern = signature["pattern"]
                try:
                    if re.search(pattern, payload, re.IGNORECASE):
                        self.detect_threat({
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "protocol": protocol,
                            "type": f"{category.replace('_', ' ').title()} Attack",
                            "details": signature["description"],
                            "severity": signature["severity"]
                        })
                except Exception as e:
                    self.log(f"Error matching pattern {pattern}: {str(e)}", level="error")

    def extract_payload(self, packet):
        """Extract payload from packet"""
        # HTTP payload
        if packet.haslayer(http.HTTPRequest):
            return str(bytes(packet[http.HTTPRequest]))
            
        # TCP payload
        if scapy.TCP in packet and packet[scapy.TCP].payload:
            return str(bytes(packet[scapy.TCP].payload))
            
        # UDP payload
        if scapy.UDP in packet and packet[scapy.UDP].payload:
            return str(bytes(packet[scapy.UDP].payload))
            
        # Raw payload as fallback
        if scapy.Raw in packet:
            return str(bytes(packet[scapy.Raw]))
            
        return None

    def detect_threat(self, threat_data):
        """Handle a detected threat"""
        # Log the threat
        self.log(f"THREAT: {threat_data['type']} from {threat_data['src_ip']} to {threat_data['dst_ip']}", 
                level="warning")
                
        # Call the threat callback if provided
        if self.callback_threat:
            self.callback_threat(threat_data)

    def log(self, message, level="info"):
        """Log a message"""
        # Log to standard logger
        if level == "info":
            logger.info(message)
        elif level == "warning":
            logger.warning(message)
        elif level == "error":
            logger.error(message)
        elif level == "critical":
            logger.critical(message)
            
        # Call the log callback if provided
        if self.callback_log:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.callback_log({
                "timestamp": timestamp,
                "level": level,
                "message": message
            })
    
    def get_interfaces(self):
        """Get a list of available network interfaces"""
        try:
            interfaces = scapy.get_if_list()
            # Format for display
            formatted_interfaces = []
            for iface in interfaces:
                ip = scapy.get_if_addr(iface)
                formatted_interfaces.append(f"{iface}: {ip}")
            return formatted_interfaces
        except Exception as e:
            self.log(f"Error getting interfaces: {str(e)}", level="error")
            return []
    
    def get_stats(self):
        """Get current statistics"""
        with self.lock:
            stats_copy = {
                "total_packets": self.stats["total_packets"],
                "protocols": dict(self.stats["protocols"]),
                "active_ips": list(self.stats["active_ips"]),
                "running_time": time.time() - self.start_time if self.start_time else 0,
                "packets_per_second": self.packet_count / (time.time() - self.start_time) if self.start_time and time.time() - self.start_time > 0 else 0
            }
            return stats_copy
    
    def get_blacklist(self):
        """Get the current blacklist"""
        return self.blacklist["ips"]
    
    def remove_from_blacklist(self, ip):
        """Remove an IP from the blacklist"""
        with self.lock:
            if ip in self.blacklist["ips"]:
                self.blacklist["ips"].remove(ip)
                self.save_blacklist()
                self.log(f"Removed {ip} from blacklist", level="info")
    
    def clear_blacklist(self):
        """Clear all IPs from the blacklist"""
        with self.lock:
            self.blacklist["ips"] = []
            self.save_blacklist()
            self.log("Cleared blacklist", level="info")

# Example usage of the NIDS system
if __name__ == "__main__":
    def log_callback(log_data):
        print(f"[{log_data['timestamp']}] {log_data['level'].upper()}: {log_data['message']}")
    
    def threat_callback(threat_data):
        print(f"THREAT DETECTED: {threat_data['type']} ({threat_data['severity']})")
        print(f"Source: {threat_data['src_ip']} -> Destination: {threat_data['dst_ip']}")
        if 'details' in threat_data:
            print(f"Details: {threat_data['details']}")
        print("-" * 50)
    
    def stats_callback(stats):
        print(f"\nStatistics Update:")
        print(f"Total Packets: {stats['total_packets']}")
        print(f"Protocol Distribution: {stats['protocols']}")
        print(f"Active IPs: {len(stats['active_ips'])}")
        print("-" * 50)
    
    # Create and configure the packet capture
    capture = PacketCapture(
        callback_log=log_callback,
        callback_threat=threat_callback,
        callback_stats=stats_callback
    )
    
    # List available interfaces
    interfaces = capture.get_interfaces()
    print("Available interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i+1}. {iface}")
    
    # Get user input for interface
    try:
        iface_idx = int(input("\nSelect interface (number): ")) - 1
        selected_interface = interfaces[iface_idx].split(":")[0].strip()
        
        # Configure and start capture
        capture.configure(interface=selected_interface, filter_str="", promisc=True)
        
        print(f"\nStarting packet capture on {selected_interface}...")
        print("Press Ctrl+C to stop\n")
        
        # Start capture in a separate thread
        capture_thread = threading.Thread(target=capture.start_capture)
        capture_thread.daemon = True
        capture_thread.start()
        
        # Keep the main thread running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping capture...")
            capture.stop_capture()
            capture_thread.join(timeout=2)
            print("Capture stopped")
            
    except (IndexError, ValueError) as e:
        print(f"Error selecting interface: {str(e)}")
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        # Ensure we stop capturing if an exception occurs
        if capture.running:
            capture.stop_capture()