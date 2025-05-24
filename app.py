#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import time
import asyncio
import aiohttp
import json
from scapy.all import ARP, Ether, srp, ICMP, IP, sniff, TCP, UDP, DNS, DNSQR, DNSRR
import ipaddress
import socket
import netifaces
from datetime import datetime, timedelta, timezone
import logging
from concurrent.futures import ThreadPoolExecutor
import sys
import os
import platform
import subprocess
import re
import nmap
import psutil
import requests
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
import sqlite3
from dataclasses import dataclass
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///network_scanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s',
    handlers=[
        logging.FileHandler('network_security.log'),
        logging.StreamHandler(sys.stdout)  # Explicitly use stdout for console output
    ]
)
logger = logging.getLogger(__name__)

# Add color to console output
class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for different log levels."""
    grey = "\x1b[38;21m"
    blue = "\x1b[38;5;39m"
    yellow = "\x1b[38;5;226m"
    red = "\x1b[38;5;196m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"

    def __init__(self, fmt):
        super().__init__()
        self.fmt = fmt
        self.FORMATS = {
            logging.DEBUG: self.grey + self.fmt + self.reset,
            logging.INFO: self.blue + self.fmt + self.reset,
            logging.WARNING: self.yellow + self.fmt + self.reset,
            logging.ERROR: self.red + self.fmt + self.reset,
            logging.CRITICAL: self.bold_red + self.fmt + self.reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# Apply colored formatter to console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(ColoredFormatter('%(asctime)s - %(levelname)s - [%(name)s] - %(message)s'))
logger.addHandler(console_handler)

# Global variables
scanning = False
scan_thread = None
monitoring = False
monitor_thread = None
executor = ThreadPoolExecutor(max_workers=10)
auto_scan_interval = 300  # 5 minutes
last_scan_time = None
known_devices = {}
security_events = deque(maxlen=1000)  # Son 1000 güvenlik olayını tut
traffic_stats = defaultdict(lambda: {'bytes': 0, 'packets': 0, 'last_seen': None})
suspicious_ips = set()
known_ports = defaultdict(set)  # Her IP için bilinen portlar
connection_patterns = defaultdict(lambda: {'connections': 0, 'bytes': 0, 'last_reset': time.time()})
threat_intel_cache = {}

# CVE API ve cache için global değişkenler
CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOIT_DB_API = "https://www.exploit-db.com/search"
VULNDB_API = "https://vuldb.com/?api"
CVE_CACHE = {}
CVE_CACHE_EXPIRY = timedelta(hours=24)
NVD_API_KEY = os.getenv('NVD_API_KEY', '7a27e323-551b-4cb9-9797-f6159d286574')  # NVD API key'i environment variable'dan al veya varsayılan değeri kullan

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship('Scan', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='running')
    devices = db.relationship('Device', backref='scan', lazy=True)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    ip = db.Column(db.String(15), nullable=False)
    mac = db.Column(db.String(17))
    vendor = db.Column(db.String(100))
    hostname = db.Column(db.String(100))
    os_info = db.Column(db.Text)  # JSON string
    open_ports = db.Column(db.Text)  # JSON string
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    vulnerabilities = db.Column(db.Text)  # JSON string

class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    event_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    source_ip = db.Column(db.String(15))
    destination_ip = db.Column(db.String(15))
    details = db.Column(db.Text)  # JSON string

# Create database tables
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@dataclass
class SecurityEvent:
    timestamp: datetime
    event_type: str
    severity: str
    source_ip: str
    destination_ip: str
    details: Dict
    hash: str = None

    def __post_init__(self):
        if not self.hash:
            event_str = f"{self.timestamp}{self.event_type}{self.source_ip}{self.destination_ip}{json.dumps(self.details)}"
            self.hash = hashlib.sha256(event_str.encode()).hexdigest()

@dataclass
class Vulnerability:
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: str
    affected_products: List[str]
    published_date: str
    last_modified_date: str
    exploit_available: bool
    exploit_urls: List[str]
    remediation_steps: List[str]
    risk_score: float
    attack_complexity: str
    attack_vector: str
    privileges_required: str
    user_interaction: str
    scope: str
    confidentiality_impact: str
    integrity_impact: str
    availability_impact: str
    references: List[Dict[str, str]]
    tags: List[str]

def init_database():
    """Initialize SQLite database for security events."""
    conn = sqlite3.connect('security_events.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS security_events
                 (timestamp TEXT, event_type TEXT, severity TEXT, 
                  source_ip TEXT, destination_ip TEXT, details TEXT, hash TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS device_history
                 (ip TEXT, mac TEXT, hostname TEXT, first_seen TEXT, 
                  last_seen TEXT, status TEXT, vendor TEXT)''')
    conn.commit()
    conn.close()

def log_security_event(event: SecurityEvent):
    """Log security event to database and memory with enhanced console output."""
    security_events.append(event)
    
    # Enhanced console logging
    severity_colors = {
        'low': '\x1b[38;5;39m',    # Blue
        'medium': '\x1b[38;5;226m', # Yellow
        'high': '\x1b[38;5;196m',   # Red
        'critical': '\x1b[31;1m'    # Bold Red
    }
    color = severity_colors.get(event.severity, '\x1b[0m')
    reset = '\x1b[0m'
    
    logger.warning(f"{color}Security Event Detected:{reset}")
    logger.warning(f"{color}├─ Type: {event.event_type}{reset}")
    logger.warning(f"{color}├─ Severity: {event.severity}{reset}")
    logger.warning(f"{color}├─ Source IP: {event.source_ip}{reset}")
    logger.warning(f"{color}├─ Destination IP: {event.destination_ip}{reset}")
    logger.warning(f"{color}└─ Details: {json.dumps(event.details, indent=2)}{reset}")
    
    # Log to database
    conn = sqlite3.connect('security_events.db')
    c = conn.cursor()
    c.execute('''INSERT INTO security_events 
                 (timestamp, event_type, severity, source_ip, destination_ip, details, hash)
                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
              (event.timestamp.isoformat(), event.event_type, event.severity,
               event.source_ip, event.destination_ip, json.dumps(event.details), event.hash))
    conn.commit()
    conn.close()
    
    # Emit to connected clients
    socketio.emit('security_event', {
        'timestamp': event.timestamp.isoformat(),
        'event_type': event.event_type,
        'severity': event.severity,
        'source_ip': event.source_ip,
        'destination_ip': event.destination_ip,
        'details': event.details
    })

def check_threat_intel(ip: str) -> Dict:
    """Check IP against threat intelligence sources."""
    if ip in threat_intel_cache:
        return threat_intel_cache[ip]
    
    try:
        # AbuseIPDB API (requires API key)
        # url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        # headers = {'Key': 'YOUR_API_KEY', 'Accept': 'application/json'}
        # response = requests.get(url, headers=headers)
        
        # For now, use a simple heuristic
        threat_info = {
            'score': 0,
            'reputation': 'unknown',
            'categories': [],
            'last_updated': datetime.now().isoformat()
        }
        
        # Check if IP is in private range
        if ipaddress.ip_address(ip).is_private:
            threat_info['reputation'] = 'private'
        else:
            # Check for known malicious patterns
            if ip in suspicious_ips:
                threat_info['score'] = 80
                threat_info['reputation'] = 'suspicious'
                threat_info['categories'].append('suspicious_activity')
        
        threat_intel_cache[ip] = threat_info
        return threat_info
    except Exception as e:
        logger.error(f"Error checking threat intel for {ip}: {e}")
        return {'score': 0, 'reputation': 'unknown', 'categories': [], 'last_updated': datetime.now().isoformat()}

def detect_anomalies(packet):
    """Detect anomalous network behavior."""
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Update traffic stats
            traffic_stats[src_ip]['bytes'] += len(packet)
            traffic_stats[src_ip]['packets'] += 1
            traffic_stats[src_ip]['last_seen'] = datetime.now()
            
            # Check for port scanning
            if TCP in packet:
                dst_port = packet[TCP].dport
                if packet[TCP].flags == 2:  # SYN flag
                    known_ports[dst_ip].add(dst_port)
                    if len(known_ports[dst_ip]) > 10:  # Port scanning threshold
                        event = SecurityEvent(
                            timestamp=datetime.now(),
                            event_type='port_scan',
                            severity='high',
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            details={'ports': list(known_ports[dst_ip])}
                        )
                        log_security_event(event)
                        suspicious_ips.add(src_ip)
            
            # Check for DNS tunneling attempts
            if DNS in packet and DNSQR in packet:
                query = packet[DNSQR].qname.decode()
                if len(query) > 100:  # Suspiciously long DNS query
                    event = SecurityEvent(
                        timestamp=datetime.now(),
                        event_type='dns_tunneling',
                        severity='medium',
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        details={'query': query}
                    )
                    log_security_event(event)
            
            # Check for connection flooding
            connection_patterns[src_ip]['connections'] += 1
            if time.time() - connection_patterns[src_ip]['last_reset'] > 60:  # Reset every minute
                if connection_patterns[src_ip]['connections'] > 1000:  # Connection flood threshold
                    event = SecurityEvent(
                        timestamp=datetime.now(),
                        event_type='connection_flood',
                        severity='high',
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        details={'connections': connection_patterns[src_ip]['connections']}
                    )
                    log_security_event(event)
                    suspicious_ips.add(src_ip)
                connection_patterns[src_ip] = {'connections': 0, 'bytes': 0, 'last_reset': time.time()}
            
            # Check threat intelligence
            threat_info = check_threat_intel(src_ip)
            if threat_info['score'] > 70:
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    event_type='suspicious_ip',
                    severity='high',
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    details=threat_info
                )
                log_security_event(event)
    
    except Exception as e:
        logger.error(f"Error in anomaly detection: {e}")

def start_monitoring():
    """Start network traffic monitoring."""
    global monitoring, monitor_thread
    
    if not monitoring:
        monitoring = True
        monitor_thread = threading.Thread(target=lambda: sniff(prn=detect_anomalies, store=0))
        monitor_thread.daemon = True
        monitor_thread.start()
        logger.info("Network monitoring started")

def stop_monitoring():
    """Stop network traffic monitoring."""
    global monitoring
    monitoring = False
    logger.info("Network monitoring stopped")

def get_local_ip():
    """Get the local IP address of the machine."""
    try:
        # Get the default gateway interface
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][1]
        
        # Get the IP address of that interface
        interface_info = netifaces.ifaddresses(default_gateway)
        return interface_info[netifaces.AF_INET][0]['addr']
    except Exception as e:
        logger.error(f"Error getting local IP: {e}")
        return None

def get_network_range():
    """Get the network range based on the local IP."""
    try:
        local_ip = get_local_ip()
        if not local_ip:
            return None
        
        # Get the network interface
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][1]
        interface_info = netifaces.ifaddresses(default_gateway)
        
        # Get the netmask
        netmask = interface_info[netifaces.AF_INET][0]['netmask']
        
        # Calculate network address
        network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
        return str(network)
    except Exception as e:
        logger.error(f"Error getting network range: {e}")
        return None

async def scan_port(ip, port, timeout=1):
    """Scan a single port on a device."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://{ip}:{port}", timeout=timeout) as response:
                return port, response.status
    except:
        return port, None

async def scan_device_ports(ip):
    """Scan common ports on a device using a faster approach."""
    common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080]
    open_ports = []
    
    # Use ThreadPoolExecutor for parallel port scanning
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  # Reduced timeout
            result = sock.connect_ex((ip, port))
            sock.close()
            return port if result == 0 else None
        except:
            return None
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_port, port) for port in common_ports]
        for future in futures:
            port = future.result()
            if port is not None:
                open_ports.append(port)
    
    return open_ports

def get_os_info(ip: str) -> Dict:
    """Get operating system information using nmap."""
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-O --osscan-guess')
        
        if ip in nm.all_hosts():
            os_info = nm[ip].get('osmatch', [])
            if os_info:
                return {
                    'os_name': os_info[0].get('name', 'Unknown'),
                    'os_accuracy': os_info[0].get('accuracy', '0'),
                    'os_type': os_info[0].get('osclass', [{}])[0].get('type', 'Unknown'),
                    'os_vendor': os_info[0].get('osclass', [{}])[0].get('vendor', 'Unknown')
                }
    except Exception as e:
        logger.error(f"Error getting OS info for {ip}: {e}")
    return {'os_name': 'Unknown', 'os_accuracy': '0', 'os_type': 'Unknown', 'os_vendor': 'Unknown'}

def get_system_users(ip: str) -> List[str]:
    """Get system users using various methods."""
    users = []
    try:
        # Try to get users via SMB
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-p445 --script smb-enum-users')
        
        if ip in nm.all_hosts():
            script_output = nm[ip].get('tcp', {}).get(445, {}).get('script', {})
            if 'smb-enum-users' in script_output:
                output = script_output['smb-enum-users']
                # Parse nmap output for usernames
                user_matches = re.findall(r'\| (\w+) \|', output)
                users.extend(user_matches)
        
        # Try to get users via SSH
        nm.scan(ip, arguments='-p22 --script ssh-auth-methods')
        if ip in nm.all_hosts():
            script_output = nm[ip].get('tcp', {}).get(22, {}).get('script', {})
            if 'ssh-auth-methods' in script_output:
                output = script_output['ssh-auth-methods']
                # Parse nmap output for usernames
                user_matches = re.findall(r'(\w+):', output)
                users.extend(user_matches)
    
    except Exception as e:
        logger.error(f"Error getting users for {ip}: {e}")
    
    return list(set(users))  # Remove duplicates

def get_device_vendor(mac: str) -> str:
    """Get device vendor from MAC address."""
    try:
        # Remove separators and convert to uppercase
        mac = mac.replace(':', '').replace('-', '').upper()
        # Get first 6 characters (OUI)
        oui = mac[:6]
        
        # Try to get vendor from local database first
        vendor = get_vendor_from_local_db(oui)
        if vendor:
            return vendor
        
        # If not found locally, try online lookup
        url = f"https://api.macvendors.com/{oui}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text
    except Exception as e:
        logger.error(f"Error getting vendor for MAC {mac}: {e}")
    return "Unknown"

def get_vendor_from_local_db(oui: str) -> Optional[str]:
    """Get vendor from local database."""
    # This is a simplified version. In a real application, you would use a proper database
    common_vendors = {
        '00000C': 'Cisco Systems',
        '00000E': 'Fujitsu',
        '000001': 'Xerox Corporation',
        '000002': 'Xerox Corporation',
        '000003': 'Xerox Corporation',
        '000004': 'Xerox Corporation',
        '000005': 'Xerox Corporation',
        '000006': 'Xerox Corporation',
        '000007': 'Xerox Corporation',
        '000008': 'Xerox Corporation',
        '000009': 'Xerox Corporation',
        '00000A': 'Omron Tateisi Electronics',
        '00000B': 'Matrix Corporation',
        '00000D': 'Fibronics Ltd.',
        '00000F': 'Next, Inc.',
        '000010': 'Sytek Inc.',
        '000011': 'Normerel Systemes',
        '000012': 'Information Technology Limited',
        '000013': 'Camex',
        '000014': 'Netronix',
        '000015': 'Datapoint Corporation',
        '000016': 'Du Pont Pixel Systems',
        '000017': 'Oracle Corporation',
        '000018': 'Webster Computer Corporation',
        '000019': 'Applied Dynamics International',
        '00001A': 'Advanced Micro Devices',
        '00001B': 'Novell Inc.',
        '00001C': 'Bell Technologies',
        '00001D': 'Cabletron Systems, Inc.',
        '00001E': 'Telsist Industria Electronica',
        '00001F': 'Telco Systems, Inc.',
        '000020': 'Dataindustrier Diab AB',
        '000021': 'Sureman COMP. & Commun.',
        '000022': 'Visual Technology Inc.',
        '000023': 'ABB INDUSTRIAL SYSTEMS AB',
        '000024': 'Connect AS',
        '000025': 'Ramtek Corporation',
        '000026': 'SHA-KEN CO., LTD.',
        '000027': 'Japan Radio Company',
        '000028': 'Prodigy Systems Corporation',
        '000029': 'IMC NETWORKS CORP.',
        '00002A': 'TRW - SEDD/INP',
        '00002B': 'CRISP AUTOMATION, INC',
        '00002C': 'Autotote Limited',
        '00002D': 'CHROMATICS INC',
        '00002E': 'SOCIETE EVIRA',
        '00002F': 'TIMEPLEX INC.',
        '000030': 'VG LABORATORY SYSTEMS LTD',
        '000031': 'QPSX COMMUNICATIONS PTY LTD',
        '000032': 'Marconi plc',
        '000033': 'EGAN MACHINERY COMPANY',
        '000034': 'NETWORK RESOURCES CORP',
        '000035': 'SPECTRAGRAPHICS CORPORATION',
        '000036': 'ATARI CORPORATION',
        '000037': 'OXFORD METRICS LIMITED',
        '000038': 'CSS LABS',
        '000039': 'TOSHIBA CORPORATION',
        '00003A': 'CHYRON CORPORATION',
        '00003B': 'i Controls, Inc.',
        '00003C': 'AUSPEX SYSTEMS INC.',
        '00003D': 'UNISYS',
        '00003E': 'SIMPACT',
        '00003F': 'SYTEK INC.',
        '000040': 'PIPER COMMUNICATIONS',
        '000041': 'NETWORK COMPUTING DEVICES INC',
        '000042': 'XEROX CORPORATION',
        '000043': 'DENSAN CO., LTD.',
        '000044': 'ICL DATA OY',
        '000045': 'HAKUSAN CORPORATION',
        '000046': 'FILENET CORPORATION',
        '000047': 'MICROFIVE CORPORATION',
        '000048': 'TRANSITION NETWORKS',
        '000049': 'INTERLAN COMMUNICATIONS CORP.',
        '00004A': 'NETWORK SYSTEMS CORP.',
        '00004B': 'LITTLE MACHINES INC.',
        '00004C': 'TECNETICS (PTY) LTD.',
        '00004D': 'SUPERNET',
        '00004E': 'CANON INC.',
        '00004F': 'MEGAHERTZ CORPORATION'
    }
    return common_vendors.get(oui, None)

async def get_device_info(ip: str) -> Optional[Dict]:
    """Get detailed information about a device with optimized scanning."""
    try:
        # Get hostname (with timeout)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"
        
        # Get MAC address using ARP with reduced timeout
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        start_time = time.time()
        result = srp(packet, timeout=1, verbose=0)[0]
        response_time = int((time.time() - start_time) * 1000)
        
        if result:
            mac = result[0][1].hwsrc
            vendor = get_device_vendor(mac)
        else:
            mac = "Unknown"
            vendor = "Unknown"
        
        # Get OS information (only if we have a MAC address)
        os_info = {'os_name': 'Unknown', 'os_accuracy': '0', 'os_type': 'Unknown', 'os_vendor': 'Unknown'}
        if mac != "Unknown":
            try:
                os_info = get_os_info(ip)
            except:
                pass
        
        # Scan ports in parallel
        open_ports = await scan_device_ports(ip)
        
        return {
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'vendor': vendor,
            'os_info': os_info,
            'response_time': response_time,
            'open_ports': open_ports,
            'last_seen': datetime.now(timezone.utc).isoformat(),
            'status': 'online'
        }
    except Exception as e:
        logger.error(f"Error getting device info for {ip}: {e}")
        return None

async def scan_batch(ip_batch):
    """Scan a batch of IP addresses in parallel."""
    tasks = []
    for ip in ip_batch:
        task = asyncio.create_task(get_device_info(ip))
        tasks.append(task)
    return await asyncio.gather(*tasks, return_exceptions=True)

async def quick_arp_scan(network):
    """
    Perform a quick ARP scan using arp-scan command asynchronously.
    Returns a list of dictionaries containing device information.
    """
    devices = []
    try:
        logger.info("🔍 Starting ARP scan...")
        socketio.emit('scan_status', {
            'message': 'Starting ARP scan...',
            'type': 'info'
        })

        # Run arp-scan command asynchronously
        process = await asyncio.create_subprocess_exec(
            'arp-scan',
            '--localnet',
            '--ignoredups',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            if process.returncode == 1:  # arp-scan not found
                logger.error("❌ arp-scan command not found. Please install it using: sudo pacman -S arp-scan")
                raise FileNotFoundError("arp-scan command not found")
            else:
                logger.error(f"❌ Error running arp-scan: {stderr.decode()}")
                raise RuntimeError(f"arp-scan failed: {stderr.decode()}")
        
        # Process output line by line
        for line in stdout.decode().splitlines():
            # Skip empty lines and non-device lines
            if (not line.strip() or 
                'Interface:' in line or 
                'Starting' in line or 
                'Ending' in line or 
                'packets received' in line or 
                'packets dropped' in line):
                continue
                
            try:
                # Parse the line (format: IP MAC Vendor)
                parts = line.split()
                if len(parts) >= 2:  # At least IP and MAC
                    ip = parts[0]
                    mac = parts[1]
                    vendor = ' '.join(parts[2:]) if len(parts) > 2 else 'Unknown'
                    
                    # Create basic device info
                    device = {
                        'ip': ip,
                        'mac': mac,
                        'vendor': vendor,
                        'hostname': 'Unknown',
                        'os_info': {'os_name': 'Unknown', 'os_accuracy': '0', 'os_type': 'Unknown', 'os_vendor': 'Unknown'},
                        'open_ports': [],
                        'last_seen': datetime.now().isoformat(),
                        'status': 'online'
                    }
                    devices.append(device)
                    
                    # Log each device immediately as it's found
                    logger.info(f"📱 Found device: {ip} | MAC: {mac} | Vendor: {vendor}")
                    
                    # Immediately emit to GUI with basic info
                    socketio.emit('device_found', device)
                    
            except Exception as e:
                logger.warning(f"⚠️ Skipping malformed line in arp-scan output: {line}")
                continue
        
        # Log summary
        real_devices = [d for d in devices if d['ip'].startswith('192.168.')]  # Filter out non-device entries
        logger.info(f"✅ ARP scan completed. Found {len(real_devices)} devices")
        socketio.emit('scan_status', {
            'message': f'ARP scan completed. Found {len(real_devices)} devices',
            'type': 'success'
        })
        return real_devices
        
    except Exception as e:
        logger.error(f"❌ Unexpected error during ARP scan: {str(e)}")
        raise

async def gather_device_details(device: Dict[str, str]) -> Optional[Dict]:
    """Gather detailed information about a device."""
    try:
        ip = device['ip']
        
        # Start all async tasks in parallel
        hostname_task = asyncio.create_task(get_hostname(ip))
        os_task = asyncio.create_task(get_os_info_async(ip))
        ports_task = asyncio.create_task(scan_device_ports(ip))
        
        # Wait for all tasks to complete
        hostname, os_info, open_ports = await asyncio.gather(
            hostname_task, os_task, ports_task,
            return_exceptions=True
        )
        
        # Handle exceptions
        if isinstance(hostname, Exception):
            hostname = "Unknown"
        if isinstance(os_info, Exception):
            os_info = {'os_name': 'Unknown', 'os_accuracy': '0', 'os_type': 'Unknown', 'os_vendor': 'Unknown'}
        if isinstance(open_ports, Exception):
            open_ports = []
        
        return {
            **device,  # Include basic info (ip, mac, vendor, status)
            'hostname': hostname,
            'os_info': os_info,
            'open_ports': open_ports,
            'last_seen': datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Error gathering details for {device['ip']}: {e}")
        return None

async def get_hostname(ip: str) -> str:
    """Get hostname for an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

async def get_os_info_async(ip: str) -> Dict:
    """Get OS information asynchronously."""
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-O --osscan-guess')
        
        if ip in nm.all_hosts():
            os_info = nm[ip].get('osmatch', [])
            if os_info:
                return {
                    'os_name': os_info[0].get('name', 'Unknown'),
                    'os_accuracy': os_info[0].get('accuracy', '0'),
                    'os_type': os_info[0].get('osclass', [{}])[0].get('type', 'Unknown'),
                    'os_vendor': os_info[0].get('osclass', [{}])[0].get('vendor', 'Unknown')
                }
    except Exception as e:
        logger.error(f"Error getting OS info for {ip}: {e}")
    return {'os_name': 'Unknown', 'os_accuracy': '0', 'os_type': 'Unknown', 'os_vendor': 'Unknown'}

async def scan_network():
    """Scan the network with optimized two-phase approach and enhanced logging."""
    global scanning
    devices = []
    try:
        network_range = get_network_range()
        if not network_range:
            logger.error("❌ Could not determine network range")
            socketio.emit('scan_status', {
                'message': 'Error: Could not determine network range',
                'type': 'error'
            })
            return devices
        
        logger.info(f"🔍 Starting network scan on: {network_range}")
        socketio.emit('scan_status', {
            'message': f'Starting scan on network: {network_range}',
            'type': 'info'
        })
        
        # Phase 1: Quick ARP scan
        logger.info("📡 Performing initial ARP scan...")
        socketio.emit('scan_status', {
            'message': 'Performing initial ARP scan...',
            'type': 'info'
        })
        
        # Clear existing devices in GUI
        socketio.emit('clear_devices')
        
        basic_devices = await quick_arp_scan(network_range)
        logger.info(f"✅ Found {len(basic_devices)} devices in initial scan")
        
        if not scanning:
            logger.warning("⚠️ Scan stopped by user")
            return devices
            
        # Phase 2: Gather detailed information
        logger.info(f"🔎 Gathering detailed information for {len(basic_devices)} devices...")
        socketio.emit('scan_status', {
            'message': f'Found {len(basic_devices)} devices. Gathering detailed information...',
            'type': 'info'
        })
        
        # Process devices in batches
        batch_size = 10
        for i in range(0, len(basic_devices), batch_size):
            if not scanning:
                logger.warning("⚠️ Scan stopped by user")
                break
                
            batch = basic_devices[i:i + batch_size]
            logger.info(f"📦 Processing batch {i//batch_size + 1}/{(len(basic_devices) + batch_size - 1)//batch_size}")
            
            tasks = [gather_device_details(device) for device in batch]
            batch_results = await asyncio.gather(*tasks)
            
            for device_info in batch_results:
                if device_info:
                    devices.append(device_info)
                    logger.info(f"📱 Updating device details: {device_info['ip']} ({device_info['vendor']})")
                    if device_info.get('os_info', {}).get('os_name') != 'Unknown':
                        logger.info(f"💻 OS: {device_info['os_info']['os_name']} ({device_info['os_info']['os_accuracy']}% accuracy)")
                    if device_info.get('open_ports'):
                        logger.info(f"🔓 Open ports: {', '.join(map(str, device_info['open_ports']))}")
                    # Update device in GUI with detailed info
                    socketio.emit('device_update', device_info)
        
        if scanning:
            logger.info(f"✅ Scan completed successfully. Found {len(devices)} devices")
            socketio.emit('scan_complete', {
                'device_count': len(devices),
                'devices': devices
            })
            socketio.emit('scan_status', {
                'message': f'Scan completed. Found {len(devices)} devices.',
                'type': 'success'
            })
        
        return devices
    except Exception as e:
        logger.error(f"❌ Error during network scan: {str(e)}", exc_info=True)
        socketio.emit('scan_status', {
            'message': f'Error during scan: {str(e)}',
            'type': 'error'
        })
        return devices
    finally:
        scanning = False

def start_scan():
    """Start the network scan in a separate thread."""
    global scanning, scan_thread
    
    if not scanning:
        scanning = True
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        scan_thread = threading.Thread(target=lambda: loop.run_until_complete(scan_network()))
        scan_thread.start()

def stop_scan():
    """Stop the ongoing network scan."""
    global scanning
    scanning = False
    socketio.emit('scan_status', {
        'message': 'Stopping scan...',
        'type': 'warning'
    })

@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('index.html')
    return redirect(url_for('login'))

@socketio.on('connect')
def handle_connect():
    emit('scan_status', {
        'message': 'Connected to server',
        'type': 'info'
    })
    # Start monitoring when first client connects
    if not monitoring:
        start_monitoring()

@socketio.on('disconnect')
def handle_disconnect():
    # Stop monitoring when last client disconnects
    if not socketio.server.manager.rooms.get('/', {}):
        stop_monitoring()

@socketio.on('start_scan')
@login_required
def handle_start_scan():
    if not current_user.is_authenticated:
        return
    
    scan = Scan(user_id=current_user.id)
    db.session.add(scan)
    db.session.commit()
    
    # Start scan in background
    threading.Thread(target=run_scan, args=(scan.id,)).start()
    emit('scan_status', {'message': 'Scan started', 'type': 'info'})

@socketio.on('stop_scan')
def handle_stop_scan():
    stop_scan()

@socketio.on('scan_device')
def handle_scan_device(data):
    ip = data.get('ip')
    if ip:
        def scan_single_device():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            device_info = loop.run_until_complete(get_device_info(ip))
            if device_info:
                emit('device_found', device_info)
        
        executor.submit(scan_single_device)

@socketio.on('get_network_info')
def handle_get_network_info():
    """Send network information to the client."""
    local_ip = get_local_ip()
    network_range = get_network_range()
    
    emit('network_info', {
        'local_ip': local_ip,
        'network_range': network_range
    })

@socketio.on('get_security_events')
@login_required
def handle_get_security_events():
    if not current_user.is_authenticated:
        return
    
    events = SecurityEvent.query.filter_by(user_id=current_user.id).order_by(SecurityEvent.timestamp.desc()).all()
    emit('security_events', [event.to_dict() for event in events])

@socketio.on('get_traffic_stats')
def handle_get_traffic_stats():
    """Send current traffic statistics to the client."""
    stats = {
        ip: {
            'bytes': data['bytes'],
            'packets': data['packets'],
            'last_seen': data['last_seen'].isoformat() if data['last_seen'] else None
        }
        for ip, data in traffic_stats.items()
    }
    emit('traffic_stats', stats)

def calculate_risk_score(vuln: Vulnerability, device_info: Dict) -> float:
    """Calculate a comprehensive risk score for a vulnerability."""
    base_score = vuln.cvss_score
    
    # Exploit availability multiplier
    exploit_multiplier = 1.5 if vuln.exploit_available else 1.0
    
    # Device criticality multiplier
    device_criticality = 1.0
    if device_info.get('os_info', {}).get('os_type') == 'server':
        device_criticality = 1.5
    elif device_info.get('os_info', {}).get('os_type') == 'router':
        device_criticality = 1.3
    
    # Open ports multiplier
    critical_ports = {21, 22, 23, 3389, 445}  # FTP, SSH, Telnet, RDP, SMB
    open_critical_ports = len(set(device_info.get('open_ports', [])) & critical_ports)
    port_multiplier = 1.0 + (open_critical_ports * 0.1)
    
    # Calculate final risk score
    risk_score = base_score * exploit_multiplier * device_criticality * port_multiplier
    
    # Normalize to 0-10 scale
    return min(10.0, risk_score)

def get_exploit_info(cve_id: str) -> Tuple[bool, List[str]]:
    """Get exploit information from multiple sources."""
    exploit_urls = []
    exploit_available = False
    
    try:
        # Check ExploitDB
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(f"{EXPLOIT_DB_API}?cve={cve_id}", headers=headers)
        if response.status_code == 200:
            # Parse ExploitDB response
            if 'exploit' in response.text.lower():
                exploit_available = True
                # Extract exploit URLs
                exploit_urls.extend(re.findall(r'https://www\.exploit-db\.com/exploits/\d+', response.text))
        
        # Check GitHub for PoCs
        github_url = f"https://github.com/search?q={cve_id}+poc&type=code"
        response = requests.get(github_url, headers=headers)
        if response.status_code == 200:
            if 'poc' in response.text.lower() or 'exploit' in response.text.lower():
                exploit_available = True
                # Extract GitHub URLs
                exploit_urls.extend(re.findall(r'https://github\.com/[^/]+/[^/]+/blob/[^/]+/[^"]+', response.text))
        
        return exploit_available, list(set(exploit_urls))
    except Exception as e:
        logger.error(f"Error getting exploit info for {cve_id}: {e}")
        return False, []

def get_remediation_steps(vuln: Vulnerability, device_info: Dict) -> List[str]:
    """Get remediation steps based on vulnerability and device information."""
    steps = []
    
    # OS-specific remediation steps
    os_type = device_info.get('os_info', {}).get('os_type', '').lower()
    os_name = device_info.get('os_info', {}).get('os_name', '').lower()
    
    if 'linux' in os_type:
        steps.append("Update system packages: sudo apt update && sudo apt upgrade")
        if 'ubuntu' in os_name:
            steps.append("Check Ubuntu security updates: sudo unattended-upgrades --dry-run")
        elif 'debian' in os_name:
            steps.append("Check Debian security updates: sudo apt-get -s dist-upgrade")
    elif 'windows' in os_type:
        steps.append("Run Windows Update: Start > Settings > Update & Security")
        steps.append("Check for optional updates in Windows Update")
    
    # Service-specific remediation steps
    for port in device_info.get('open_ports', []):
        if port == 21:  # FTP
            steps.append("Consider disabling FTP and using SFTP instead")
        elif port == 23:  # Telnet
            steps.append("Disable Telnet and use SSH instead")
        elif port == 445:  # SMB
            steps.append("Ensure SMB signing is enabled")
            steps.append("Disable SMBv1 if possible")
    
    # General remediation steps
    steps.append(f"Monitor {vuln.cve_id} for updates and patches")
    if vuln.exploit_available:
        steps.append("Apply patches immediately due to available exploits")
    
    return steps

def get_cve_for_product(product_info: Dict) -> List[Vulnerability]:
    """Enhanced CVE scanning with multiple sources and detailed analysis."""
    vulnerabilities = []
    cache_key = f"{product_info['os_info']['os_name']}_{product_info['os_info']['os_vendor']}"
    
    # Check cache first
    if cache_key in CVE_CACHE:
        cache_data = CVE_CACHE[cache_key]
        if datetime.now() - cache_data['timestamp'] < CVE_CACHE_EXPIRY:
            return cache_data['vulnerabilities']
    
    try:
        # Prepare search terms
        search_terms = [
            product_info['os_info']['os_name'],
            product_info['os_info']['os_vendor'],
            f"{product_info['os_info']['os_name']} {product_info['os_info']['os_vendor']}"
        ]
        
        # Add version information if available
        if 'version' in product_info['os_info']:
            search_terms.append(f"{product_info['os_info']['os_name']} {product_info['os_info']['version']}")
        
        # Add common services based on open ports
        port_services = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            443: 'https',
            445: 'smb',
            3306: 'mysql',
            3389: 'rdp',
            8080: 'http-proxy'
        }
        
        for port in product_info.get('open_ports', []):
            if port in port_services:
                service = port_services[port]
                search_terms.append(service)
                # Add common service versions
                if service in ['http', 'https']:
                    search_terms.append('apache')
                    search_terms.append('nginx')
                elif service == 'mysql':
                    search_terms.append('mariadb')
        
        # Search for CVEs from multiple sources
        for term in search_terms:
            # NVD API search
            headers = {'apiKey': NVD_API_KEY} if NVD_API_KEY else {}
            params = {
                'keywordSearch': term,
                'resultsPerPage': 50,  # Increased from 20
                'pubStartDate': (datetime.now() - timedelta(days=730)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'  # 2 years
            }
            
            response = requests.get(CVE_API_URL, params=params, headers=headers)
            if response.status_code == 200:
                data = response.json()
                for cve in data.get('vulnerabilities', []):
                    cve_data = cve.get('cve', {})
                    
                    # Get CVSS data
                    metrics = cve_data.get('metrics', {})
                    cvss_data = next(iter(metrics.values()), {}) if metrics else {}
                    cvss_score = float(cvss_data.get('cvssData', {}).get('baseScore', 0))
                    cvss_vector = cvss_data.get('cvssData', {}).get('vectorString', '')
                    
                    # Get attack metrics
                    attack_metrics = cvss_data.get('cvssData', {})
                    attack_complexity = attack_metrics.get('attackComplexity', 'Unknown')
                    attack_vector = attack_metrics.get('attackVector', 'Unknown')
                    privileges_required = attack_metrics.get('privilegesRequired', 'Unknown')
                    user_interaction = attack_metrics.get('userInteraction', 'Unknown')
                    scope = attack_metrics.get('scope', 'Unknown')
                    confidentiality_impact = attack_metrics.get('confidentialityImpact', 'Unknown')
                    integrity_impact = attack_metrics.get('integrityImpact', 'Unknown')
                    availability_impact = attack_metrics.get('availabilityImpact', 'Unknown')
                    
                    # Determine severity
                    severity = 'low'
                    if cvss_score >= 7.0:
                        severity = 'high'
                    elif cvss_score >= 4.0:
                        severity = 'medium'
                    
                    # Get exploit information
                    exploit_available, exploit_urls = get_exploit_info(cve_data.get('id', ''))
                    
                    # Get remediation steps
                    remediation_steps = get_remediation_steps(
                        Vulnerability(
                            cve_id=cve_data.get('id', ''),
                            description=cve_data.get('descriptions', [{}])[0].get('value', ''),
                            severity=severity,
                            cvss_score=cvss_score,
                            cvss_vector=cvss_vector,
                            affected_products=[p.get('product', '') for p in cve_data.get('configurations', [{}])[0].get('nodes', [{}])[0].get('cpeMatch', [])],
                            published_date=cve_data.get('published', ''),
                            last_modified_date=cve_data.get('lastModified', ''),
                            exploit_available=exploit_available,
                            exploit_urls=exploit_urls,
                            remediation_steps=[],
                            risk_score=0.0,
                            attack_complexity=attack_complexity,
                            attack_vector=attack_vector,
                            privileges_required=privileges_required,
                            user_interaction=user_interaction,
                            scope=scope,
                            confidentiality_impact=confidentiality_impact,
                            integrity_impact=integrity_impact,
                            availability_impact=availability_impact,
                            references=[{'url': ref.get('url', ''), 'name': ref.get('name', '')} 
                                      for ref in cve_data.get('references', [])],
                            tags=[tag.get('name', '') for tag in cve_data.get('tags', [])]
                        ),
                        product_info
                    )
                    
                    # Create vulnerability object
                    vulnerability = Vulnerability(
                        cve_id=cve_data.get('id', ''),
                        description=cve_data.get('descriptions', [{}])[0].get('value', ''),
                        severity=severity,
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        affected_products=[p.get('product', '') for p in cve_data.get('configurations', [{}])[0].get('nodes', [{}])[0].get('cpeMatch', [])],
                        published_date=cve_data.get('published', ''),
                        last_modified_date=cve_data.get('lastModified', ''),
                        exploit_available=exploit_available,
                        exploit_urls=exploit_urls,
                        remediation_steps=remediation_steps,
                        risk_score=calculate_risk_score(vulnerability, product_info),
                        attack_complexity=attack_complexity,
                        attack_vector=attack_vector,
                        privileges_required=privileges_required,
                        user_interaction=user_interaction,
                        scope=scope,
                        confidentiality_impact=confidentiality_impact,
                        integrity_impact=integrity_impact,
                        availability_impact=availability_impact,
                        references=[{'url': ref.get('url', ''), 'name': ref.get('name', '')} 
                                  for ref in cve_data.get('references', [])],
                        tags=[tag.get('name', '') for tag in cve_data.get('tags', [])]
                    )
                    
                    vulnerabilities.append(vulnerability)
        
        # Sort vulnerabilities by risk score
        vulnerabilities.sort(key=lambda x: x.risk_score, reverse=True)
        
        # Update cache
        CVE_CACHE[cache_key] = {
            'timestamp': datetime.now(),
            'vulnerabilities': vulnerabilities
        }
        
        return vulnerabilities
    
    except Exception as e:
        logger.error(f"Error fetching CVE data: {e}")
        return []

@socketio.on('scan_cve')
@login_required
def handle_scan_cve(data):
    """Handle CVE scan request for a device with enhanced reporting."""
    if not current_user.is_authenticated:
        return
    
    ip = data.get('ip')
    if not ip or ip not in known_devices:
        emit('cve_scan_error', {'message': 'Device not found'})
        return
    
    device_info = known_devices[ip]
    vulnerabilities = get_cve_for_product(device_info)
    
    # Log security events for high severity vulnerabilities
    high_severity_vulns = [v for v in vulnerabilities if v.severity == 'high']
    if high_severity_vulns:
        event = SecurityEvent(
            timestamp=datetime.now(),
            event_type='high_severity_vulnerability',
            severity='high',
            source_ip=ip,
            destination_ip=ip,
            details={
                'vulnerabilities': [
                    {
                        'cve_id': v.cve_id,
                        'description': v.description,
                        'cvss_score': v.cvss_score,
                        'risk_score': v.risk_score,
                        'exploit_available': v.exploit_available,
                        'remediation_steps': v.remediation_steps
                    } for v in high_severity_vulns
                ]
            }
        )
        log_security_event(event)
    
    # Emit detailed results
    emit('cve_scan_results', {
        'ip': ip,
        'vulnerabilities': [
            {
                'cve_id': v.cve_id,
                'description': v.description,
                'severity': v.severity,
                'cvss_score': v.cvss_score,
                'cvss_vector': v.cvss_vector,
                'risk_score': v.risk_score,
                'affected_products': v.affected_products,
                'published_date': v.published_date,
                'last_modified_date': v.last_modified_date,
                'exploit_available': v.exploit_available,
                'exploit_urls': v.exploit_urls,
                'remediation_steps': v.remediation_steps,
                'attack_complexity': v.attack_complexity,
                'attack_vector': v.attack_vector,
                'privileges_required': v.privileges_required,
                'user_interaction': v.user_interaction,
                'scope': v.scope,
                'confidentiality_impact': v.confidentiality_impact,
                'integrity_impact': v.integrity_impact,
                'availability_impact': v.availability_impact,
                'references': v.references,
                'tags': v.tags
            } for v in vulnerabilities
        ]
    })

def get_default_interface():
    """Get the default network interface."""
    try:
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][1]
        return default_gateway
    except Exception as e:
        logger.error(f"Error getting default interface: {e}")
        return None

def run_scan(scan_id):
    with app.app_context():
        try:
            scan = db.session.get(Scan, scan_id)
            if not scan:
                return
            
            scan.status = 'running'
            scan.start_time = datetime.now(timezone.utc)
            db.session.commit()
            
            # Get network interface
            interface = get_default_interface()
            if not interface:
                scan.status = 'failed'
                scan.end_time = datetime.now(timezone.utc)
                db.session.commit()
                return
            
            # Create event loop and run scan_network
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            devices = loop.run_until_complete(scan_network())
            loop.close()
            
            # Update scan status and devices
            for device in devices:
                new_device = Device(
                    scan_id=scan.id,
                    ip=device['ip'],
                    mac=device['mac'],
                    vendor=device['vendor'],
                    hostname=device['hostname'],
                    os_info=device['os_info'],
                    open_ports=device['open_ports']
                )
                db.session.add(new_device)
            
            scan.status = 'completed'
            scan.end_time = datetime.now(timezone.utc)
            db.session.commit()
            
        except Exception as e:
            if scan:
                scan.status = 'failed'
                scan.end_time = datetime.now(timezone.utc)
                db.session.commit()
            app.logger.error(f"Scan error: {str(e)}")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        return redirect(url_for('index'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    try:
        # Root yetkisi kontrolü
        if os.geteuid() != 0:
            print("Bu uygulama root yetkisi gerektirir. Lütfen sudo ile çalıştırın.")
            sys.exit(1)
        
        # Start the application
        socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False)
    except KeyboardInterrupt:
        print("\nUygulama kapatılıyor...")
        stop_monitoring()
        sys.exit(0) 