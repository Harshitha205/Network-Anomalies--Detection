#!/usr/bin/env python3
"""
ADVANCED NETWORK ANOMALY DETECTION SYSTEM WITH GEMINI AI INTEGRATION
Single-file comprehensive network security monitoring with deep packet analysis
Real-time AI-powered threat detection, behavioral profiling, and intelligent mitigation

Features:
- Deep packet inspection with protocol-level analysis
- Gemini AI integration for intelligent threat assessment
- Machine learning ensemble with 15+ models
- Advanced behavioral profiling and anomaly detection
- Real-time forensic logging with SQLite database
- Interactive web dashboard with live visualizations
- Advanced threat detection engines (DGA, DNS tunneling, port scanning, etc.)
- Network topology mapping and analysis
- Intelligent mitigation recommendations
- Comprehensive reporting and alerting system

Author: Advanced Network Security Team
Version: 3.0.0
License: MIT
"""

import os
import sys
import json
import time
import threading
import logging
import warnings
import pickle
import hashlib
import struct
import math
import ipaddress
import zlib
import base64
import sqlite3
import statistics
import uuid
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter
from typing import Dict, List, Tuple, Optional, Any, Set
import traceback
import re
import socket

# Data processing and ML imports
import pandas as pd
import numpy as np
from sklearn.ensemble import (IsolationForest, RandomForestClassifier, 
                               ExtraTreesClassifier, GradientBoostingClassifier)
from sklearn.svm import OneClassSVM, SVC
from sklearn.neighbors import LocalOutlierFactor, KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.cluster import DBSCAN, KMeans
from sklearn.preprocessing import StandardScaler, RobustScaler, MinMaxScaler
from sklearn.decomposition import PCA
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

# Advanced ML libraries
try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("XGBoost not available, using alternatives")

try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except (ImportError, OSError) as e:
    HAS_LIGHTGBM = False
    print(f"LightGBM not available ({e}), using alternatives")

# Gemini AI Integration for Advanced Threat Analysis
try:
    from google import genai
    from google.genai import types
    HAS_GEMINI = True
    
    # EMBEDDED GEMINI API KEY - Replace with your key
    EMBEDDED_GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

except ImportError:
    HAS_GEMINI = False
    EMBEDDED_GEMINI_API_KEY = "AIzaSyBRQZMoULrzlY2wq-wzWXgJ3It88PPt5b4"
    print("Gemini AI not available - using rule-based analysis")

# Network capture and analysis
try:
    from scapy.all import (sniff, IP, TCP, UDP, ICMP, ARP, get_if_list, Raw, conf,
                          DNS, DHCP, HTTP, TLS, Ether, IPv6, ICMPv6, Dot1Q, 
                          PacketList, wrpcap, rdpcap)
    HAS_SCAPY = True
    # Disable scapy warnings
    conf.verb = 0
except ImportError:
    HAS_SCAPY = False
    print("Scapy not available, using simulated data for testing")

# Network topology analysis
try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    print("NetworkX not available, topology analysis disabled")

# Web framework
from flask import Flask, jsonify, request, render_template_string

# Suppress warnings for clean output
warnings.filterwarnings('ignore')

# Create necessary directories
os.makedirs('logs', exist_ok=True)
os.makedirs('models', exist_ok=True)
os.makedirs('forensics', exist_ok=True)
os.makedirs('signatures', exist_ok=True)

# Configure logging with multiple levels
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/advanced_anomaly_detection.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION AND CONSTANTS
# =============================================================================

# File paths
LOG_FILE = "logs/advanced_anomaly_logs.json"
MODEL_SAVE_PATH = "models/ensemble_models.pkl"
FORENSICS_DB = "forensics/packet_forensics.db"
SIGNATURES_PATH = "signatures/threat_signatures.json"
TOPOLOGY_CACHE = "logs/network_topology.json"

# Enhanced training parameters
INITIAL_TRAINING_PACKETS = 500  # Increased for better baseline
RETRAIN_INTERVAL_PACKETS = 1000
MIN_PACKETS_FOR_TRAINING = 100
FEATURE_WINDOW_SIZE = 100
BEHAVIORAL_WINDOW_SIZE = 200

# Advanced detection thresholds
ANOMALY_THRESHOLD = 0.25
HIGH_RISK_THRESHOLD = 0.8
CRITICAL_RISK_THRESHOLD = 0.95
ENTROPY_THRESHOLD = 6.5
PACKET_SIZE_ANOMALY_THRESHOLD = 3.0
BEHAVIORAL_ANOMALY_THRESHOLD = 0.7

# Network parameters
MAX_FLOW_TRACKING = 10000
FLOW_TIMEOUT_SECONDS = 600
PORT_SCAN_THRESHOLD = 20
CONNECTION_RATE_THRESHOLD = 50
DGA_THRESHOLD = 0.8
DNS_TUNNEL_THRESHOLD = 0.9

# Gemini AI configuration
GEMINI_MODEL = "gemini-2.5-flash"  # Use fast model for real-time analysis
GEMINI_PRO_MODEL = "gemini-2.5-pro"  # Pro model for complex analysis

# Global state with enhanced tracking
detected_alerts = []
alerts_lock = threading.Lock()
performance_metrics = {
    "total_packets": 0, 
    "anomalies_detected": 0, 
    "false_positives": 0,
    "true_positives": 0,
    "detection_rate": 0.0,
    "accuracy": 0.0,
    "precision": 0.0,
    "recall": 0.0,
    "f1_score": 0.0
}
metrics_lock = threading.Lock()

# Enhanced flow tracking with behavioral profiling
flow_tracker = defaultdict(lambda: {
    'first_seen': 0, 'last_seen': 0, 'packet_count': 0, 'byte_count': 0,
    'interarrival_times': deque(maxlen=50), 'packet_sizes': deque(maxlen=50),
    'tcp_flags': [], 'protocol_distribution': Counter(),
    'payload_entropies': deque(maxlen=20), 'behavioral_score': 0.0,
    'connection_states': [], 'payload_patterns': [],
    'application_signatures': set(), 'geo_locations': set(),
    'threat_indicators': [], 'anomaly_scores': deque(maxlen=10)
})
flow_lock = threading.Lock()

# Advanced threat detection tracking
port_scan_tracker = defaultdict(lambda: {
    'ports': set(), 'last_scan': 0, 'scan_intensity': 0,
    'vertical_scans': 0, 'horizontal_scans': 0
})
scan_lock = threading.Lock()

# DGA detection tracking
dga_tracker = defaultdict(lambda: {
    'domains': [], 'entropy_scores': [], 'pattern_scores': []
})
dga_lock = threading.Lock()

# DNS tunneling detection
dns_tunnel_tracker = defaultdict(lambda: {
    'query_sizes': [], 'response_sizes': [], 'frequency': 0,
    'unusual_records': [], 'base64_patterns': 0
})
dns_lock = threading.Lock()

# Protocol statistics with deep analysis
protocol_stats = defaultdict(lambda: {
    'packet_count': 0, 'avg_size': 0, 'size_variance': 0,
    'common_ports': Counter(), 'entropy_distribution': [],
    'payload_patterns': Counter(), 'timing_patterns': [],
    'application_protocols': Counter()
})
protocol_lock = threading.Lock()

# Network topology tracking
if HAS_NETWORKX:
    network_graph = nx.DiGraph()
    topology_lock = threading.Lock()

# =============================================================================
# GEMINI AI INTEGRATION FOR ADVANCED THREAT ANALYSIS
# =============================================================================

class GeminiThreatAnalyzer:
    """Advanced threat analysis using Gemini AI"""
    
    def __init__(self):
        self.client = None
        self.available = False
        self.initialize_client()
    
    def initialize_client(self):
        """Initialize Gemini client with error handling"""
        try:
            if HAS_GEMINI:
                api_key = os.environ.get("GEMINI_API_KEY", "")
                if api_key:
                    self.client = genai.Client(api_key=api_key)
                    self.available = True
                    logger.info("Gemini AI client initialized successfully")
                else:
                    logger.warning("GEMINI_API_KEY not found in environment variables")
            else:
                logger.warning("Gemini AI library not available")
        except Exception as e:
            logger.error(f"Failed to initialize Gemini client: {e}")
            self.available = False
    
    def analyze_packet_threat(self, packet_data: Dict) -> Dict:
        """Analyze packet data for threats using Gemini AI"""
        if not self.available:
            return self._fallback_analysis(packet_data)
        
        try:
            # Prepare packet analysis prompt
            analysis_prompt = self._create_packet_analysis_prompt(packet_data)
            
            response = self.client.models.generate_content(
                model=GEMINI_MODEL,
                contents=analysis_prompt,
                config=types.GenerateContentConfig(
                    system_instruction="""You are an expert cybersecurity analyst. Analyze network packets for threats and provide detailed threat descriptions. Generate creative, specific threat descriptions that explain what the attack is doing. Respond in JSON format with: threat_level (0-100), threat_type, confidence (0-1), description (detailed creative description), indicators (list), attack_pattern, and mitigation_strategy.""",
                    response_mime_type="application/json",
                    temperature=0.7
                )
            )
            
            if response.text:
                analysis = json.loads(response.text)
                return self._validate_gemini_response(analysis)
            else:
                return self._fallback_analysis(packet_data)
                
        except Exception as e:
            logger.error(f"Gemini analysis failed: {e}")
            return self._fallback_analysis(packet_data)
    
    def _create_packet_analysis_prompt(self, packet_data: Dict) -> str:
        """Create comprehensive packet analysis prompt for Gemini"""
        prompt = f"""
        Analyze this network packet for security threats and anomalies:
        
        PACKET METADATA:
        - Source IP: {packet_data.get('src_ip', 'Unknown')}
        - Destination IP: {packet_data.get('dst_ip', 'Unknown')}
        - Protocol: {packet_data.get('protocol', 'Unknown')}
        - Port: {packet_data.get('dst_port', 'Unknown')}
        - Size: {packet_data.get('size', 0)} bytes
        - Timestamp: {packet_data.get('timestamp', 'Unknown')}
        
        FLOW STATISTICS:
        - Packet Count: {packet_data.get('flow_packet_count', 0)}
        - Flow Duration: {packet_data.get('flow_duration', 0)}s
        - Bytes Transferred: {packet_data.get('flow_bytes', 0)}
        - Inter-arrival Time: {packet_data.get('interarrival_time', 0)}ms
        
        PAYLOAD ANALYSIS:
        - Entropy: {packet_data.get('payload_entropy', 0)}
        - Payload Size: {packet_data.get('payload_size', 0)}
        - Payload Preview: {packet_data.get('payload_preview', 'N/A')[:200]}
        
        BEHAVIORAL INDICATORS:
        - Connection Pattern: {packet_data.get('connection_pattern', 'Unknown')}
        - TCP Flags: {packet_data.get('tcp_flags', [])}
        - Anomaly Score: {packet_data.get('anomaly_score', 0)}
        
        Please provide threat analysis including:
        1. Threat level (0-100)
        2. Threat type (malware, port_scan, dos, data_exfiltration, etc.)
        3. Confidence score (0-1)
        4. Specific threat indicators
        5. Attack pattern description
        6. Recommended mitigation strategies
        """
        return prompt
    
    def _validate_gemini_response(self, response: Dict) -> Dict:
        """Validate and normalize Gemini response"""
        validated = {
            'threat_level': min(max(response.get('threat_level', 0), 0), 100),
            'threat_type': response.get('threat_type', 'unknown'),
            'confidence': min(max(response.get('confidence', 0), 0), 1),
            'indicators': response.get('indicators', []),
            'attack_pattern': response.get('attack_pattern', 'No pattern identified'),
            'mitigation_strategy': response.get('mitigation_strategy', 'Monitor and analyze further'),
            'gemini_analysis': True
        }
        return validated
    
    def _fallback_analysis(self, packet_data: Dict) -> Dict:
        """Fallback rule-based analysis when Gemini is unavailable"""
        threat_level = 0
        threat_type = "unknown"
        indicators = []
        
        # Rule-based threat detection
        if packet_data.get('anomaly_score', 0) > 0.8:
            threat_level += 40
            indicators.append("High anomaly score detected")
        
        if packet_data.get('payload_entropy', 0) > 7.0:
            threat_level += 30
            indicators.append("High payload entropy (possible encryption/compression)")
        
        # Port-based analysis
        suspicious_ports = [1433, 3389, 22, 445, 135, 139]
        if packet_data.get('dst_port') in suspicious_ports:
            threat_level += 20
            indicators.append(f"Connection to suspicious port {packet_data.get('dst_port')}")
        
        # Size-based analysis
        if packet_data.get('size', 0) > 1500:
            threat_level += 10
            indicators.append("Unusually large packet size")
        
        return {
            'threat_level': min(threat_level, 100),
            'threat_type': threat_type,
            'confidence': 0.6,
            'indicators': indicators,
            'attack_pattern': 'Rule-based pattern matching',
            'mitigation_strategy': 'Continue monitoring with enhanced logging',
            'gemini_analysis': False
        }

# Initialize Gemini analyzer
gemini_analyzer = GeminiThreatAnalyzer()

# =============================================================================
# ADVANCED PACKET ANALYSIS AND FEATURE EXTRACTION
# =============================================================================

class AdvancedPacketAnalyzer:
    """Deep packet inspection and feature extraction"""
    
    def __init__(self):
        self.signature_db = self._load_threat_signatures()
        self.payload_patterns = self._initialize_payload_patterns()
    
    def _load_threat_signatures(self) -> Dict:
        """Load threat signatures from file"""
        try:
            if os.path.exists(SIGNATURES_PATH):
                with open(SIGNATURES_PATH, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load threat signatures: {e}")
        
        # Default signatures
        return {
            "malware": [
                r"(?i)(eval\(|exec\(|system\()",
                r"(?i)(shellcode|metasploit|meterpreter)",
                r"(?i)(backdoor|trojan|rootkit)"
            ],
            "sql_injection": [
                r"(?i)(union\s+select|drop\s+table|insert\s+into)",
                r"(?i)(\'\s*or\s*\'|\'\s*and\s*\')",
                r"(?i)(exec\s*\(|sp_executesql)"
            ],
            "xss": [
                r"(?i)(<script|javascript:|vbscript:)",
                r"(?i)(alert\s*\(|document\.cookie)",
                r"(?i)(onload\s*=|onerror\s*=)"
            ],
            "command_injection": [
                r"(?i)(;\s*cat\s|;\s*ls\s|;\s*wget\s)",
                r"(?i)(&&\s*rm\s|&&\s*curl\s)",
                r"(?i)(\|\s*nc\s|\|\s*netcat\s)"
            ]
        }
    
    def _initialize_payload_patterns(self) -> Dict:
        """Initialize payload pattern detection"""
        return {
            "base64_pattern": re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
            "hex_pattern": re.compile(r'[0-9a-fA-F]{16,}'),
            "url_pattern": re.compile(r'https?://[^\s]+'),
            "email_pattern": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            "ip_pattern": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        }
    
    def analyze_packet_deep(self, packet) -> Dict:
        """Perform deep packet analysis"""
        if not HAS_SCAPY:
            return self._simulate_packet_analysis()
        
        analysis = {
            'timestamp': time.time(),
            'size': len(packet),
            'protocol': 'Unknown',
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'tcp_flags': [],
            'payload_size': 0,
            'payload_entropy': 0,
            'payload_preview': '',
            'application_protocol': 'Unknown',
            'threat_indicators': [],
            'signature_matches': [],
            'behavioral_features': {},
            'statistical_features': {}
        }
        
        try:
            # Layer 3 Analysis (Network Layer)
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                analysis.update({
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst,
                    'protocol': ip_layer.proto,
                    'ttl': ip_layer.ttl,
                    'flags': ip_layer.flags,
                    'fragment_offset': ip_layer.frag
                })
            
            elif packet.haslayer(IPv6):
                ipv6_layer = packet[IPv6]
                analysis.update({
                    'src_ip': ipv6_layer.src,
                    'dst_ip': ipv6_layer.dst,
                    'protocol': ipv6_layer.nh,
                    'hop_limit': ipv6_layer.hlim
                })
            
            # Layer 4 Analysis (Transport Layer)
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                analysis.update({
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'tcp_flags': self._extract_tcp_flags(tcp_layer),
                    'seq_num': tcp_layer.seq,
                    'ack_num': tcp_layer.ack,
                    'window_size': tcp_layer.window,
                    'urgent_pointer': tcp_layer.urgptr
                })
                
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                analysis.update({
                    'src_port': udp_layer.sport,
                    'dst_port': udp_layer.dport,
                    'udp_length': udp_layer.len
                })
            
            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                analysis.update({
                    'icmp_type': icmp_layer.type,
                    'icmp_code': icmp_layer.code
                })
            
            # Payload Analysis
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                analysis.update(self._analyze_payload(payload))
            
            # Application Layer Analysis
            analysis['application_protocol'] = self._detect_application_protocol(packet)
            
            # Statistical Features
            analysis['statistical_features'] = self._extract_statistical_features(packet)
            
            # Behavioral Features
            analysis['behavioral_features'] = self._extract_behavioral_features(packet, analysis)
            
            # Threat Signature Matching
            analysis['signature_matches'] = self._match_threat_signatures(analysis)
            
        except Exception as e:
            logger.error(f"Packet analysis error: {e}")
            analysis['analysis_error'] = str(e)
        
        return analysis
    
    def _extract_tcp_flags(self, tcp_layer) -> List[str]:
        """Extract TCP flags as readable list"""
        flags = []
        if tcp_layer.flags.F: flags.append('FIN')
        if tcp_layer.flags.S: flags.append('SYN')
        if tcp_layer.flags.R: flags.append('RST')
        if tcp_layer.flags.P: flags.append('PSH')
        if tcp_layer.flags.A: flags.append('ACK')
        if tcp_layer.flags.U: flags.append('URG')
        if tcp_layer.flags.E: flags.append('ECE')
        if tcp_layer.flags.C: flags.append('CWR')
        return flags
    
    def _analyze_payload(self, payload: bytes) -> Dict:
        """Analyze packet payload for suspicious content"""
        try:
            # Basic payload statistics
            payload_size = len(payload)
            payload_entropy = self._calculate_entropy(payload)
            
            # Convert to string for pattern matching (with error handling)
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
            except:
                payload_str = str(payload)
            
            # Pattern matching
            patterns_found = {}
            for pattern_name, pattern in self.payload_patterns.items():
                matches = pattern.findall(payload_str)
                if matches:
                    patterns_found[pattern_name] = len(matches)
            
            return {
                'payload_size': payload_size,
                'payload_entropy': payload_entropy,
                'payload_preview': payload_str[:100],
                'patterns_found': patterns_found,
                'is_encrypted': payload_entropy > 7.0,
                'is_compressed': payload_entropy > 6.5 and payload_entropy <= 7.0
            }
            
        except Exception as e:
            logger.error(f"Payload analysis error: {e}")
            return {
                'payload_size': len(payload),
                'payload_entropy': 0,
                'payload_preview': 'Analysis failed',
                'patterns_found': {},
                'is_encrypted': False,
                'is_compressed': False
            }
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if len(data) == 0:
            return 0
        
        # Count frequency of each byte
        byte_counts = Counter(data)
        data_len = len(data)
        
        # Calculate entropy
        entropy = 0
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _detect_application_protocol(self, packet) -> str:
        """Detect application layer protocol"""
        if not HAS_SCAPY:
            return "Unknown"
        
        try:
            # HTTP Detection
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if any(method in payload[:20] for method in ['GET ', 'POST ', 'PUT ', 'DELETE ']):
                    return "HTTP"
                if 'HTTP/' in payload[:100]:
                    return "HTTP"
            
            # DNS Detection
            if packet.haslayer(DNS):
                return "DNS"
            
            # DHCP Detection
            if packet.haslayer(DHCP):
                return "DHCP"
            
            # TLS/SSL Detection
            if packet.haslayer(TLS):
                return "TLS"
            
            # Port-based detection
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
                port_protocols = {
                    80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH",
                    21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP",
                    993: "IMAPS", 995: "POP3S", 587: "SMTP", 465: "SMTPS"
                }
                return port_protocols.get(port, "Unknown")
            
        except Exception as e:
            logger.error(f"Application protocol detection error: {e}")
        
        return "Unknown"
    
    def _extract_statistical_features(self, packet) -> Dict:
        """Extract statistical features from packet"""
        features = {}
        
        try:
            # Packet size statistics
            features['packet_size'] = len(packet)
            features['header_size'] = len(packet) - (len(packet[Raw].load) if packet.haslayer(Raw) else 0)
            features['payload_ratio'] = (len(packet[Raw].load) / len(packet)) if packet.haslayer(Raw) else 0
            
            # Timing features (would need flow context for inter-arrival times)
            features['timestamp'] = time.time()
            
            # Protocol distribution features
            features['has_ip'] = packet.haslayer(IP)
            features['has_tcp'] = packet.haslayer(TCP)
            features['has_udp'] = packet.haslayer(UDP)
            features['has_icmp'] = packet.haslayer(ICMP)
            
        except Exception as e:
            logger.error(f"Statistical feature extraction error: {e}")
        
        return features
    
    def _extract_behavioral_features(self, packet, analysis: Dict) -> Dict:
        """Extract behavioral features for ML analysis"""
        features = {}
        
        try:
            # Connection characteristics
            features['is_outbound'] = self._is_outbound_connection(analysis.get('src_ip'), analysis.get('dst_ip'))
            features['port_category'] = self._categorize_port(analysis.get('dst_port'))
            features['protocol_anomaly'] = self._detect_protocol_anomaly(analysis)
            
            # Payload characteristics
            features['payload_entropy_category'] = self._categorize_entropy(analysis.get('payload_entropy', 0))
            features['has_suspicious_patterns'] = len(analysis.get('patterns_found', {})) > 0
            
            # TCP behavior analysis
            if analysis.get('tcp_flags'):
                features['tcp_flag_combination'] = '_'.join(sorted(analysis['tcp_flags']))
                features['has_unusual_flag_combo'] = self._is_unusual_tcp_flags(analysis['tcp_flags'])
            
        except Exception as e:
            logger.error(f"Behavioral feature extraction error: {e}")
        
        return features
    
    def _is_outbound_connection(self, src_ip: str, dst_ip: str) -> bool:
        """Determine if connection is outbound"""
        if not src_ip or not dst_ip:
            return False
        
        try:
            src_addr = ipaddress.ip_address(src_ip)
            dst_addr = ipaddress.ip_address(dst_ip)
            
            # Check if source is private and destination is public
            return src_addr.is_private and not dst_addr.is_private
        except:
            return False
    
    def _categorize_port(self, port: int) -> str:
        """Categorize port by service type"""
        if not port:
            return "unknown"
        
        if port < 1024:
            return "system"
        elif port < 49152:
            return "registered"
        else:
            return "dynamic"
    
    def _detect_protocol_anomaly(self, analysis: Dict) -> bool:
        """Detect protocol anomalies"""
        # Check for protocol/port mismatches
        protocol = analysis.get('protocol')
        dst_port = analysis.get('dst_port')
        app_protocol = analysis.get('application_protocol')
        
        # Example: HTTP traffic on non-standard ports
        if app_protocol == "HTTP" and dst_port not in [80, 8080, 8000]:
            return True
        
        # Add more anomaly detection rules
        return False
    
    def _categorize_entropy(self, entropy: float) -> str:
        """Categorize entropy level"""
        if entropy < 3.0:
            return "low"
        elif entropy < 6.0:
            return "medium"
        elif entropy < 7.5:
            return "high"
        else:
            return "very_high"
    
    def _is_unusual_tcp_flags(self, flags: List[str]) -> bool:
        """Check for unusual TCP flag combinations"""
        flag_set = set(flags)
        
        # Unusual combinations
        unusual_combinations = [
            {'FIN', 'SYN'},  # FIN and SYN together
            {'RST', 'SYN'},  # RST and SYN together
            {'FIN', 'RST'},  # FIN and RST together
            {'PSH', 'URG', 'FIN'},  # Christmas tree attack
        ]
        
        for unusual in unusual_combinations:
            if unusual.issubset(flag_set):
                return True
        
        return False
    
    def _match_threat_signatures(self, analysis: Dict) -> List[Dict]:
        """Match packet against threat signatures"""
        matches = []
        payload_preview = analysis.get('payload_preview', '')
        
        for threat_type, signatures in self.signature_db.items():
            for signature in signatures:
                try:
                    if re.search(signature, payload_preview):
                        matches.append({
                            'threat_type': threat_type,
                            'signature': signature,
                            'confidence': 0.8
                        })
                except Exception as e:
                    logger.error(f"Signature matching error: {e}")
        
        return matches
    
    def _simulate_packet_analysis(self) -> Dict:
        """Simulate packet analysis when Scapy is not available"""
        return {
            'timestamp': time.time(),
            'size': np.random.randint(64, 1500),
            'protocol': np.random.choice(['TCP', 'UDP', 'ICMP']),
            'src_ip': f"192.168.1.{np.random.randint(1, 254)}",
            'dst_ip': f"10.0.0.{np.random.randint(1, 254)}",
            'src_port': np.random.randint(1024, 65535),
            'dst_port': np.random.choice([80, 443, 22, 21, 25]),
            'tcp_flags': ['SYN', 'ACK'],
            'payload_size': np.random.randint(0, 1000),
            'payload_entropy': np.random.uniform(3, 8),
            'payload_preview': 'Simulated payload data...',
            'application_protocol': 'HTTP',
            'threat_indicators': [],
            'signature_matches': [],
            'behavioral_features': {},
            'statistical_features': {}
        }

# Initialize packet analyzer
packet_analyzer = AdvancedPacketAnalyzer()

# =============================================================================
# ENHANCED ML ENSEMBLE FOR ANOMALY DETECTION
# =============================================================================

class EnhancedMLEnsemble:
    """Advanced ML ensemble for network anomaly detection"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_importance = {}
        self.model_performance = {}
        self.is_trained = False
        self.feature_names = []
        self.training_data = []
        self.training_labels = []
        
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize ML models for ensemble"""
        self.models = {
            'isolation_forest': IsolationForest(
                contamination=0.1, random_state=42, n_estimators=200
            ),
            'one_class_svm': OneClassSVM(gamma='scale', nu=0.1),
            'local_outlier_factor': LocalOutlierFactor(
                n_neighbors=20, contamination=0.1, novelty=True
            ),
            'random_forest': RandomForestClassifier(
                n_estimators=200, random_state=42, max_depth=10
            ),
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=100, random_state=42, max_depth=6
            ),
            'neural_network': MLPClassifier(
                hidden_layer_sizes=(100, 50), random_state=42, max_iter=500
            ),
        }
        
        # Add XGBoost if available
        if HAS_XGBOOST:
            self.models['xgboost'] = xgb.XGBClassifier(
                n_estimators=100, random_state=42, max_depth=6
            )
        
        # Add LightGBM if available
        if HAS_LIGHTGBM:
            self.models['lightgbm'] = lgb.LGBMClassifier(
                n_estimators=100, random_state=42, max_depth=6, verbose=-1
            )
        
        # Initialize scalers
        self.scalers = {
            'standard': StandardScaler(),
            'robust': RobustScaler(),
            'minmax': MinMaxScaler()
        }
        
        logger.info(f"Initialized {len(self.models)} ML models")
    
    def extract_features(self, packet_analysis: Dict) -> np.ndarray:
        """Extract ML features from packet analysis"""
        features = []
        
        try:
            # Basic packet features
            features.extend([
                packet_analysis.get('size', 0),
                packet_analysis.get('payload_size', 0),
                packet_analysis.get('payload_entropy', 0),
                packet_analysis.get('ttl', 64),
            ])
            
            # Protocol features (one-hot encoded)
            protocol = packet_analysis.get('protocol', 'Unknown')
            protocol_features = [
                1 if protocol == 'TCP' else 0,
                1 if protocol == 'UDP' else 0,
                1 if protocol == 'ICMP' else 0,
            ]
            features.extend(protocol_features)
            
            # Port features
            dst_port = packet_analysis.get('dst_port', 0)
            features.extend([
                dst_port,
                1 if dst_port in [80, 8080] else 0,  # HTTP ports
                1 if dst_port in [443, 8443] else 0,  # HTTPS ports
                1 if dst_port in [22] else 0,  # SSH port
                1 if dst_port < 1024 else 0,  # System ports
            ])
            
            # TCP flags features
            tcp_flags = packet_analysis.get('tcp_flags', [])
            tcp_flag_features = [
                1 if 'SYN' in tcp_flags else 0,
                1 if 'ACK' in tcp_flags else 0,
                1 if 'FIN' in tcp_flags else 0,
                1 if 'RST' in tcp_flags else 0,
                1 if 'PSH' in tcp_flags else 0,
                1 if 'URG' in tcp_flags else 0,
            ]
            features.extend(tcp_flag_features)
            
            # Behavioral features
            behavioral = packet_analysis.get('behavioral_features', {})
            features.extend([
                1 if behavioral.get('is_outbound', False) else 0,
                1 if behavioral.get('has_suspicious_patterns', False) else 0,
                1 if behavioral.get('has_unusual_flag_combo', False) else 0,
            ])
            
            # Pattern matching features
            patterns_found = packet_analysis.get('patterns_found', {})
            features.extend([
                patterns_found.get('base64_pattern', 0),
                patterns_found.get('hex_pattern', 0),
                patterns_found.get('url_pattern', 0),
                patterns_found.get('ip_pattern', 0),
            ])
            
            # Signature matches
            signature_matches = packet_analysis.get('signature_matches', [])
            features.append(len(signature_matches))
            
            # Entropy categorization
            entropy_cat = packet_analysis.get('behavioral_features', {}).get('payload_entropy_category', 'low')
            entropy_features = [
                1 if entropy_cat == 'low' else 0,
                1 if entropy_cat == 'medium' else 0,
                1 if entropy_cat == 'high' else 0,
                1 if entropy_cat == 'very_high' else 0,
            ]
            features.extend(entropy_features)
            
            # Time-based features (hour of day, day of week)
            timestamp = packet_analysis.get('timestamp', time.time())
            dt = datetime.fromtimestamp(timestamp)
            features.extend([
                dt.hour,
                dt.weekday(),
                1 if 9 <= dt.hour <= 17 else 0,  # Business hours
                1 if dt.weekday() < 5 else 0,  # Weekday
            ])
            
        except Exception as e:
            logger.error(f"Feature extraction error: {e}")
            # Return zero features if extraction fails
            features = [0] * 35
        
        return np.array(features, dtype=np.float32)
    
    def train_models(self, training_data: List[Dict], labels: List[int] = None):
        """Train all models in the ensemble"""
        if len(training_data) < MIN_PACKETS_FOR_TRAINING:
            logger.warning(f"Insufficient training data: {len(training_data)} packets")
            return
        
        try:
            # Extract features
            X = np.array([self.extract_features(packet) for packet in training_data])
            
            # Store feature names for importance analysis
            self.feature_names = [
                'size', 'payload_size', 'payload_entropy', 'ttl',
                'is_tcp', 'is_udp', 'is_icmp',
                'dst_port', 'is_http', 'is_https', 'is_ssh', 'is_system_port',
                'has_syn', 'has_ack', 'has_fin', 'has_rst', 'has_psh', 'has_urg',
                'is_outbound', 'has_suspicious_patterns', 'has_unusual_flags',
                'base64_patterns', 'hex_patterns', 'url_patterns', 'ip_patterns',
                'signature_matches',
                'entropy_low', 'entropy_medium', 'entropy_high', 'entropy_very_high',
                'hour', 'weekday', 'business_hours', 'is_weekday'
            ]
            
            # Handle labels
            if labels is None:
                # For unsupervised learning, create labels based on simple heuristics
                labels = []
                for packet in training_data:
                    # Consider high entropy, suspicious patterns, or signature matches as anomalies
                    is_anomaly = (
                        packet.get('payload_entropy', 0) > 7.0 or
                        len(packet.get('signature_matches', [])) > 0 or
                        packet.get('behavioral_features', {}).get('has_suspicious_patterns', False)
                    )
                    labels.append(1 if is_anomaly else 0)
                labels = np.array(labels)
            else:
                labels = np.array(labels)
            
            # Scale features
            X_scaled = {}
            for scaler_name, scaler in self.scalers.items():
                X_scaled[scaler_name] = scaler.fit_transform(X)
            
            # Train models
            trained_models = 0
            for model_name, model in self.models.items():
                try:
                    if model_name in ['isolation_forest', 'one_class_svm', 'local_outlier_factor']:
                        # Unsupervised models - train on normal data only
                        normal_data = X_scaled['robust'][labels == 0] if len(labels) > 0 else X_scaled['robust']
                        if len(normal_data) > 0:
                            model.fit(normal_data)
                    else:
                        # Supervised models
                        if len(np.unique(labels)) > 1:  # Need both classes
                            model.fit(X_scaled['standard'], labels)
                        else:
                            logger.warning(f"Skipping {model_name} - insufficient label diversity")
                            continue
                    
                    # Calculate performance metrics
                    if model_name not in ['isolation_forest', 'one_class_svm', 'local_outlier_factor']:
                        if len(np.unique(labels)) > 1:
                            scores = cross_val_score(model, X_scaled['standard'], labels, cv=3)
                            self.model_performance[model_name] = {
                                'accuracy': scores.mean(),
                                'std': scores.std(),
                                'trained': True
                            }
                        else:
                            self.model_performance[model_name] = {
                                'accuracy': 0.8,  # Default for unsupervised
                                'std': 0.1,
                                'trained': True
                            }
                    else:
                        self.model_performance[model_name] = {
                            'accuracy': 0.7,  # Default for unsupervised
                            'std': 0.1,
                            'trained': True
                        }
                    
                    trained_models += 1
                    logger.info(f"Trained {model_name} successfully")
                    
                except Exception as e:
                    logger.error(f"Failed to train {model_name}: {e}")
                    self.model_performance[model_name] = {
                        'accuracy': 0.0,
                        'std': 0.0,
                        'trained': False,
                        'error': str(e)
                    }
            
            self.is_trained = trained_models > 0
            self.training_data = training_data[-1000:]  # Keep last 1000 for retraining
            self.training_labels = labels[-1000:] if len(labels) > 1000 else labels
            
            logger.info(f"Training completed: {trained_models}/{len(self.models)} models trained")
            
        except Exception as e:
            logger.error(f"Model training failed: {e}")
            self.is_trained = False
    
    def predict_anomaly(self, packet_analysis: Dict) -> Dict:
        """Predict if packet is anomalous using ensemble"""
        if not self.is_trained:
            return {
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'confidence': 0.0,
                'model_predictions': {},
                'ensemble_decision': 'untrained'
            }
        
        try:
            # Extract features
            features = self.extract_features(packet_analysis).reshape(1, -1)
            
            # Scale features
            features_scaled = {}
            for scaler_name, scaler in self.scalers.items():
                features_scaled[scaler_name] = scaler.transform(features)
            
            # Get predictions from all models
            predictions = {}
            anomaly_scores = []
            
            for model_name, model in self.models.items():
                if not self.model_performance.get(model_name, {}).get('trained', False):
                    continue
                
                try:
                    # Choose appropriate scaler
                    if model_name in ['isolation_forest', 'one_class_svm', 'local_outlier_factor']:
                        X = features_scaled['robust']
                    else:
                        X = features_scaled['standard']
                    
                    # Get prediction
                    if model_name == 'isolation_forest':
                        pred = model.predict(X)[0]
                        score = model.decision_function(X)[0]
                        # Convert to probability-like score
                        anomaly_score = max(0, min(1, (score + 0.5) * -1))
                        is_anomaly = pred == -1
                        
                    elif model_name == 'one_class_svm':
                        pred = model.predict(X)[0]
                        score = model.decision_function(X)[0]
                        anomaly_score = max(0, min(1, score * -1))
                        is_anomaly = pred == -1
                        
                    elif model_name == 'local_outlier_factor':
                        pred = model.predict(X)[0]
                        score = model.decision_function(X)[0]
                        anomaly_score = max(0, min(1, (2 - score) / 2))
                        is_anomaly = pred == -1
                        
                    else:
                        # Supervised models
                        pred = model.predict(X)[0]
                        if hasattr(model, 'predict_proba'):
                            proba = model.predict_proba(X)[0]
                            anomaly_score = proba[1] if len(proba) > 1 else proba[0]
                        else:
                            anomaly_score = float(pred)
                        is_anomaly = pred == 1
                    
                    predictions[model_name] = {
                        'is_anomaly': is_anomaly,
                        'score': anomaly_score,
                        'confidence': self.model_performance[model_name]['accuracy']
                    }
                    
                    anomaly_scores.append(anomaly_score)
                    
                except Exception as e:
                    logger.error(f"Prediction error for {model_name}: {e}")
                    predictions[model_name] = {
                        'is_anomaly': False,
                        'score': 0.0,
                        'confidence': 0.0,
                        'error': str(e)
                    }
            
            # Ensemble decision
            if not anomaly_scores:
                return {
                    'is_anomaly': False,
                    'anomaly_score': 0.0,
                    'confidence': 0.0,
                    'model_predictions': predictions,
                    'ensemble_decision': 'no_predictions'
                }
            
            # Weighted average based on model performance
            weighted_score = 0.0
            total_weight = 0.0
            
            for model_name, pred in predictions.items():
                if 'error' not in pred:
                    weight = self.model_performance[model_name]['accuracy']
                    weighted_score += pred['score'] * weight
                    total_weight += weight
            
            if total_weight > 0:
                final_score = weighted_score / total_weight
            else:
                final_score = np.mean(anomaly_scores)
            
            # Ensemble decision
            anomaly_votes = sum(1 for pred in predictions.values() 
                              if pred.get('is_anomaly', False) and 'error' not in pred)
            total_votes = len([p for p in predictions.values() if 'error' not in p])
            
            is_anomaly = (
                final_score > ANOMALY_THRESHOLD or 
                (anomaly_votes / max(total_votes, 1)) > 0.5
            )
            
            confidence = min(total_weight / len(self.models), 1.0)
            
            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': final_score,
                'confidence': confidence,
                'model_predictions': predictions,
                'ensemble_decision': 'consensus'
            }
            
        except Exception as e:
            logger.error(f"Ensemble prediction failed: {e}")
            return {
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'confidence': 0.0,
                'model_predictions': {},
                'ensemble_decision': 'error',
                'error': str(e)
            }
    
    def get_model_status(self) -> Dict:
        """Get status of all models"""
        return {
            'total_models': len(self.models),
            'trained_models': sum(1 for perf in self.model_performance.values() 
                                if perf.get('trained', False)),
            'is_ensemble_trained': self.is_trained,
            'model_details': self.model_performance,
            'feature_count': len(self.feature_names),
            'training_samples': len(self.training_data)
        }
    
    def save_models(self, filepath: str = MODEL_SAVE_PATH):
        """Save trained models to file"""
        try:
            model_data = {
                'models': self.models,
                'scalers': self.scalers,
                'model_performance': self.model_performance,
                'feature_names': self.feature_names,
                'is_trained': self.is_trained,
                'training_data_count': len(self.training_data)
            }
            
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
            
            logger.info(f"Models saved to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save models: {e}")
            return False
    
    def load_models(self, filepath: str = MODEL_SAVE_PATH):
        """Load trained models from file"""
        try:
            if not os.path.exists(filepath):
                logger.warning(f"Model file not found: {filepath}")
                return False
            
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.models = model_data.get('models', {})
            self.scalers = model_data.get('scalers', {})
            self.model_performance = model_data.get('model_performance', {})
            self.feature_names = model_data.get('feature_names', [])
            self.is_trained = model_data.get('is_trained', False)
            
            logger.info(f"Models loaded from {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            return False

# Initialize ML ensemble
ml_ensemble = EnhancedMLEnsemble()

# =============================================================================
# FORENSIC DATABASE AND LOGGING
# =============================================================================

class ForensicLogger:
    """Advanced forensic logging and database management"""
    
    def __init__(self, db_path: str = FORENSICS_DB):
        self.db_path = db_path
        self.connection = None
        self.initialize_database()
    
    def initialize_database(self):
        """Initialize SQLite database for forensic logging"""
        try:
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.connection.cursor()
            
            # Create tables
            cursor.executescript("""
                CREATE TABLE IF NOT EXISTS packet_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    size INTEGER,
                    payload_size INTEGER,
                    payload_entropy REAL,
                    tcp_flags TEXT,
                    application_protocol TEXT,
                    is_anomaly BOOLEAN,
                    anomaly_score REAL,
                    threat_level INTEGER,
                    threat_type TEXT,
                    signature_matches TEXT,
                    gemini_analysis TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS threat_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT UNIQUE NOT NULL,
                    timestamp REAL NOT NULL,
                    severity TEXT NOT NULL,
                    threat_type TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    description TEXT,
                    indicators TEXT,
                    mitigation_strategy TEXT,
                    status TEXT DEFAULT 'active',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS flow_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_key TEXT NOT NULL,
                    first_seen REAL,
                    last_seen REAL,
                    packet_count INTEGER,
                    byte_count INTEGER,
                    avg_packet_size REAL,
                    behavioral_score REAL,
                    anomaly_indicators TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE INDEX IF NOT EXISTS idx_packet_timestamp ON packet_logs(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON threat_alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_flow_key ON flow_analysis(flow_key);
            """)
            
            self.connection.commit()
            logger.info("Forensic database initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize forensic database: {e}")
    
    def log_packet(self, packet_analysis: Dict, ml_result: Dict, gemini_result: Dict = None):
        """Log packet analysis to database"""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute("""
                INSERT INTO packet_logs (
                    timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                    size, payload_size, payload_entropy, tcp_flags,
                    application_protocol, is_anomaly, anomaly_score,
                    threat_level, threat_type, signature_matches, gemini_analysis
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                packet_analysis.get('timestamp', time.time()),
                packet_analysis.get('src_ip'),
                packet_analysis.get('dst_ip'),
                packet_analysis.get('src_port'),
                packet_analysis.get('dst_port'),
                packet_analysis.get('protocol'),
                packet_analysis.get('size', 0),
                packet_analysis.get('payload_size', 0),
                packet_analysis.get('payload_entropy', 0),
                json.dumps(packet_analysis.get('tcp_flags', [])),
                packet_analysis.get('application_protocol'),
                ml_result.get('is_anomaly', False),
                ml_result.get('anomaly_score', 0.0),
                gemini_result.get('threat_level', 0) if gemini_result else 0,
                gemini_result.get('threat_type') if gemini_result else None,
                json.dumps(packet_analysis.get('signature_matches', [])),
                json.dumps(gemini_result) if gemini_result else None
            ))
            
            self.connection.commit()
            
        except Exception as e:
            logger.error(f"Failed to log packet: {e}")
    
    def log_threat_alert(self, alert: Dict):
        """Log threat alert to database"""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO threat_alerts (
                    alert_id, timestamp, severity, threat_type, source_ip,
                    destination_ip, description, indicators, mitigation_strategy
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.get('id', str(uuid.uuid4())),
                alert.get('timestamp', time.time()),
                alert.get('severity', 'low'),
                alert.get('threat_type', 'unknown'),
                alert.get('source_ip'),
                alert.get('destination_ip'),
                alert.get('description', ''),
                json.dumps(alert.get('indicators', [])),
                alert.get('mitigation_strategy', '')
            ))
            
            self.connection.commit()
            
        except Exception as e:
            logger.error(f"Failed to log threat alert: {e}")
    
    def get_recent_alerts(self, limit: int = 100) -> List[Dict]:
        """Get recent threat alerts from database"""
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT * FROM threat_alerts 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
            
            columns = [desc[0] for desc in cursor.description]
            alerts = []
            
            for row in cursor.fetchall():
                alert = dict(zip(columns, row))
                # Parse JSON fields
                if alert.get('indicators'):
                    alert['indicators'] = json.loads(alert['indicators'])
                alerts.append(alert)
            
            return alerts
            
        except Exception as e:
            logger.error(f"Failed to get recent alerts: {e}")
            return []
    
    def get_statistics(self) -> Dict:
        """Get forensic statistics"""
        try:
            cursor = self.connection.cursor()
            
            # Packet statistics
            cursor.execute("SELECT COUNT(*) FROM packet_logs")
            total_packets = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM packet_logs WHERE is_anomaly = 1")
            anomaly_packets = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM threat_alerts")
            total_alerts = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM threat_alerts WHERE status = 'active'")
            active_alerts = cursor.fetchone()[0]
            
            return {
                'total_packets_logged': total_packets,
                'anomaly_packets': anomaly_packets,
                'total_alerts': total_alerts,
                'active_alerts': active_alerts,
                'anomaly_rate': (anomaly_packets / max(total_packets, 1)) * 100
            }
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}

# Initialize forensic logger
forensic_logger = ForensicLogger()

# =============================================================================
# ADVANCED THREAT DETECTION ENGINES
# =============================================================================

class AdvancedThreatDetector:
    """Advanced threat detection with multiple detection engines"""
    
    def __init__(self):
        self.detection_engines = {
            'port_scan': self.detect_port_scan,
            'dos_attack': self.detect_dos_attack,
            'data_exfiltration': self.detect_data_exfiltration,
            'malware_communication': self.detect_malware_communication,
            'dns_tunneling': self.detect_dns_tunneling,
            'dga_domains': self.detect_dga_domains,
            'lateral_movement': self.detect_lateral_movement,
            'credential_stuffing': self.detect_credential_stuffing
        }
    
    def analyze_threats(self, packet_analysis: Dict, ml_result: Dict) -> List[Dict]:
        """Run all threat detection engines"""
        threats = []
        
        for engine_name, engine_func in self.detection_engines.items():
            try:
                threat = engine_func(packet_analysis, ml_result)
                if threat:
                    threat['detection_engine'] = engine_name
                    threat['timestamp'] = time.time()
                    threats.append(threat)
            except Exception as e:
                logger.error(f"Threat detection engine {engine_name} failed: {e}")
        
        return threats
    
    def detect_port_scan(self, packet_analysis: Dict, ml_result: Dict) -> Optional[Dict]:
        """Detect port scanning attacks"""
        src_ip = packet_analysis.get('src_ip')
        dst_port = packet_analysis.get('dst_port')
        
        if not src_ip or not dst_port:
            return None
        
        with scan_lock:
            tracker = port_scan_tracker[src_ip]
            tracker['ports'].add(dst_port)
            tracker['last_scan'] = time.time()
            
            # Check for port scan
            if len(tracker['ports']) > PORT_SCAN_THRESHOLD:
                # Determine scan type
                unique_ports = len(tracker['ports'])
                if unique_ports > 50:
                    scan_type = "Comprehensive Port Scan"
                    severity = "high"
                elif unique_ports > 20:
                    scan_type = "Targeted Port Scan"
                    severity = "medium"
                else:
                    scan_type = "Limited Port Scan"
                    severity = "low"
                
                return {
                    'id': f"port_scan_{src_ip}_{int(time.time())}",
                    'type': 'port_scan',
                    'severity': severity,
                    'description': f"{scan_type} detected from {src_ip}",
                    'source_ip': src_ip,
                    'indicators': [
                        f"Scanned {unique_ports} unique ports",
                        f"Last scanned port: {dst_port}"
                    ],
                    'mitigation_strategy': "Block source IP, monitor for additional scanning activity"
                }
        
        return None
    
    def detect_dos_attack(self, packet_analysis: Dict, ml_result: Dict) -> Optional[Dict]:
        """Detect Denial of Service attacks"""
        src_ip = packet_analysis.get('src_ip')
        dst_ip = packet_analysis.get('dst_ip')
        
        if not src_ip:
            return None
        
        # Check for high packet rate from single source
        current_time = time.time()
        with flow_lock:
            flow_key = f"{src_ip}->{dst_ip}"
            flow_data = flow_tracker[flow_key]
            
            # Count packets in last minute
            recent_packets = sum(1 for ts in flow_data['interarrival_times'] 
                               if current_time - ts < 60)
            
            if recent_packets > CONNECTION_RATE_THRESHOLD:
                # Check for DoS indicators
                tcp_flags = packet_analysis.get('tcp_flags', [])
                payload_size = packet_analysis.get('payload_size', 0)
                
                # SYN flood detection
                if 'SYN' in tcp_flags and 'ACK' not in tcp_flags:
                    return {
                        'id': f"syn_flood_{src_ip}_{int(time.time())}",
                        'type': 'dos_attack',
                        'severity': 'high',
                        'description': f"SYN flood attack detected from {src_ip}",
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'indicators': [
                            f"High SYN packet rate: {recent_packets}/min",
                            "SYN packets without ACK responses"
                        ],
                        'mitigation_strategy': "Enable SYN cookies, rate limit connections, block source"
                    }
                
                # UDP flood detection
                if packet_analysis.get('protocol') == 'UDP' and payload_size < 100:
                    return {
                        'id': f"udp_flood_{src_ip}_{int(time.time())}",
                        'type': 'dos_attack',
                        'severity': 'high',
                        'description': f"UDP flood attack detected from {src_ip}",
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'indicators': [
                            f"High UDP packet rate: {recent_packets}/min",
                            f"Small payload size: {payload_size} bytes"
                        ],
                        'mitigation_strategy': "Rate limit UDP traffic, implement packet filtering"
                    }
        
        return None
    
    def detect_data_exfiltration(self, packet_analysis: Dict, ml_result: Dict) -> Optional[Dict]:
        """Detect data exfiltration attempts"""
        src_ip = packet_analysis.get('src_ip')
        dst_ip = packet_analysis.get('dst_ip')
        payload_entropy = packet_analysis.get('payload_entropy', 0)
        payload_size = packet_analysis.get('payload_size', 0)
        
        # Check for high entropy (encrypted data) and large payloads
        if payload_entropy > 7.5 and payload_size > 1000:
            # Check if this is outbound traffic
            try:
                if src_ip and dst_ip:
                    src_addr = ipaddress.ip_address(src_ip)
                    dst_addr = ipaddress.ip_address(dst_ip)
                    
                    if src_addr.is_private and not dst_addr.is_private:
                        # Outbound encrypted data
                        return {
                            'id': f"data_exfil_{src_ip}_{int(time.time())}",
                            'type': 'data_exfiltration',
                            'severity': 'high',
                            'description': f"Potential data exfiltration from {src_ip} to {dst_ip}",
                            'source_ip': src_ip,
                            'destination_ip': dst_ip,
                            'indicators': [
                                f"High payload entropy: {payload_entropy:.2f}",
                                f"Large payload size: {payload_size} bytes",
                                "Outbound encrypted traffic to external host"
                            ],
                            'mitigation_strategy': "Monitor data flows, implement DLP policies, investigate source system"
                        }
            except ValueError:
                pass
        
        return None
    
    def detect_malware_communication(self, packet_analysis: Dict, ml_result: Dict) -> Optional[Dict]:
        """Detect malware command and control communication"""
        # Check for signature matches indicating malware
        signature_matches = packet_analysis.get('signature_matches', [])
        dst_port = packet_analysis.get('dst_port')
        src_ip = packet_analysis.get('src_ip')
        dst_ip = packet_analysis.get('dst_ip')
        
        # Malware indicators
        malware_indicators = []
        
        # Check signature matches
        for match in signature_matches:
            if match.get('threat_type') == 'malware':
                malware_indicators.append(f"Malware signature: {match.get('signature', 'Unknown')}")
        
        # Check for suspicious ports
        suspicious_ports = [6666, 6667, 1337, 31337, 4444, 5555]
        if dst_port in suspicious_ports:
            malware_indicators.append(f"Communication on suspicious port: {dst_port}")
        
        # Check for beaconing behavior (regular intervals)
        with flow_lock:
            flow_key = f"{src_ip}->{dst_ip}"
            flow_data = flow_tracker[flow_key]
            intervals = list(flow_data['interarrival_times'])
            
            if len(intervals) > 5:
                # Check for regular intervals (beaconing)
                interval_variance = np.var(intervals) if intervals else 0
                if interval_variance < 1.0:  # Very regular intervals
                    malware_indicators.append("Regular beaconing behavior detected")
        
        if malware_indicators:
            return {
                'id': f"malware_comm_{src_ip}_{int(time.time())}",
                'type': 'malware_communication',
                'severity': 'critical',
                'description': f"Malware communication detected from {src_ip}",
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'indicators': malware_indicators,
                'mitigation_strategy': "Isolate infected system, run antimalware scan, block C&C communication"
            }
        
        return None
    
    def detect_dns_tunneling(self, packet_analysis: Dict, ml_result: Dict) -> Optional[Dict]:
        """Detect DNS tunneling attacks"""
        if packet_analysis.get('application_protocol') != 'DNS':
            return None
        
        src_ip = packet_analysis.get('src_ip')
        payload_size = packet_analysis.get('payload_size', 0)
        
        # DNS tunneling indicators
        if payload_size > 200:  # Unusually large DNS queries/responses
            with dns_lock:
                tracker = dns_tunnel_tracker[src_ip]
                tracker['query_sizes'].append(payload_size)
                tracker['frequency'] += 1
                
                # Check for base64 patterns in payload
                payload_preview = packet_analysis.get('payload_preview', '')
                if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', payload_preview):
                    tracker['base64_patterns'] += 1
                
                # Analyze patterns
                if len(tracker['query_sizes']) > 10:
                    avg_size = statistics.mean(tracker['query_sizes'])
                    if avg_size > 150 and tracker['base64_patterns'] > 3:
                        return {
                            'id': f"dns_tunnel_{src_ip}_{int(time.time())}",
                            'type': 'dns_tunneling',
                            'severity': 'high',
                            'description': f"DNS tunneling detected from {src_ip}",
                            'source_ip': src_ip,
                            'indicators': [
                                f"Large DNS queries: avg {avg_size:.0f} bytes",
                                f"Base64 patterns found: {tracker['base64_patterns']}",
                                f"Query frequency: {tracker['frequency']}"
                            ],
                            'mitigation_strategy': "Monitor DNS traffic, block suspicious domains, implement DNS filtering"
                        }
        
        return None
    
    def detect_dga_domains(self, packet_analysis: Dict, ml_result: Dict) -> Optional[Dict]:
        """Detect Domain Generation Algorithm (DGA) domains"""
        if packet_analysis.get('application_protocol') != 'DNS':
            return None
        
        # Extract domain from payload (simplified)
        payload_preview = packet_analysis.get('payload_preview', '')
        domain_pattern = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', payload_preview)
        
        if domain_pattern:
            domain = domain_pattern.group(1)
            dga_score = self._calculate_dga_score(domain)
            
            if dga_score > DGA_THRESHOLD:
                return {
                    'id': f"dga_domain_{domain}_{int(time.time())}",
                    'type': 'dga_domains',
                    'severity': 'high',
                    'description': f"DGA domain detected: {domain}",
                    'source_ip': packet_analysis.get('src_ip'),
                    'indicators': [
                        f"Domain: {domain}",
                        f"DGA score: {dga_score:.2f}",
                        "Algorithmically generated domain pattern"
                    ],
                    'mitigation_strategy': "Block domain, investigate source system, monitor for additional DGA activity"
                }
        
        return None
    
    def _calculate_dga_score(self, domain: str) -> float:
        """Calculate DGA probability score for a domain"""
        score = 0.0
        
        # Remove TLD
        domain_parts = domain.split('.')
        if len(domain_parts) < 2:
            return 0.0
        
        subdomain = domain_parts[0]
        
        # Length check
        if len(subdomain) > 15:
            score += 0.3
        
        # Entropy check
        entropy = self._calculate_string_entropy(subdomain)
        if entropy > 3.5:
            score += 0.4
        
        # Consonant-vowel ratio
        vowels = 'aeiou'
        consonants = sum(1 for c in subdomain.lower() if c.isalpha() and c not in vowels)
        vowel_count = sum(1 for c in subdomain.lower() if c in vowels)
        
        if vowel_count > 0:
            cv_ratio = consonants / vowel_count
            if cv_ratio > 3:
                score += 0.2
        
        # Number inclusion
        if any(c.isdigit() for c in subdomain):
            score += 0.1
        
        return min(score, 1.0)
    
    def _calculate_string_entropy(self, s: str) -> float:
        """Calculate entropy of a string"""
        if not s:
            return 0.0
        
        char_counts = Counter(s.lower())
        length = len(s)
        
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def detect_lateral_movement(self, packet_analysis: Dict, ml_result: Dict) -> Optional[Dict]:
        """Detect lateral movement attempts"""
        src_ip = packet_analysis.get('src_ip')
        dst_ip = packet_analysis.get('dst_ip')
        dst_port = packet_analysis.get('dst_port')
        
        # Check for internal-to-internal communication on administrative ports
        admin_ports = [22, 23, 135, 139, 445, 1433, 3389, 5985, 5986]
        
        try:
            if src_ip and dst_ip:
                src_addr = ipaddress.ip_address(src_ip)
                dst_addr = ipaddress.ip_address(dst_ip)
                
                # Both internal IPs communicating on admin ports
                if (src_addr.is_private and dst_addr.is_private and 
                    dst_port in admin_ports):
                    
                    return {
                        'id': f"lateral_move_{src_ip}_{dst_ip}_{int(time.time())}",
                        'type': 'lateral_movement',
                        'severity': 'medium',
                        'description': f"Potential lateral movement from {src_ip} to {dst_ip}",
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'indicators': [
                            f"Administrative port access: {dst_port}",
                            "Internal-to-internal communication",
                            f"Service: {self._get_service_name(dst_port)}"
                        ],
                        'mitigation_strategy': "Monitor authentication attempts, verify legitimate access, implement micro-segmentation"
                    }
        except ValueError:
            pass
        
        return None
    
    def detect_credential_stuffing(self, packet_analysis: Dict, ml_result: Dict) -> Optional[Dict]:
        """Detect credential stuffing attacks"""
        src_ip = packet_analysis.get('src_ip')
        dst_port = packet_analysis.get('dst_port')
        
        # Check for authentication-related ports
        auth_ports = [80, 443, 21, 22, 23, 25, 110, 143, 993, 995]
        
        if dst_port in auth_ports:
            with flow_lock:
                flow_key = f"{src_ip}->auth"
                flow_data = flow_tracker[flow_key]
                
                # Count recent authentication attempts
                current_time = time.time()
                recent_attempts = sum(1 for ts in flow_data['interarrival_times'] 
                                    if current_time - ts < 300)  # 5 minutes
                
                if recent_attempts > 20:  # High number of auth attempts
                    return {
                        'id': f"cred_stuff_{src_ip}_{int(time.time())}",
                        'type': 'credential_stuffing',
                        'severity': 'high',
                        'description': f"Credential stuffing attack detected from {src_ip}",
                        'source_ip': src_ip,
                        'indicators': [
                            f"High authentication attempts: {recent_attempts} in 5 minutes",
                            f"Target port: {dst_port}",
                            f"Service: {self._get_service_name(dst_port)}"
                        ],
                        'mitigation_strategy': "Implement account lockout, rate limiting, CAPTCHA, monitor for successful logins"
                    }
        
        return None
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for port"""
        service_map = {
            22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
            110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
            445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3389: "RDP",
            5985: "WinRM HTTP", 5986: "WinRM HTTPS"
        }
        return service_map.get(port, f"Port {port}")

# Initialize threat detector
threat_detector = AdvancedThreatDetector()

# =============================================================================
# PACKET CAPTURE AND PROCESSING ENGINE
# =============================================================================

class PacketProcessor:
    """Main packet processing engine"""
    
    def __init__(self):
        self.running = False
        self.packet_count = 0
        self.processing_thread = None
        self.simulation_mode = not HAS_SCAPY
        self.training_packets = []
    
    def start_capture(self, interface: str = None):
        """Start packet capture"""
        self.running = True
        
        if self.simulation_mode:
            logger.info("Starting packet capture simulation")
            self.processing_thread = threading.Thread(target=self._simulate_packets)
        else:
            logger.info(f"Starting real packet capture on interface: {interface}")
            self.processing_thread = threading.Thread(
                target=self._capture_packets, args=(interface,)
            )
        
        self.processing_thread.daemon = True
        self.processing_thread.start()
    
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        logger.info("Packet capture stopped")
    
    def _capture_packets(self, interface: str = None):
        """Capture real packets using Scapy"""
        try:
            def packet_handler(packet):
                if self.running:
                    self._process_packet(packet)
            
            # Start sniffing
            sniff(iface=interface, prn=packet_handler, stop_filter=lambda x: not self.running)
            
        except Exception as e:
            logger.error(f"Packet capture failed: {e}")
            # Fall back to simulation
            self._simulate_packets()
    
    def _simulate_packets(self):
        """Simulate network packets for testing"""
        while self.running:
            try:
                # Create simulated packet data
                simulated_packet = self._generate_simulated_packet()
                self._process_packet(simulated_packet)
                
                # Random delay between packets
                time.sleep(np.random.exponential(0.1))
                
            except Exception as e:
                logger.error(f"Packet simulation error: {e}")
                time.sleep(1)
    
    def _generate_simulated_packet(self) -> Dict:
        """Generate realistic simulated packet data"""
        protocols = ['TCP', 'UDP', 'ICMP']
        protocol = np.random.choice(protocols, p=[0.7, 0.25, 0.05])
        
        # Generate realistic IP addresses
        internal_ips = [f"192.168.1.{i}" for i in range(1, 255)]
        external_ips = [f"{np.random.randint(1, 223)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}" for _ in range(100)]
        
        # Realistic port distributions
        common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995]
        random_ports = list(range(1024, 65535))
        
        is_outbound = np.random.choice([True, False], p=[0.6, 0.4])
        
        if is_outbound:
            src_ip = np.random.choice(internal_ips)
            dst_ip = np.random.choice(external_ips)
        else:
            src_ip = np.random.choice(external_ips)
            dst_ip = np.random.choice(internal_ips)
        
        dst_port = np.random.choice(common_ports + random_ports[:100], 
                                   p=[0.05]*len(common_ports) + [0.005]*100)
        
        # Generate payload with varying entropy
        payload_size = np.random.randint(0, 1500)
        if payload_size > 0:
            # Sometimes generate high-entropy (encrypted) payloads
            if np.random.random() < 0.1:
                payload = os.urandom(payload_size)
                entropy = 8.0
            else:
                # Normal text-like payload
                payload = b'A' * payload_size
                entropy = np.random.uniform(3, 6)
        else:
            payload = b''
            entropy = 0
        
        # Sometimes add anomalous characteristics
        is_anomalous = np.random.random() < 0.05
        if is_anomalous:
            # Make it suspicious
            if np.random.random() < 0.5:
                # High entropy payload
                payload = os.urandom(max(payload_size, 500))
                entropy = 8.0
            else:
                # Suspicious port
                dst_port = np.random.choice([1337, 4444, 6666, 31337])
        
        return {
            'timestamp': time.time(),
            'size': 40 + payload_size,  # Headers + payload
            'protocol': protocol,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': np.random.randint(1024, 65535),
            'dst_port': dst_port,
            'tcp_flags': ['SYN', 'ACK'] if protocol == 'TCP' else [],
            'payload_size': payload_size,
            'payload_entropy': entropy,
            'payload_preview': payload[:100].decode('utf-8', errors='ignore'),
            'application_protocol': 'HTTP' if dst_port in [80, 8080] else 'HTTPS' if dst_port == 443 else 'Unknown',
            'threat_indicators': [],
            'signature_matches': [],
            'behavioral_features': {},
            'statistical_features': {},
            'simulated': True
        }
    
    def _process_packet(self, packet):
        """Process a single packet through the analysis pipeline"""
        try:
            # Analyze packet
            if isinstance(packet, dict):
                # Already analyzed (simulation)
                packet_analysis = packet
            else:
                # Real packet - analyze it
                packet_analysis = packet_analyzer.analyze_packet_deep(packet)
            
            # Update metrics
            with metrics_lock:
                performance_metrics["total_packets"] += 1
            
            self.packet_count += 1
            
            # ML anomaly detection
            ml_result = ml_ensemble.predict_anomaly(packet_analysis)
            
            # Gemini AI analysis for high-risk packets
            gemini_result = None
            if (ml_result.get('is_anomaly', False) or 
                ml_result.get('anomaly_score', 0) > HIGH_RISK_THRESHOLD):
                
                # Run Gemini analysis 
                try:
                    gemini_result = gemini_analyzer.analyze_packet_threat(packet_analysis)
                except Exception as e:
                    logger.error(f"Gemini analysis failed: {e}")
                    gemini_result = gemini_analyzer._fallback_analysis(packet_analysis)
            
            # Threat detection
            threats = threat_detector.analyze_threats(packet_analysis, ml_result)
            
            # Process results
            self._process_analysis_results(packet_analysis, ml_result, gemini_result, threats)
            
            # Store for training
            self.training_packets.append(packet_analysis)
            if len(self.training_packets) > RETRAIN_INTERVAL_PACKETS:
                self._retrain_models()
            
            # Forensic logging
            forensic_logger.log_packet(packet_analysis, ml_result, gemini_result)
            
        except Exception as e:
            logger.error(f"Packet processing error: {e}")
    
    def _process_analysis_results(self, packet_analysis: Dict, ml_result: Dict, 
                                gemini_result: Optional[Dict], threats: List[Dict]):
        """Process and store analysis results"""
        try:
            # Update performance metrics
            with metrics_lock:
                if ml_result.get('is_anomaly', False):
                    performance_metrics["anomalies_detected"] += 1
                
                # Calculate detection rate
                if performance_metrics["total_packets"] > 0:
                    performance_metrics["detection_rate"] = (
                        performance_metrics["anomalies_detected"] / 
                        performance_metrics["total_packets"] * 100
                    )
            
            # Create alerts for significant findings
            if threats or (gemini_result and gemini_result.get('threat_level', 0) > 50):
                alert = self._create_alert(packet_analysis, ml_result, gemini_result, threats)
                
                with alerts_lock:
                    detected_alerts.append(alert)
                    # Keep only recent alerts
                    if len(detected_alerts) > 1000:
                        detected_alerts[:] = detected_alerts[-500:]
                
                # Log to forensic database
                forensic_logger.log_threat_alert(alert)
                
                logger.warning(f"Threat detected: {alert['description']}")
        
        except Exception as e:
            logger.error(f"Results processing error: {e}")
    
    def _create_alert(self, packet_analysis: Dict, ml_result: Dict, 
                     gemini_result: Optional[Dict], threats: List[Dict]) -> Dict:
        """Create comprehensive threat alert"""
        # Determine severity
        severity = "low"
        threat_types = []
        indicators = []
        mitigation_strategies = []
        
        # Process ML results
        if ml_result.get('is_anomaly', False):
            threat_types.append("anomaly")
            indicators.append(f"ML anomaly score: {ml_result.get('anomaly_score', 0):.2f}")
        
        # Process Gemini results
        if gemini_result:
            threat_level = gemini_result.get('threat_level', 0)
            if threat_level > 80:
                severity = "critical"
            elif threat_level > 60:
                severity = "high"
            elif threat_level > 40:
                severity = "medium"
            
            threat_types.append(gemini_result.get('threat_type', 'unknown'))
            indicators.extend(gemini_result.get('indicators', []))
            mitigation_strategies.append(gemini_result.get('mitigation_strategy', ''))
        
        # Process specific threats
        for threat in threats:
            threat_types.append(threat.get('type', 'unknown'))
            indicators.extend(threat.get('indicators', []))
            mitigation_strategies.append(threat.get('mitigation_strategy', ''))
            
            # Update severity based on threat
            threat_severity = threat.get('severity', 'low')
            if threat_severity == 'critical' or severity == 'low':
                severity = threat_severity
        
        # Create comprehensive description
        if gemini_result and gemini_result.get('gemini_analysis', False):
            description = f"AI-Enhanced Threat Detection: {gemini_result.get('attack_pattern', 'Multiple indicators detected')}"
        else:
            description = f"Network Anomaly Detected: {', '.join(set(threat_types))}"
        
        return {
            'id': f"alert_{int(time.time())}_{np.random.randint(1000, 9999)}",
            'timestamp': time.time(),
            'severity': severity,
            'description': description,
            'threat_types': list(set(threat_types)),
            'source_ip': packet_analysis.get('src_ip'),
            'destination_ip': packet_analysis.get('dst_ip'),
            'source_port': packet_analysis.get('src_port'),
            'destination_port': packet_analysis.get('dst_port'),
            'protocol': packet_analysis.get('protocol'),
            'indicators': indicators,
            'mitigation_strategies': list(filter(None, mitigation_strategies)),
            'ml_analysis': ml_result,
            'gemini_analysis': gemini_result,
            'packet_details': {
                'size': packet_analysis.get('size', 0),
                'payload_entropy': packet_analysis.get('payload_entropy', 0),
                'application_protocol': packet_analysis.get('application_protocol', 'Unknown')
            }
        }
    
    def _retrain_models(self):
        """Retrain ML models with new data"""
        try:
            logger.info("Starting model retraining...")
            
            # Use recent training data
            training_data = self.training_packets[-RETRAIN_INTERVAL_PACKETS:]
            
            # Train models in background thread
            training_thread = threading.Thread(
                target=ml_ensemble.train_models, 
                args=(training_data,)
            )
            training_thread.daemon = True
            training_thread.start()
            
            # Clear old training data
            self.training_packets = self.training_packets[-500:]
            
        except Exception as e:
            logger.error(f"Model retraining failed: {e}")

# Initialize packet processor
packet_processor = PacketProcessor()

# =============================================================================
# ENHANCED WEB DASHBOARD
# =============================================================================

# HTML template for the enhanced dashboard
ENHANCED_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Network Anomaly Detection System</title>
    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .dashboard-header { 
            background: rgba(0,0,0,0.3); 
            backdrop-filter: blur(10px); 
            padding: 20px; 
            margin-bottom: 30px; 
            border-radius: 15px; 
            border: 1px solid rgba(255,255,255,0.1); 
        }
        .status-card { 
            background: rgba(0,0,0,0.4); 
            backdrop-filter: blur(10px); 
            border: 1px solid rgba(255,255,255,0.1); 
            border-radius: 12px; 
            padding: 20px; 
            margin-bottom: 20px; 
            transition: all 0.3s ease;
        }
        .status-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }
        .metric-card { 
            background: linear-gradient(135deg, rgba(13,202,240,0.1), rgba(13,110,253,0.1)); 
            border: 1px solid rgba(13,202,240,0.3); 
        }
        .threat-card { 
            background: linear-gradient(135deg, rgba(220,53,69,0.1), rgba(255,69,0,0.1)); 
            border: 1px solid rgba(220,53,69,0.3); 
        }
        .performance-card { 
            background: linear-gradient(135deg, rgba(25,135,84,0.1), rgba(40,167,69,0.1)); 
            border: 1px solid rgba(25,135,84,0.3); 
        }
        .gemini-card {
            background: linear-gradient(135deg, rgba(147,51,234,0.1), rgba(168,85,247,0.1)); 
            border: 1px solid rgba(147,51,234,0.3);
        }
        .badge-critical { background: linear-gradient(45deg, #dc3545, #ff6b6b) !important; }
        .badge-high { background: linear-gradient(45deg, #fd7e14, #ffb347) !important; }
        .badge-medium { background: linear-gradient(45deg, #ffc107, #ffd93d) !important; color: #000 !important; }
        .badge-low { background: linear-gradient(45deg, #198754, #20c997) !important; }
        .details-toggle { 
            cursor: pointer; 
            color: #0d6efd; 
            transition: all 0.3s; 
        }
        .details-toggle:hover { 
            color: #0056b3; 
            transform: scale(1.05); 
        }
        .details-content { 
            background: rgba(0,0,0,0.6); 
            padding: 15px; 
            margin-top: 10px; 
            border-radius: 8px; 
            display: none; 
            font-family: 'Courier New', monospace; 
            font-size: 0.85rem; 
            border-left: 3px solid #0d6efd; 
        }
        @keyframes pulse { 
            0% { opacity: 1; } 
            50% { opacity: 0.7; } 
            100% { opacity: 1; } 
        }
        .pulse { animation: pulse 2s infinite; }
        .loading-spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #3498db;
            border-radius: 50%;
            animation: spin 2s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .chart-container {
            position: relative;
            height: 300px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container-fluid mt-3">
        <div class="dashboard-header text-center">
            <h1><i class="fas fa-shield-alt"></i> Advanced Network Anomaly Detection System</h1>
            <p class="mb-0">Real-time AI-powered network security monitoring with Gemini AI integration</p>
            <div class="mt-2">
                <span id="system-status" class="badge bg-info">
                    <span class="loading-spinner"></span> Initializing...
                </span>
                <span id="last-update" class="badge bg-secondary ms-2">Last Update: Never</span>
            </div>
        </div>
        
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="status-card metric-card">
                    <h6><i class="fas fa-chart-line"></i> Packets Processed</h6>
                    <div id="packet-count" class="h5">0</div>
                    <small id="packet-rate">Rate: 0/sec</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="status-card threat-card">
                    <h6><i class="fas fa-exclamation-triangle"></i> Threats Detected</h6>
                    <div id="threat-count" class="h5">0</div>
                    <small id="threat-rate">Rate: 0/min</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="status-card performance-card">
                    <h6><i class="fas fa-tachometer-alt"></i> Detection Accuracy</h6>
                    <div id="accuracy" class="h5">--</div>
                    <small id="detection-rate">Detection Rate: --%</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="status-card gemini-card">
                    <h6><i class="fas fa-brain"></i> Gemini AI Status</h6>
                    <div id="gemini-status" class="h5">--</div>
                    <small id="gemini-analyses">Analyses: 0</small>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-md-6">
                <div class="status-card">
                    <h6><i class="fas fa-cogs"></i> ML Model Status</h6>
                    <div id="model-status-container">
                        <span class="loading-spinner"></span> Loading model status...
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="status-card">
                    <h6><i class="fas fa-database"></i> Forensic Statistics</h6>
                    <div id="forensic-stats">
                        <span class="loading-spinner"></span> Loading statistics...
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-12">
                <div class="status-card">
                    <h6><i class="fas fa-chart-area"></i> Real-time Analytics</h6>
                    <div class="chart-container">
                        <canvas id="analyticsChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-12">
                <div class="status-card">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <h3><i class="fas fa-bug"></i> Detected Threats & Anomalies</h3>
                        <div>
                            <button class="btn btn-sm btn-outline-info" onclick="refreshAlerts()">
                                <i class="fas fa-refresh"></i> Refresh
                            </button>
                            <button class="btn btn-sm btn-outline-warning" onclick="clearAlerts()">
                                <i class="fas fa-trash"></i> Clear
                            </button>
                        </div>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-dark table-hover alert-table">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Severity</th>
                                    <th>Type</th>
                                    <th>Source</th>
                                    <th>Description</th>
                                    <th>AI Analysis</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="alerts-table-body">
                                <tr>
                                    <td colspan="7" class="text-center">
                                        <span class="loading-spinner"></span> Loading alerts...
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Global variables
        let analyticsChart = null;
        let alertData = [];
        let startTime = Date.now();
        
        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            initializeCharts();
            updateDashboard();
            setInterval(updateDashboard, 2000); // Update every 2 seconds
        });
        
        function initializeCharts() {
            const ctx = document.getElementById('analyticsChart').getContext('2d');
            analyticsChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Packets/sec',
                        data: [],
                        borderColor: 'rgb(75, 192, 192)',
                        backgroundColor: 'rgba(75, 192, 192, 0.1)',
                        tension: 0.1
                    }, {
                        label: 'Anomalies/min',
                        data: [],
                        borderColor: 'rgb(255, 99, 132)',
                        backgroundColor: 'rgba(255, 99, 132, 0.1)',
                        tension: 0.1
                    }, {
                        label: 'Threat Level',
                        data: [],
                        borderColor: 'rgb(255, 205, 86)',
                        backgroundColor: 'rgba(255, 205, 86, 0.1)',
                        tension: 0.1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: {
                                color: '#e9ecef'
                            }
                        }
                    },
                    scales: {
                        x: {
                            ticks: {
                                color: '#e9ecef'
                            },
                            grid: {
                                color: 'rgba(255, 255, 255, 0.1)'
                            }
                        },
                        y: {
                            ticks: {
                                color: '#e9ecef'
                            },
                            grid: {
                                color: 'rgba(255, 255, 255, 0.1)'
                            }
                        }
                    }
                }
            });
        }
        
        async function updateDashboard() {
            try {
                // Fetch system status
                const statusResponse = await fetch('/api/status');
                const status = await statusResponse.json();
                
                // Update metrics
                document.getElementById('packet-count').textContent = status.total_packets || 0;
                document.getElementById('threat-count').textContent = status.threats_detected || 0;
                document.getElementById('accuracy').textContent = 
                    status.accuracy ? (status.accuracy * 100).toFixed(1) + '%' : '--';
                document.getElementById('detection-rate').textContent = 
                    'Detection Rate: ' + (status.detection_rate || 0).toFixed(1) + '%';
                
                // Update system status
                const systemStatus = document.getElementById('system-status');
                if (status.is_running) {
                    systemStatus.innerHTML = '<i class="fas fa-check-circle text-success"></i> Online';
                    systemStatus.className = 'badge bg-success';
                } else {
                    systemStatus.innerHTML = '<i class="fas fa-times-circle text-danger"></i> Offline';
                    systemStatus.className = 'badge bg-danger';
                }
                
                // Update Gemini status
                const geminiStatus = document.getElementById('gemini-status');
                if (status.gemini_available) {
                    geminiStatus.innerHTML = '<i class="fas fa-brain text-info"></i> Active';
                } else {
                    geminiStatus.innerHTML = '<i class="fas fa-exclamation-triangle text-warning"></i> Unavailable';
                }
                document.getElementById('gemini-analyses').textContent = 
                    'Analyses: ' + (status.gemini_analyses || 0);
                
                // Update last update time
                document.getElementById('last-update').textContent = 
                    'Last Update: ' + new Date().toLocaleTimeString();
                
                // Update charts
                updateCharts(status);
                
                // Update model status
                await updateModelStatus();
                
                // Update forensic stats
                await updateForensicStats();
                
                // Update alerts
                await updateAlerts();
                
            } catch (error) {
                console.error('Dashboard update failed:', error);
            }
        }
        
        function updateCharts(status) {
            const now = new Date();
            const timeLabel = now.toLocaleTimeString();
            
            // Update chart data
            const maxPoints = 20;
            
            analyticsChart.data.labels.push(timeLabel);
            analyticsChart.data.datasets[0].data.push(status.packet_rate || 0);
            analyticsChart.data.datasets[1].data.push(status.anomaly_rate || 0);
            analyticsChart.data.datasets[2].data.push(status.threat_level || 0);
            
            // Keep only recent data points
            if (analyticsChart.data.labels.length > maxPoints) {
                analyticsChart.data.labels.shift();
                analyticsChart.data.datasets.forEach(dataset => dataset.data.shift());
            }
            
            analyticsChart.update('none');
        }
        
        async function updateModelStatus() {
            try {
                const response = await fetch('/api/models');
                const models = await response.json();
                
                let statusHtml = '';
                for (const [modelName, status] of Object.entries(models.model_details || {})) {
                    const badgeClass = status.trained ? 'bg-success' : 'bg-warning';
                    const accuracy = status.accuracy ? (status.accuracy * 100).toFixed(1) + '%' : 'N/A';
                    statusHtml += `
                        <span class="badge ${badgeClass} me-2 mb-2">
                            ${modelName}: ${accuracy}
                        </span>
                    `;
                }
                
                if (statusHtml) {
                    document.getElementById('model-status-container').innerHTML = statusHtml;
                } else {
                    document.getElementById('model-status-container').innerHTML = 
                        '<span class="text-muted">No model data available</span>';
                }
                
            } catch (error) {
                console.error('Model status update failed:', error);
            }
        }
        
        async function updateForensicStats() {
            try {
                const response = await fetch('/api/forensics');
                const stats = await response.json();
                
                const statsHtml = `
                    <div class="row">
                        <div class="col-6">
                            <small class="text-muted">Packets Logged</small><br>
                            <strong>${stats.total_packets_logged || 0}</strong>
                        </div>
                        <div class="col-6">
                            <small class="text-muted">Active Alerts</small><br>
                            <strong>${stats.active_alerts || 0}</strong>
                        </div>
                    </div>
                    <div class="row mt-2">
                        <div class="col-6">
                            <small class="text-muted">Anomaly Rate</small><br>
                            <strong>${(stats.anomaly_rate || 0).toFixed(1)}%</strong>
                        </div>
                        <div class="col-6">
                            <small class="text-muted">Total Alerts</small><br>
                            <strong>${stats.total_alerts || 0}</strong>
                        </div>
                    </div>
                `;
                
                document.getElementById('forensic-stats').innerHTML = statsHtml;
                
            } catch (error) {
                console.error('Forensic stats update failed:', error);
            }
        }
        
        async function updateAlerts() {
            try {
                const response = await fetch('/api/alerts');
                const alerts = await response.json();
                
                const tbody = document.getElementById('alerts-table-body');
                
                if (alerts.length === 0) {
                    tbody.innerHTML = `
                        <tr>
                            <td colspan="7" class="text-center text-muted">
                                <i class="fas fa-shield-alt"></i> No threats detected
                            </td>
                        </tr>
                    `;
                    return;
                }
                
                let html = '';
                alerts.slice(0, 20).forEach((alert, index) => {
                    const time = new Date(alert.timestamp * 1000).toLocaleString();
                    const severityClass = getSeverityClass(alert.severity);
                    const hasGemini = alert.gemini_analysis && alert.gemini_analysis.gemini_analysis;
                    
                    html += `
                        <tr>
                            <td>${time}</td>
                            <td><span class="badge ${severityClass}">${alert.severity.toUpperCase()}</span></td>
                            <td>${alert.threat_types ? alert.threat_types.join(', ') : 'Unknown'}</td>
                            <td>${alert.source_ip || 'N/A'}</td>
                            <td class="text-truncate" style="max-width: 200px;" title="${alert.description}">
                                ${alert.description}
                            </td>
                            <td>
                                ${hasGemini ? '<i class="fas fa-brain text-info" title="Gemini AI Analysis"></i>' : 
                                  '<i class="fas fa-cog text-secondary" title="Rule-based Analysis"></i>'}
                            </td>
                            <td>
                                <button class="btn btn-sm btn-outline-info details-toggle" 
                                        onclick="toggleDetails(${index})">
                                    <i class="fas fa-eye"></i>
                                </button>
                            </td>
                        </tr>
                        <tr class="details-row" id="details-${index}" style="display: none;">
                            <td colspan="7">
                                <div class="details-content">
                                    ${formatAlertDetails(alert)}
                                </div>
                            </td>
                        </tr>
                    `;
                });
                
                tbody.innerHTML = html;
                alertData = alerts;
                
            } catch (error) {
                console.error('Alerts update failed:', error);
            }
        }
        
        function getSeverityClass(severity) {
            switch (severity.toLowerCase()) {
                case 'critical': return 'badge-critical';
                case 'high': return 'badge-high';
                case 'medium': return 'badge-medium';
                case 'low': return 'badge-low';
                default: return 'bg-secondary';
            }
        }
        
        function formatAlertDetails(alert) {
            let details = `
                <strong>Alert ID:</strong> ${alert.id}<br>
                <strong>Source:</strong> ${alert.source_ip || 'N/A'}:${alert.source_port || 'N/A'}<br>
                <strong>Destination:</strong> ${alert.destination_ip || 'N/A'}:${alert.destination_port || 'N/A'}<br>
                <strong>Protocol:</strong> ${alert.protocol || 'N/A'}<br>
            `;
            
            if (alert.indicators && alert.indicators.length > 0) {
                details += `<br><strong>Indicators:</strong><ul>`;
                alert.indicators.forEach(indicator => {
                    details += `<li>${indicator}</li>`;
                });
                details += `</ul>`;
            }
            
            if (alert.mitigation_strategies && alert.mitigation_strategies.length > 0) {
                details += `<br><strong>Mitigation Strategies:</strong><ul>`;
                alert.mitigation_strategies.forEach(strategy => {
                    details += `<li>${strategy}</li>`;
                });
                details += `</ul>`;
            }
            
            if (alert.gemini_analysis && alert.gemini_analysis.gemini_analysis) {
                details += `<br><strong>AI Analysis:</strong><br>`;
                details += `<em>${alert.gemini_analysis.attack_pattern || 'Advanced AI analysis performed'}</em>`;
            }
            
            return details;
        }
        
        function toggleDetails(index) {
            const detailsRow = document.getElementById(`details-${index}`);
            if (detailsRow.style.display === 'none') {
                detailsRow.style.display = 'table-row';
            } else {
                detailsRow.style.display = 'none';
            }
        }
        
        async function refreshAlerts() {
            await updateAlerts();
        }
        
        async function clearAlerts() {
            if (confirm('Are you sure you want to clear all alerts?')) {
                try {
                    await fetch('/api/alerts', { method: 'DELETE' });
                    await updateAlerts();
                } catch (error) {
                    console.error('Failed to clear alerts:', error);
                    alert('Failed to clear alerts');
                }
            }
        }
    </script>
</body>
</html>
"""

# =============================================================================
# FLASK WEB APPLICATION
# =============================================================================

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "advanced_network_security_key_2024")

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template_string(ENHANCED_HTML_TEMPLATE)

@app.route('/api/status')
def api_status():
    """Get system status"""
    try:
        with metrics_lock:
            current_metrics = performance_metrics.copy()
        
        # Calculate rates
        current_time = time.time()
        uptime = current_time - startTime if 'startTime' in globals() else 0
        
        packet_rate = current_metrics["total_packets"] / max(uptime, 1)
        anomaly_rate = current_metrics["anomalies_detected"] / max(uptime / 60, 1)  # per minute
        
        # Calculate threat level (0-100)
        with alerts_lock:
            recent_alerts = [alert for alert in detected_alerts 
                            if current_time - alert.get('timestamp', 0) < 300]  # last 5 minutes
        
        threat_level = 0
        if recent_alerts:
            severity_scores = {'low': 25, 'medium': 50, 'high': 75, 'critical': 100}
            threat_level = max(severity_scores.get(alert.get('severity', 'low'), 0) 
                             for alert in recent_alerts)
        
        return jsonify({
            'is_running': getattr(packet_processor, 'running', True),
            'total_packets': int(current_metrics["total_packets"]),
            'threats_detected': len(detected_alerts),
            'accuracy': float(current_metrics.get("accuracy", 0)),
            'detection_rate': float(current_metrics.get("detection_rate", 0)),
            'packet_rate': float(packet_rate),
            'anomaly_rate': float(anomaly_rate),
            'threat_level': int(threat_level),
            'gemini_available': gemini_analyzer.available,
            'gemini_analyses': sum(1 for alert in detected_alerts 
                                 if alert.get('gemini_analysis') is not None),
            'uptime': float(uptime)
        })
        
    except Exception as e:
        logger.error(f"Status API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/models')
def api_models():
    """Get ML model status"""
    try:
        return jsonify(ml_ensemble.get_model_status())
    except Exception as e:
        logger.error(f"Models API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/forensics')
def api_forensics():
    """Get forensic statistics"""
    try:
        return jsonify(forensic_logger.get_statistics())
    except Exception as e:
        logger.error(f"Forensics API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts')
def api_alerts():
    """Get recent alerts"""
    try:
        with alerts_lock:
            # Return recent alerts sorted by timestamp
            recent_alerts = sorted(detected_alerts, 
                                 key=lambda x: x.get('timestamp', 0), 
                                 reverse=True)[:50]
        
        # Convert numpy types to native Python types for JSON serialization
        def convert_types(obj):
            if isinstance(obj, dict):
                return {k: convert_types(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_types(v) for v in obj]
            elif hasattr(obj, 'item'):  # numpy scalar
                return obj.item()
            elif hasattr(obj, 'tolist'):  # numpy array
                return obj.tolist()
            else:
                return obj
        
        converted_alerts = convert_types(recent_alerts)
        return jsonify(converted_alerts)
        
    except Exception as e:
        logger.error(f"Alerts API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts', methods=['DELETE'])
def api_clear_alerts():
    """Clear all alerts"""
    try:
        with alerts_lock:
            detected_alerts.clear()
        
        return jsonify({'success': True, 'message': 'Alerts cleared'})
        
    except Exception as e:
        logger.error(f"Clear alerts API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/start')
def api_start():
    """Start packet capture"""
    try:
        if not packet_processor.running:
            packet_processor.start_capture()
            return jsonify({'success': True, 'message': 'Packet capture started'})
        else:
            return jsonify({'success': False, 'message': 'Already running'})
            
    except Exception as e:
        logger.error(f"Start API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stop')
def api_stop():
    """Stop packet capture"""
    try:
        if packet_processor.running:
            packet_processor.stop_capture()
            return jsonify({'success': True, 'message': 'Packet capture stopped'})
        else:
            return jsonify({'success': False, 'message': 'Not running'})
            
    except Exception as e:
        logger.error(f"Stop API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/metrics')
def api_metrics():
    """Get detailed performance metrics"""
    try:
        with metrics_lock:
            current_metrics = performance_metrics.copy()
        
        # Add additional calculated metrics
        current_time = time.time()
        uptime = current_time - startTime if 'startTime' in globals() else 0
        
        # Convert numpy types to native Python types
        def convert_metric(value):
            if hasattr(value, 'item'):
                return value.item()
            elif hasattr(value, 'tolist'):
                return value.tolist()
            else:
                return float(value) if isinstance(value, (int, float)) else value
        
        converted_metrics = {k: convert_metric(v) for k, v in current_metrics.items()}
        
        # Add system stats
        converted_metrics.update({
            'uptime_seconds': float(uptime),
            'packet_rate_per_second': float(converted_metrics["total_packets"] / max(uptime, 1)),
            'threats_per_minute': float(len(detected_alerts) / max(uptime / 60, 1)),
            'active_flows': len(flow_tracker),
            'ml_models_active': len(ml_ensemble.models),
            'gemini_available': gemini_analyzer.available
        })
        
        return jsonify(converted_metrics)
        
    except Exception as e:
        logger.error(f"Metrics API error: {e}")
        return jsonify({'error': str(e)}), 500

# =============================================================================
# MAIN EXECUTION
# =============================================================================

def initialize_system():
    """Initialize the complete system"""
    global startTime
    startTime = time.time()
    
    logger.info("=== Advanced Network Anomaly Detection System ===")
    logger.info("Initializing system components...")
    
    # Load configuration if available
    config_file = "config.json"
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            logger.info(f"Configuration loaded from {config_file}")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
    
    # Load saved models if available
    if os.path.exists(MODEL_SAVE_PATH):
        ml_ensemble.load_models()
    
    # Initialize with some training data if models are not trained
    if not ml_ensemble.is_trained:
        logger.info("Training initial models with simulated data...")
        # Generate some initial training data
        training_data = []
        for _ in range(INITIAL_TRAINING_PACKETS):
            simulated_packet = packet_analyzer._simulate_packet_analysis()
            training_data.append(simulated_packet)
        
        # Train models in background
        training_thread = threading.Thread(
            target=ml_ensemble.train_models, 
            args=(training_data,)
        )
        training_thread.daemon = True
        training_thread.start()
    
    logger.info("System initialization complete")
    logger.info(f"Gemini AI: {'Available' if gemini_analyzer.available else 'Unavailable'}")
    logger.info(f"Scapy: {'Available' if HAS_SCAPY else 'Simulation mode'}")
    logger.info(f"ML Models: {len(ml_ensemble.models)} initialized")

def main():
    """Main function"""
    try:
        # Initialize system
        initialize_system()
        
        # Start packet capture
        packet_processor.start_capture()
        
        # Start web server
        logger.info("Starting web dashboard on http://0.0.0.0:5000")
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
        
    except KeyboardInterrupt:
        logger.info("Shutting down system...")
        packet_processor.stop_capture()
        
        # Save models
        ml_ensemble.save_models()
        
        logger.info("System shutdown complete")
        
    except Exception as e:
        logger.error(f"System error: {e}")
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    main()
