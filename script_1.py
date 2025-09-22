"""
ICS Security Sentinel - Main Framework Class

Industrial Control Systems Security Monitoring and Threat Detection Framework

Author: Marco Lucchese
Email: marco.lucchese@gmx.com
Date: September 2025
"""

import asyncio
import logging
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
import json

from .core.protocol_monitor import ProtocolMonitor
from .core.threat_detector import ThreatDetector  
from .core.mitre_mapper import MitreMapper
from .core.sigma_engine import SigmaEngine
from .utils.logger import SecurityLogger
from .utils.config_manager import ConfigManager
from .utils.report_generator import ReportGenerator


class SecuritySentinel:
    """
    Main ICS Security Sentinel Framework Class
    
    Provides security monitoring and threat detection capabilities
    for Industrial Control Systems and OT networks.
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """
        Initialize Security Sentinel framework.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.get_config()
        
        # Initialize logging
        self.logger = SecurityLogger(
            name="SecuritySentinel",
            level=self.config.get("logging", {}).get("level", "INFO"),
            log_file=self.config.get("logging", {}).get("file", "logs/sentinel.log")
        )
        
        # Initialize core components
        self.protocol_monitor = ProtocolMonitor(self.config)
        self.threat_detector = ThreatDetector(self.config)
        self.mitre_mapper = MitreMapper(self.config)
        self.sigma_engine = SigmaEngine(self.config)
        self.report_generator = ReportGenerator(self.config)
        
        # Runtime state
        self.monitoring_active = False
        self.monitoring_thread = None
        self.detected_threats = []
        self.network_baseline = {}
        self.start_time = None
        
        # Event callbacks
        self.threat_callbacks: List[Callable] = []
        self.alert_callbacks: List[Callable] = []
        
        self.logger.info("ICS Security Sentinel initialized")
        
    def start_monitoring(self, 
                        interface: str = "eth0",
                        protocols: List[str] = None,
                        enable_ml_detection: bool = True) -> bool:
        """
        Start real-time ICS network monitoring and threat detection.
        
        Args:
            interface: Network interface to monitor
            protocols: List of protocols to analyze
            enable_ml_detection: Enable ML-based anomaly detection
            
        Returns:
            bool: True if monitoring started successfully
        """
        if self.monitoring_active:
            self.logger.warning("Monitoring already active")
            return False
            
        try:
            if protocols is None:
                protocols = ["modbus", "dnp3", "opc_ua"]
                
            self.logger.info(f"Starting ICS monitoring on {interface}")
            self.logger.info(f"Protocols: {protocols}")
            
            # Configure protocol monitor
            self.protocol_monitor.configure(
                interface=interface,
                protocols=protocols,
                packet_callback=self._handle_packet
            )
            
            # Configure threat detector
            if enable_ml_detection:
                self.threat_detector.enable_ml_detection()
                self.logger.info("ML detection enabled")
                
            # Start monitoring thread
            self.monitoring_active = True
            self.start_time = datetime.now()
            self.monitoring_thread = threading.Thread(
                target=self._monitoring_loop,
                daemon=True
            )
            self.monitoring_thread.start()
            
            self.logger.info("ICS monitoring started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {str(e)}")
            self.monitoring_active = False
            return False
            
    def stop_monitoring(self) -> bool:
        """Stop ICS network monitoring."""
        if not self.monitoring_active:
            return False
            
        try:
            self.logger.info("Stopping monitoring...")
            self.monitoring_active = False
            
            self.protocol_monitor.stop()
            
            if self.monitoring_thread and self.monitoring_thread.is_alive():
                self.monitoring_thread.join(timeout=5.0)
                
            self.logger.info("Monitoring stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping monitoring: {str(e)}")
            return False
            
    def _monitoring_loop(self):
        """Internal monitoring loop."""
        self.logger.info("Starting monitoring loop")
        
        while self.monitoring_active:
            try:
                # Process network packets
                self.protocol_monitor.process_packets()
                
                # Run threat detection
                self._run_periodic_detection()
                
                # Update baseline
                self._update_baseline()
                
                time.sleep(0.1)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(1.0)
                
        self.logger.info("Monitoring loop terminated")
        
    def _handle_packet(self, packet_data: Dict[str, Any]):
        """
        Handle network packets from protocol monitor.
        
        Args:
            packet_data: Parsed packet information
        """
        try:
            protocol = packet_data.get("protocol")
            src_ip = packet_data.get("src_ip")
            dst_ip = packet_data.get("dst_ip")
            timestamp = packet_data.get("timestamp", time.time())
            
            # Run Sigma rule detection
            sigma_matches = self.sigma_engine.evaluate_packet(packet_data)
            if sigma_matches:
                self._handle_sigma_detection(sigma_matches, packet_data)
                
            # Run ML anomaly detection
            if self.threat_detector.ml_enabled:
                anomaly_score = self.threat_detector.detect_anomaly(packet_data)
                if anomaly_score > self.threat_detector.anomaly_threshold:
                    self._handle_anomaly_detection(anomaly_score, packet_data)
                    
            # Update statistics
            self.protocol_monitor.update_statistics(packet_data)
            
            self.logger.debug(f"Processed {protocol} packet: {src_ip} -> {dst_ip}")
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")
            
    def _handle_sigma_detection(self, matches: List[Dict], packet_data: Dict):
        """Handle Sigma rule matches."""
        for match in matches:
            threat = {
                "id": f"sigma_{int(time.time())}_{hash(str(match)) % 10000}",
                "type": "sigma_detection", 
                "timestamp": time.time(),
                "severity": match.get("level", "medium"),
                "rule_id": match.get("id"),
                "rule_title": match.get("title"),
                "description": match.get("description"),
                "mitre_techniques": match.get("tags", {}).get("attack", []),
                "packet_data": packet_data,
                "raw_match": match
            }
            
            self.detected_threats.append(threat)
            self._trigger_threat_callbacks(threat)
            
            self.logger.warning(
                f"Sigma detection: {match.get('title')} "
                f"(Severity: {threat['severity']})"
            )
            
    def _handle_anomaly_detection(self, score: float, packet_data: Dict):
        """Handle ML anomaly detections."""
        threat = {
            "id": f"anomaly_{int(time.time())}_{hash(str(packet_data)) % 10000}",
            "type": "ml_anomaly",
            "timestamp": time.time(), 
            "severity": "high" if score > 0.8 else "medium",
            "anomaly_score": score,
            "description": f"Network anomaly detected (score: {score:.3f})",
            "packet_data": packet_data
        }
        
        self.detected_threats.append(threat)
        self._trigger_threat_callbacks(threat)
        
        self.logger.warning(f"Anomaly detected: score {score:.3f}")
        
    def _run_periodic_detection(self):
        """Run periodic threat detection tasks."""
        current_time = time.time()
        
        # Behavioral analysis
        behavioral_threats = self.threat_detector.analyze_behavior(
            self.protocol_monitor.get_recent_activity(minutes=5)
        )
        
        for threat in behavioral_threats:
            self.detected_threats.append(threat)
            self._trigger_threat_callbacks(threat)
            
    def _update_baseline(self):
        """Update network baseline."""
        stats = self.protocol_monitor.get_statistics()
        self.network_baseline.update(stats)
        
    def _trigger_threat_callbacks(self, threat: Dict):
        """Trigger threat detection callbacks."""
        for callback in self.threat_callbacks:
            try:
                callback(threat)
            except Exception as e:
                self.logger.error(f"Error in threat callback: {str(e)}")
                
    def add_threat_callback(self, callback: Callable[[Dict], None]):
        """Add callback for threat detections."""
        self.threat_callbacks.append(callback)
        
    def generate_security_report(self, 
                                timeframe: str = "24h",
                                include_mitre_mapping: bool = True,
                                format: str = "json") -> Dict[str, Any]:
        """
        Generate security report.
        
        Args:
            timeframe: Time period for report
            include_mitre_mapping: Include MITRE ATT&CK mapping
            format: Output format
            
        Returns:
            Security report data
        """
        try:
            self.logger.info(f"Generating report for {timeframe}")
            
            # Parse timeframe
            end_time = time.time()
            if timeframe.endswith("h"):
                hours = int(timeframe[:-1])
                start_time = end_time - (hours * 3600)
            elif timeframe.endswith("d"):
                days = int(timeframe[:-1])
                start_time = end_time - (days * 86400)
            else:
                start_time = end_time - 86400
                
            # Filter threats by timeframe
            period_threats = [
                t for t in self.detected_threats 
                if start_time <= t["timestamp"] <= end_time
            ]
            
            # Generate report data
            report_data = {
                "metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "timeframe": timeframe,
                    "start_time": datetime.fromtimestamp(start_time).isoformat(),
                    "end_time": datetime.fromtimestamp(end_time).isoformat(),
                    "format": format
                },
                "summary": {
                    "total_threats": len(period_threats),
                    "high_severity": len([t for t in period_threats if t.get("severity") == "high"]),
                    "medium_severity": len([t for t in period_threats if t.get("severity") == "medium"]), 
                    "low_severity": len([t for t in period_threats if t.get("severity") == "low"]),
                    "uptime": self._calculate_uptime()
                },
                "threats": period_threats,
                "network_statistics": self.protocol_monitor.get_statistics(),
                "protocol_analysis": self._analyze_protocol_activity(period_threats)
            }
            
            # Add MITRE analysis if requested
            if include_mitre_mapping:
                report_data["mitre_analysis"] = self.mitre_mapper.analyze_threats(
                    period_threats
                )
                
            # Generate formatted report
            formatted_report = self.report_generator.generate_report(
                report_data, format
            )
            
            self.logger.info("Security report generated")
            return formatted_report
            
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            return {"error": str(e)}
            
    def _calculate_uptime(self) -> str:
        """Calculate monitoring uptime."""
        if not self.start_time:
            return "0s"
            
        uptime_seconds = (datetime.now() - self.start_time).total_seconds()
        
        if uptime_seconds < 60:
            return f"{int(uptime_seconds)}s"
        elif uptime_seconds < 3600:
            return f"{int(uptime_seconds / 60)}m"
        elif uptime_seconds < 86400:
            return f"{int(uptime_seconds / 3600)}h"
        else:
            return f"{int(uptime_seconds / 86400)}d"
            
    def _analyze_protocol_activity(self, threats: List[Dict]) -> Dict[str, Any]:
        """Analyze protocol-specific threat activity."""
        analysis = {
            "modbus": {"threats": 0, "common_attacks": []},
            "dnp3": {"threats": 0, "common_attacks": []},
            "opc_ua": {"threats": 0, "common_attacks": []}
        }
        
        for threat in threats:
            protocol = threat.get("packet_data", {}).get("protocol")
            if protocol in analysis:
                analysis[protocol]["threats"] += 1
                
        return analysis
        
    def get_status(self) -> Dict[str, Any]:
        """Get current system status."""
        return {
            "monitoring_active": self.monitoring_active,
            "uptime": self._calculate_uptime(),
            "total_threats_detected": len(self.detected_threats),
            "recent_threats": len([
                t for t in self.detected_threats 
                if time.time() - t["timestamp"] < 3600
            ]),
            "protocols_monitored": self.protocol_monitor.get_active_protocols(),
            "ml_detection_enabled": self.threat_detector.ml_enabled,
            "sigma_rules_loaded": self.sigma_engine.get_rules_count()
        }
