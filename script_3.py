"""
Sigma Rules Engine for ICS Environments

Custom Sigma rules engine designed for Industrial Control Systems,
with support for Modbus, DNP3, OPC UA, and other industrial protocols.

Author: Marco Lucchese
Email: marco.lucchese@gmx.com
Date: September 2025
"""

import yaml
import re
import logging
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import fnmatch


class SigmaEngine:
    """
    Sigma Rules Engine for ICS Security
    
    Processes Sigma rules designed for industrial environments
    and provides real-time threat detection capabilities.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Sigma rules engine."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Storage for loaded rules
        self.rules: List[Dict[str, Any]] = []
        self.compiled_rules: List[Dict[str, Any]] = []
        
        # Performance metrics
        self.rule_stats = {
            "total_rules": 0,
            "evaluations": 0,
            "matches": 0,
            "false_positives": 0
        }
        
        # Load rules
        self._load_rules()
        
        self.logger.info(f"Sigma engine initialized with {len(self.rules)} rules")
        
    def _load_rules(self):
        """Load Sigma rules from configured directories."""
        rules_config = self.config.get("sigma", {})
        
        # Load from rules directory
        rules_dir = rules_config.get("rules_directory", "config/sigma_rules/")
        if Path(rules_dir).exists():
            self._load_rules_from_directory(rules_dir)
            
        # Load built-in ICS rules
        if rules_config.get("load_builtin_rules", True):
            self._load_builtin_ics_rules()
            
        # Compile all rules
        self._compile_rules()
        
    def _load_rules_from_directory(self, rules_dir: str):
        """Load Sigma rules from directory."""
        rules_path = Path(rules_dir)
        
        for rule_file in rules_path.glob("*.yml"):
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule_content = yaml.safe_load(f)
                    
                if self._validate_rule(rule_content):
                    rule_content["source_file"] = str(rule_file)
                    self.rules.append(rule_content)
                    self.logger.debug(f"Loaded rule: {rule_content.get('title', 'Unknown')}")
                else:
                    self.logger.warning(f"Invalid rule in {rule_file}")
                    
            except Exception as e:
                self.logger.error(f"Error loading rule from {rule_file}: {str(e)}")
                
    def _load_builtin_ics_rules(self):
        """Load built-in ICS-specific Sigma rules."""
        builtin_rules = [
            # Modbus Function Code Anomaly
            {
                "title": "Suspicious Modbus Function Code",
                "id": "ics-001-modbus-suspicious-function",
                "status": "experimental",
                "description": "Detects suspicious Modbus function codes that may indicate attack activity",
                "author": "Marco Lucchese",
                "date": "2025/09/22",
                "level": "medium",
                "logsource": {
                    "product": "ics_monitor",
                    "service": "modbus"
                },
                "detection": {
                    "selection": {
                        "protocol": "modbus",
                        "function_code": [90, 100, 110, 120, 125]
                    },
                    "condition": "selection"
                },
                "falsepositives": [
                    "Custom Modbus implementations",
                    "Vendor-specific function codes"
                ],
                "tags": [
                    "attack.discovery",
                    "attack.t0842"
                ]
            },
            
            # Modbus Unauthorized Write
            {
                "title": "Modbus Unauthorized Write Operations",
                "id": "ics-002-modbus-unauthorized-write", 
                "status": "experimental",
                "description": "Detects unauthorized write operations to Modbus devices",
                "author": "Marco Lucchese",
                "date": "2025/09/22",
                "level": "high",
                "logsource": {
                    "product": "ics_monitor",
                    "service": "modbus"
                },
                "detection": {
                    "selection": {
                        "protocol": "modbus",
                        "function_code": [5, 6, 15, 16],
                        "src_ip": "!192.168.100.*"
                    },
                    "condition": "selection"
                },
                "falsepositives": [
                    "Legitimate engineering operations",
                    "Automated control systems"
                ],
                "tags": [
                    "attack.impair_process_control",
                    "attack.t0839"
                ]
            },
            
            # DNP3 Authentication Failure
            {
                "title": "DNP3 Authentication Failures",
                "id": "ics-003-dnp3-auth-failure",
                "status": "experimental", 
                "description": "Detects multiple DNP3 authentication failures indicating brute force attack",
                "author": "Marco Lucchese",
                "date": "2025/09/22",
                "level": "medium",
                "logsource": {
                    "product": "ics_monitor",
                    "service": "dnp3"
                },
                "detection": {
                    "selection": {
                        "protocol": "dnp3",
                        "auth_result": "failed"
                    },
                    "timeframe": "5m",
                    "condition": "selection | count() > 5"
                },
                "falsepositives": [
                    "Clock synchronization issues",
                    "Network connectivity problems"
                ],
                "tags": [
                    "attack.initial_access",
                    "attack.t0859"
                ]
            },
            
            # OPC UA Certificate Anomaly
            {
                "title": "OPC UA Invalid Certificate",
                "id": "ics-004-opcua-cert-anomaly",
                "status": "experimental",
                "description": "Detects OPC UA connections with invalid certificates",
                "author": "Marco Lucchese", 
                "date": "2025/09/22",
                "level": "high",
                "logsource": {
                    "product": "ics_monitor",
                    "service": "opcua"
                },
                "detection": {
                    "selection": {
                        "protocol": "opc_ua",
                        "cert_valid": "false"
                    },
                    "condition": "selection"
                },
                "falsepositives": [
                    "Expired certificates during maintenance",
                    "Self-signed certificates in test environments"
                ],
                "tags": [
                    "attack.evasion",
                    "attack.t0851"
                ]
            },
            
            # PLC Programming Change
            {
                "title": "Unauthorized PLC Programming Changes",
                "id": "ics-005-plc-program-change",
                "status": "experimental",
                "description": "Detects unauthorized changes to PLC programming",
                "author": "Marco Lucchese",
                "date": "2025/09/22", 
                "level": "critical",
                "logsource": {
                    "product": "ics_monitor",
                    "service": "plc"
                },
                "detection": {
                    "selection": {
                        "event_type": "program_download",
                        "user": "!engineering_*"
                    },
                    "condition": "selection"
                },
                "falsepositives": [
                    "Emergency maintenance operations",
                    "Scheduled updates during maintenance windows"
                ],
                "tags": [
                    "attack.persistence",
                    "attack.t0889",
                    "attack.impair_process_control",
                    "attack.t0856"
                ]
            },
            
            # HMI Suspicious Login
            {
                "title": "Suspicious HMI Login Activity",
                "id": "ics-006-hmi-suspicious-login",
                "status": "experimental",
                "description": "Detects suspicious login patterns to HMI systems",
                "author": "Marco Lucchese",
                "date": "2025/09/22",
                "level": "medium",
                "logsource": {
                    "product": "ics_monitor", 
                    "service": "hmi"
                },
                "detection": {
                    "selection": {
                        "event_type": "login",
                        "time": "!08:00-18:00"
                    },
                    "condition": "selection"
                },
                "falsepositives": [
                    "Shift workers",
                    "Maintenance personnel",
                    "24/7 operations"
                ],
                "tags": [
                    "attack.initial_access",
                    "attack.t0859"
                ]
            },
            
            # Network Segmentation Violation
            {
                "title": "ICS Network Segmentation Violation", 
                "id": "ics-007-segmentation-violation",
                "status": "experimental",
                "description": "Detects communication crossing ICS network boundaries",
                "author": "Marco Lucchese",
                "date": "2025/09/22",
                "level": "high",
                "logsource": {
                    "product": "ics_monitor",
                    "service": "network"
                },
                "detection": {
                    "selection": {
                        "src_zone": "corporate",
                        "dst_zone": "control"
                    },
                    "condition": "selection"
                },
                "falsepositives": [
                    "Authorized cross-zone services", 
                    "Historian data collection",
                    "Engineering workstation access"
                ],
                "tags": [
                    "attack.lateral_movement",
                    "attack.t0867"
                ]
            }
        ]
        
        # Add builtin rules
        for rule in builtin_rules:
            if self._validate_rule(rule):
                rule["source_file"] = "builtin"
                self.rules.append(rule)
                
        self.logger.info(f"Loaded {len(builtin_rules)} built-in ICS Sigma rules")
        
    def _validate_rule(self, rule: Dict[str, Any]) -> bool:
        """Validate Sigma rule structure."""
        required_fields = ["title", "detection"]
        
        for field in required_fields:
            if field not in rule:
                self.logger.warning(f"Rule missing required field: {field}")
                return False
                
        detection = rule.get("detection", {})
        if "condition" not in detection:
            self.logger.warning("Rule missing detection condition")
            return False
            
        return True
        
    def _compile_rules(self):
        """Compile Sigma rules for efficient evaluation."""
        self.compiled_rules = []
        
        for rule in self.rules:
            try:
                compiled_rule = self._compile_rule(rule)
                if compiled_rule:
                    self.compiled_rules.append(compiled_rule)
                    
            except Exception as e:
                self.logger.error(f"Error compiling rule {rule.get('title', 'Unknown')}: {str(e)}")
                
        self.rule_stats["total_rules"] = len(self.compiled_rules)
        self.logger.info(f"Compiled {len(self.compiled_rules)} Sigma rules")
        
    def _compile_rule(self, rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Compile single Sigma rule for evaluation."""
        detection = rule.get("detection", {})
        condition = detection.get("condition", "")
        
        compiled_rule = {
            "id": rule.get("id", "unknown"),
            "title": rule.get("title", "Unknown Rule"),
            "level": rule.get("level", "medium"),
            "description": rule.get("description", ""),
            "tags": rule.get("tags", []),
            "falsepositives": rule.get("falsepositives", []),
            "source_file": rule.get("source_file", "unknown"),
            "logsource": rule.get("logsource", {}),
            "original_rule": rule,
            "detection_logic": {}
        }
        
        # Compile detection selections
        for key, value in detection.items():
            if key != "condition":
                compiled_rule["detection_logic"][key] = self._compile_selection(value)
                
        # Compile condition logic
        compiled_rule["condition"] = self._compile_condition(condition)
        
        return compiled_rule
        
    def _compile_selection(self, selection: Dict[str, Any]) -> Dict[str, Any]:
        """Compile detection selection for efficient matching."""
        compiled_selection = {}
        
        for field, criteria in selection.items():
            if isinstance(criteria, str):
                if criteria.startswith("!"):
                    # Negation
                    compiled_selection[field] = {
                        "type": "not_equals",
                        "value": criteria[1:],
                        "compiled_pattern": self._compile_pattern(criteria[1:])
                    }
                else:
                    compiled_selection[field] = {
                        "type": "equals",
                        "value": criteria,
                        "compiled_pattern": self._compile_pattern(criteria)
                    }
                    
            elif isinstance(criteria, list):
                # Multiple values (OR logic)
                compiled_patterns = []
                for value in criteria:
                    if isinstance(value, str):
                        compiled_patterns.append({
                            "value": value,
                            "pattern": self._compile_pattern(value)
                        })
                        
                compiled_selection[field] = {
                    "type": "in_list",
                    "values": criteria,
                    "compiled_patterns": compiled_patterns
                }
                
            elif isinstance(criteria, dict):
                # Complex criteria
                compiled_selection[field] = {
                    "type": "complex",
                    "criteria": criteria
                }
                
        return compiled_selection
        
    def _compile_pattern(self, pattern: str) -> Any:
        """Compile string pattern for efficient matching."""
        if "*" in pattern or "?" in pattern:
            # Wildcard pattern
            return {
                "type": "wildcard",
                "pattern": pattern
            }
        elif pattern.startswith("/") and pattern.endswith("/"):
            # Regex pattern
            try:
                regex_pattern = re.compile(pattern[1:-1], re.IGNORECASE)
                return {
                    "type": "regex",
                    "pattern": regex_pattern
                }
            except re.error as e:
                self.logger.warning(f"Invalid regex pattern {pattern}: {str(e)}")
                return {
                    "type": "literal",
                    "pattern": pattern
                }
        else:
            # Literal match
            return {
                "type": "literal", 
                "pattern": pattern.lower()
            }
            
    def _compile_condition(self, condition: str) -> Dict[str, Any]:
        """Compile Sigma rule condition."""
        condition = condition.strip()
        
        if "|" in condition:
            # Contains aggregation
            parts = condition.split("|")
            selection_part = parts[0].strip()
            aggregation_part = "|".join(parts[1:]).strip()
            
            return {
                "type": "aggregation",
                "selection": selection_part,
                "aggregation": aggregation_part
            }
        else:
            # Simple selection
            return {
                "type": "simple",
                "selection": condition
            }
            
    def evaluate_packet(self, packet_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate network packet against all Sigma rules.
        
        Args:
            packet_data: Parsed packet information
            
        Returns:
            List of matching rules
        """
        matches = []
        self.rule_stats["evaluations"] += 1
        
        for rule in self.compiled_rules:
            try:
                if self._evaluate_rule_against_packet(rule, packet_data):
                    match_info = {
                        "rule_id": rule["id"],
                        "title": rule["title"],
                        "level": rule["level"],
                        "description": rule["description"],
                        "tags": rule["tags"],
                        "matched_at": datetime.now().isoformat(),
                        "packet_info": {
                            "protocol": packet_data.get("protocol"),
                            "src_ip": packet_data.get("src_ip"),
                            "dst_ip": packet_data.get("dst_ip"),
                            "timestamp": packet_data.get("timestamp")
                        }
                    }
                    matches.append(match_info)
                    self.rule_stats["matches"] += 1
                    
            except Exception as e:
                self.logger.error(f"Error evaluating rule {rule['id']}: {str(e)}")
                
        return matches
        
    def _evaluate_rule_against_packet(self, rule: Dict[str, Any], packet_data: Dict[str, Any]) -> bool:
        """Evaluate single rule against packet data."""
        # Check logsource
        logsource = rule.get("logsource", {})
        if logsource:
            product = logsource.get("product")
            service = logsource.get("service")
            
            if product and packet_data.get("product") != product:
                return False
            if service and packet_data.get("protocol") != service:
                return False
                
        # Evaluate condition
        condition = rule.get("condition", {})
        
        if condition.get("type") == "simple":
            selection_name = condition.get("selection")
            return self._evaluate_selection(rule["detection_logic"].get(selection_name, {}), packet_data)
            
        elif condition.get("type") == "aggregation":
            # For packet-level evaluation, treat as simple match
            selection_name = condition.get("selection")
            return self._evaluate_selection(rule["detection_logic"].get(selection_name, {}), packet_data)
            
        return False
        
    def _evaluate_selection(self, selection: Dict[str, Any], packet_data: Dict[str, Any]) -> bool:
        """Evaluate detection selection against packet data."""
        if not selection:
            return False
            
        # All conditions must match (AND logic)
        for field_name, field_criteria in selection.items():
            field_value = packet_data.get(field_name)
            
            if not self._match_field_criteria(field_value, field_criteria):
                return False
                
        return True
        
    def _match_field_criteria(self, field_value: Any, criteria: Dict[str, Any]) -> bool:
        """Match field value against compiled criteria."""
        if field_value is None:
            return False
            
        criteria_type = criteria.get("type")
        
        if criteria_type == "equals":
            return self._match_pattern(str(field_value), criteria.get("compiled_pattern", {}))
            
        elif criteria_type == "not_equals":
            return not self._match_pattern(str(field_value), criteria.get("compiled_pattern", {}))
            
        elif criteria_type == "in_list":
            for pattern_info in criteria.get("compiled_patterns", []):
                if self._match_pattern(str(field_value), pattern_info.get("pattern", {})):
                    return True
            return False
            
        elif criteria_type == "complex":
            # Handle complex criteria
            complex_criteria = criteria.get("criteria", {})
            
            # Numeric range example
            if "gte" in complex_criteria or "lte" in complex_criteria:
                try:
                    numeric_value = float(field_value)
                    if "gte" in complex_criteria and numeric_value < float(complex_criteria["gte"]):
                        return False
                    if "lte" in complex_criteria and numeric_value > float(complex_criteria["lte"]):
                        return False
                    return True
                except (ValueError, TypeError):
                    return False
                    
        return False
        
    def _match_pattern(self, value: str, pattern_info: Dict[str, Any]) -> bool:
        """Match value against compiled pattern."""
        pattern_type = pattern_info.get("type")
        pattern = pattern_info.get("pattern")
        
        if pattern_type == "literal":
            return value.lower() == pattern
            
        elif pattern_type == "wildcard":
            return fnmatch.fnmatch(value.lower(), pattern.lower())
            
        elif pattern_type == "regex":
            return bool(pattern.search(value))
            
        return False
        
    def get_rules_count(self) -> int:
        """Get total number of loaded rules."""
        return len(self.compiled_rules)
        
    def get_rule_statistics(self) -> Dict[str, Any]:
        """Get Sigma engine statistics."""
        stats = self.rule_stats.copy()
        
        if stats["evaluations"] > 0:
            stats["match_rate"] = (stats["matches"] / stats["evaluations"]) * 100
        else:
            stats["match_rate"] = 0.0
            
        return stats
        
    def get_rules_by_level(self) -> Dict[str, int]:
        """Get rule count by severity level."""
        level_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        
        for rule in self.compiled_rules:
            level = rule.get("level", "medium")
            if level in level_counts:
                level_counts[level] += 1
                
        return level_counts
        
    def export_rules_summary(self) -> Dict[str, Any]:
        """Export summary of all loaded rules."""
        rules_summary = {
            "total_rules": len(self.compiled_rules),
            "by_level": self.get_rules_by_level(),
            "by_source": {},
            "rules_list": []
        }
        
        # Count by source
        for rule in self.compiled_rules:
            source = rule.get("source_file", "unknown")
            rules_summary["by_source"][source] = rules_summary["by_source"].get(source, 0) + 1
            
            # Add to rules list
            rules_summary["rules_list"].append({
                "id": rule.get("id"),
                "title": rule.get("title"), 
                "level": rule.get("level"),
                "source": source,
                "tags": rule.get("tags", [])
            })
            
        return rules_summary
