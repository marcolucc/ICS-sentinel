# Update the MITRE mapper with Marco's information and clean up AI language
mitre_mapper_code = '''"""
MITRE ATT&CK for ICS Integration Module

Provides integration with the MITRE ATT&CK for ICS framework for automatic 
threat categorization, technique mapping, and tactical analysis of detected 
security events in industrial environments.

Author: Marco Lucchese
Email: marco.lucchese@gmx.com
Date: September 2025
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
from pathlib import Path
import re


class MitreMapper:
    """
    MITRE ATT&CK for ICS Framework Integration
    
    Automated mapping of detected threats to MITRE ATT&CK for ICS
    tactics, techniques, and sub-techniques.
    """
    
    # MITRE ATT&CK for ICS Tactics
    ICS_TACTICS = {
        "TA0108": {
            "name": "Initial Access",
            "description": "Getting into ICS network",
            "techniques": ["T0817", "T0818", "T0819", "T0886", "T0883", "T0866", 
                          "T0822", "T0860", "T0859", "T0847", "T0848", "T0865"]
        },
        "TA0104": {
            "name": "Execution", 
            "description": "Running malicious code",
            "techniques": ["T0871", "T0873", "T0874", "T0875", "T0807", 
                          "T0823", "T0834", "T0853", "T0863", "T0858"]
        },
        "TA0110": {
            "name": "Persistence",
            "description": "Maintaining foothold",
            "techniques": ["T0889", "T0839", "T0891", "T0857", "T0859", "T0864"]
        },
        "TA0111": {
            "name": "Privilege Escalation", 
            "description": "Gaining higher-level permissions",
            "techniques": ["T0890", "T0874"]
        },
        "TA0103": {
            "name": "Evasion",
            "description": "Avoiding detection",
            "techniques": ["T0872", "T0820", "T0849", "T0851", "T0856", "T0892", "T0882"]
        },
        "TA0102": {
            "name": "Discovery",
            "description": "Learning about environment", 
            "techniques": ["T0840", "T0842", "T0846", "T0888", "T0887"]
        },
        "TA0109": {
            "name": "Lateral Movement",
            "description": "Moving through environment",
            "techniques": ["T0812", "T0867", "T0886", "T0859", "T0868", "T0869", "T0880"]
        },
        "TA0100": {
            "name": "Collection",
            "description": "Gathering data of interest",
            "techniques": ["T0802", "T0830", "T0845", "T0852", "T0861", "T0877", 
                          "T0893", "T0894", "T0835", "T0821", "T0883"]
        },
        "TA0101": {
            "name": "Command and Control",
            "description": "Communicating with compromised systems",
            "techniques": ["T0885", "T0884", "T0869"]
        },
        "TA0107": {
            "name": "Inhibit Response Function",
            "description": "Preventing safety/protection functions",
            "techniques": ["T0800", "T0878", "T0803", "T0804", "T0809", "T0881", 
                          "T0814", "T0816", "T0815", "T0892", "T0838", "T0851", 
                          "T0855", "T0856"]
        },
        "TA0106": {
            "name": "Impair Process Control", 
            "description": "Manipulating control systems",
            "techniques": ["T0806", "T0836", "T0879", "T0839", "T0856"]
        },
        "TA0105": {
            "name": "Impact",
            "description": "Manipulating, interrupting, or destroying systems",
            "techniques": ["T0809", "T0813", "T0815", "T0826", "T0827", "T0828", 
                          "T0829", "T0831", "T0832", "T0880", "T0837", "T0841"]
        }
    }
    
    # Key ICS techniques with details
    TECHNIQUE_DETAILS = {
        "T0817": {
            "name": "Drive-by Compromise", 
            "description": "Access through compromised websites",
            "detection": ["Web proxy logs", "DNS queries", "Network traffic analysis"],
            "platforms": ["Windows", "Human-Machine Interface"]
        },
        "T0883": {
            "name": "Internet Accessible Device",
            "description": "Leveraging internet accessible devices", 
            "detection": ["External scanning", "Unusual external connections"],
            "platforms": ["Control Server", "Data Historian", "Human-Machine Interface"]
        },
        "T0866": {
            "name": "Exploitation of Remote Services",
            "description": "Exploiting remote services for access",
            "detection": ["Authentication failures", "Remote access logs", "Protocol anomalies"],
            "platforms": ["Control Server", "Engineering Workstation", "Human-Machine Interface"]
        },
        "T0871": {
            "name": "Execution through API",
            "description": "Executing code through application APIs",
            "detection": ["API call monitoring", "Process execution logs"],
            "platforms": ["Control Server", "Data Historian", "Human-Machine Interface"]
        },
        "T0807": {
            "name": "Command-Line Interface", 
            "description": "Abusing command-line interfaces",
            "detection": ["Command-line auditing", "Process monitoring"],
            "platforms": ["Engineering Workstation", "Human-Machine Interface", "Control Server"]
        },
        "T0889": {
            "name": "Modify Program",
            "description": "Modifying programs for persistence",
            "detection": ["File integrity monitoring", "Program change detection"],
            "platforms": ["Engineering Workstation", "Human-Machine Interface", "Control Server"]
        }
    }
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize MITRE ATT&CK mapper."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Load custom mappings if available
        self.custom_mappings = self._load_custom_mappings()
        
        # Cache for analysis
        self.analysis_cache = {}
        
        self.logger.info("MITRE ATT&CK mapper initialized")
        
    def _load_custom_mappings(self) -> Dict[str, Any]:
        """Load custom technique mappings."""
        mappings_path = self.config.get("mitre", {}).get("custom_mappings_file")
        
        if mappings_path and Path(mappings_path).exists():
            try:
                with open(mappings_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.warning(f"Could not load custom mappings: {e}")
                
        return {}
        
    def map_threat_to_mitre(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map detected threat to MITRE ATT&CK for ICS framework.
        """
        try:
            mapping_result = {
                "threat_id": threat.get("id"),
                "timestamp": datetime.now().isoformat(),
                "tactics": [],
                "techniques": [],
                "confidence": 0.0,
                "analysis": {}
            }
            
            # Extract threat indicators
            indicators = self._extract_threat_indicators(threat)
            
            # Map based on threat type
            threat_type = threat.get("type", "unknown")
            
            if threat_type == "sigma_detection":
                mapping_result = self._map_sigma_detection(threat, indicators)
            elif threat_type == "ml_anomaly":
                mapping_result = self._map_anomaly_detection(threat, indicators)
            elif threat_type == "protocol_violation":
                mapping_result = self._map_protocol_violation(threat, indicators)
            else:
                mapping_result = self._generic_threat_mapping(threat, indicators)
                
            # Add technique details
            mapping_result = self._enrich_with_technique_details(mapping_result)
            
            self.logger.debug(f"Mapped threat {threat.get('id')} to {len(mapping_result['techniques'])} techniques")
            
            return mapping_result
            
        except Exception as e:
            self.logger.error(f"Error mapping threat: {str(e)}")
            return {"error": str(e), "threat_id": threat.get("id")}
            
    def _extract_threat_indicators(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant indicators from threat data."""
        indicators = {
            "severity": threat.get("severity", "unknown"),
            "protocol": None,
            "src_ip": None,
            "dst_ip": None,
            "function_code": None,
            "command": None,
            "file_path": None,
            "process_name": None
        }
        
        # Extract from packet data
        packet_data = threat.get("packet_data", {})
        if packet_data:
            indicators.update({
                "protocol": packet_data.get("protocol"),
                "src_ip": packet_data.get("src_ip"), 
                "dst_ip": packet_data.get("dst_ip"),
                "function_code": packet_data.get("function_code"),
                "modbus_function": packet_data.get("modbus_function"),
                "dnp3_function": packet_data.get("dnp3_function"),
                "opc_method": packet_data.get("opc_method")
            })
            
        # Extract from Sigma rule matches
        if threat.get("type") == "sigma_detection":
            sigma_data = threat.get("raw_match", {})
            indicators["rule_tags"] = sigma_data.get("tags", [])
            indicators["rule_level"] = sigma_data.get("level")
            
        return indicators
        
    def _map_sigma_detection(self, threat: Dict[str, Any], indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Map Sigma rule detection to MITRE techniques."""
        mapping = {
            "threat_id": threat.get("id"),
            "mapping_type": "sigma_rules",
            "tactics": [],
            "techniques": [],
            "confidence": 0.8,
            "analysis": {
                "rule_title": threat.get("rule_title"),
                "rule_id": threat.get("rule_id"),
                "detection_method": "signature_based"
            }
        }
        
        # Extract MITRE techniques from Sigma rule tags
        mitre_techniques = threat.get("mitre_techniques", [])
        
        for technique_id in mitre_techniques:
            clean_id = technique_id.replace("attack.", "").upper()
            if clean_id.startswith("T"):
                mapping["techniques"].append(clean_id)
                
                # Map technique to tactic
                tactic = self._get_tactic_for_technique(clean_id)
                if tactic and tactic not in mapping["tactics"]:
                    mapping["tactics"].append(tactic)
                    
        # If no explicit MITRE tags, infer from rule content
        if not mapping["techniques"]:
            mapping = self._infer_techniques_from_sigma(threat, indicators, mapping)
            
        return mapping
        
    def _map_anomaly_detection(self, threat: Dict[str, Any], indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Map ML anomaly detection to MITRE techniques."""
        mapping = {
            "threat_id": threat.get("id"),
            "mapping_type": "ml_inference", 
            "tactics": [],
            "techniques": [],
            "confidence": 0.6,
            "analysis": {
                "anomaly_score": threat.get("anomaly_score"),
                "detection_method": "behavioral_analysis"
            }
        }
        
        protocol = indicators.get("protocol")
        anomaly_score = threat.get("anomaly_score", 0)
        
        # High anomaly scores suggest advanced techniques
        if anomaly_score > 0.8:
            mapping["confidence"] = 0.7
            
            if protocol in ["modbus", "dnp3"]:
                mapping["techniques"].extend(["T0856", "T0839"])
                mapping["tactics"].extend(["TA0106", "TA0107"])
                
        elif anomaly_score > 0.5:
            mapping["techniques"].extend(["T0842", "T0845"])
            mapping["tactics"].extend(["TA0102", "TA0100"])
            
        return mapping
        
    def _map_protocol_violation(self, threat: Dict[str, Any], indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Map protocol violations to MITRE techniques."""
        mapping = {
            "threat_id": threat.get("id"),
            "mapping_type": "protocol_analysis",
            "tactics": [],
            "techniques": [],
            "confidence": 0.7,
            "analysis": {
                "protocol": indicators.get("protocol"),
                "detection_method": "protocol_validation"
            }
        }
        
        protocol = indicators.get("protocol")
        
        if protocol == "modbus":
            function_code = indicators.get("modbus_function")
            if function_code in [15, 16]:  # Write functions
                mapping["techniques"].append("T0839")
                mapping["tactics"].append("TA0106")
                
        elif protocol == "dnp3":
            mapping["techniques"].append("T0842")
            mapping["tactics"].append("TA0102")
            
        elif protocol == "opc_ua":
            mapping["techniques"].append("T0845")
            mapping["tactics"].append("TA0100")
            
        return mapping
        
    def _generic_threat_mapping(self, threat: Dict[str, Any], indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Generic threat mapping."""
        mapping = {
            "threat_id": threat.get("id"),
            "mapping_type": "generic_inference",
            "tactics": ["TA0102"],
            "techniques": ["T0842"],
            "confidence": 0.3,
            "analysis": {
                "detection_method": "generic_pattern_matching"
            }
        }
        
        severity = indicators.get("severity", "").lower()
        
        if severity == "high":
            mapping["tactics"].append("TA0105")
            mapping["techniques"].append("T0826")
            mapping["confidence"] = 0.5
            
        return mapping
        
    def _infer_techniques_from_sigma(self, threat: Dict[str, Any], indicators: Dict[str, Any], mapping: Dict[str, Any]) -> Dict[str, Any]:
        """Infer MITRE techniques from Sigma rule content."""
        rule_title = threat.get("rule_title", "").lower()
        rule_desc = threat.get("description", "").lower()
        
        # Pattern matching
        patterns = {
            "authentication": ["T0859"],
            "brute.?force": ["T0859", "T0866"],
            "command.?line": ["T0807"],
            "file.?modification": ["T0889"],
            "network.?scan": ["T0842"],
            "privilege.?escalation": ["T0890"],
            "persistence": ["T0889"],
            "lateral.?movement": ["T0867"],
            "data.?exfiltration": ["T0845"]
        }
        
        text_to_analyze = f"{rule_title} {rule_desc}"
        
        for pattern, techniques in patterns.items():
            if re.search(pattern, text_to_analyze):
                mapping["techniques"].extend(techniques)
                
                for technique in techniques:
                    tactic = self._get_tactic_for_technique(technique)
                    if tactic and tactic not in mapping["tactics"]:
                        mapping["tactics"].append(tactic)
                        
        # Remove duplicates
        mapping["techniques"] = list(set(mapping["techniques"]))
        mapping["tactics"] = list(set(mapping["tactics"]))
        
        return mapping
        
    def _get_tactic_for_technique(self, technique_id: str) -> Optional[str]:
        """Get tactic ID for given technique ID."""
        for tactic_id, tactic_data in self.ICS_TACTICS.items():
            if technique_id in tactic_data["techniques"]:
                return tactic_id
        return None
        
    def _enrich_with_technique_details(self, mapping: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich mapping with technique information."""
        enriched_techniques = []
        
        for technique_id in mapping.get("techniques", []):
            technique_info = {
                "id": technique_id,
                "name": self.TECHNIQUE_DETAILS.get(technique_id, {}).get("name", "Unknown"),
                "description": self.TECHNIQUE_DETAILS.get(technique_id, {}).get("description", ""),
                "detection_methods": self.TECHNIQUE_DETAILS.get(technique_id, {}).get("detection", []),
                "platforms": self.TECHNIQUE_DETAILS.get(technique_id, {}).get("platforms", [])
            }
            enriched_techniques.append(technique_info)
            
        mapping["technique_details"] = enriched_techniques
        
        # Enrich tactics
        enriched_tactics = []
        for tactic_id in mapping.get("tactics", []):
            tactic_info = {
                "id": tactic_id,
                "name": self.ICS_TACTICS.get(tactic_id, {}).get("name", "Unknown"),
                "description": self.ICS_TACTICS.get(tactic_id, {}).get("description", "")
            }
            enriched_tactics.append(tactic_info)
            
        mapping["tactic_details"] = enriched_tactics
        
        return mapping
        
    def analyze_threats(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze multiple threats and generate MITRE ATT&CK summary."""
        analysis = {
            "summary": {
                "total_threats": len(threats),
                "mapped_threats": 0,
                "unique_tactics": set(),
                "unique_techniques": set(),
                "confidence_distribution": {"high": 0, "medium": 0, "low": 0}
            },
            "tactic_breakdown": {},
            "technique_frequency": {},
            "threat_mappings": [],
            "recommendations": [],
            "coverage_analysis": {}
        }
        
        # Analyze each threat
        for threat in threats:
            mapping = self.map_threat_to_mitre(threat)
            
            if "error" not in mapping:
                analysis["summary"]["mapped_threats"] += 1
                analysis["threat_mappings"].append(mapping)
                
                # Collect tactics and techniques
                for tactic in mapping.get("tactics", []):
                    analysis["summary"]["unique_tactics"].add(tactic)
                    analysis["tactic_breakdown"][tactic] = analysis["tactic_breakdown"].get(tactic, 0) + 1
                    
                for technique in mapping.get("techniques", []):
                    analysis["summary"]["unique_techniques"].add(technique)
                    analysis["technique_frequency"][technique] = analysis["technique_frequency"].get(technique, 0) + 1
                    
                # Confidence distribution
                confidence = mapping.get("confidence", 0)
                if confidence >= 0.7:
                    analysis["summary"]["confidence_distribution"]["high"] += 1
                elif confidence >= 0.4:
                    analysis["summary"]["confidence_distribution"]["medium"] += 1
                else:
                    analysis["summary"]["confidence_distribution"]["low"] += 1
                    
        # Convert sets to lists
        analysis["summary"]["unique_tactics"] = list(analysis["summary"]["unique_tactics"])
        analysis["summary"]["unique_techniques"] = list(analysis["summary"]["unique_techniques"])
        
        # Generate recommendations
        analysis["recommendations"] = self._generate_recommendations(analysis)
        
        # Coverage analysis
        analysis["coverage_analysis"] = self._analyze_coverage(analysis)
        
        return analysis
        
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate security recommendations."""
        recommendations = []
        
        # Check for high-risk tactics
        high_risk_tactics = ["TA0105", "TA0106", "TA0107"]
        
        for tactic_id in high_risk_tactics:
            if tactic_id in analysis["tactic_breakdown"]:
                count = analysis["tactic_breakdown"][tactic_id]
                tactic_name = self.ICS_TACTICS[tactic_id]["name"]
                
                recommendations.append({
                    "priority": "high",
                    "category": "detection",
                    "title": f"Enhanced Monitoring for {tactic_name}",
                    "description": f"Detected {count} threats using {tactic_name} tactics.",
                    "mitre_tactic": tactic_id
                })
                
        return recommendations
        
    def _analyze_coverage(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze MITRE ATT&CK coverage."""
        total_tactics = len(self.ICS_TACTICS)
        covered_tactics = len(analysis["summary"]["unique_tactics"])
        
        total_techniques = sum(len(data["techniques"]) for data in self.ICS_TACTICS.values())
        covered_techniques = len(analysis["summary"]["unique_techniques"])
        
        return {
            "tactic_coverage": {
                "covered": covered_tactics,
                "total": total_tactics,
                "percentage": (covered_tactics / total_tactics) * 100
            },
            "technique_coverage": {
                "covered": covered_techniques,  
                "total": total_techniques,
                "percentage": (covered_techniques / total_techniques) * 100
            }
        }
'''

# Save updated MITRE mapper
with open('mitre_mapper.py', 'w') as f:
    f.write(mitre_mapper_code)

print("✅ Updated MITRE mapper with Marco's information")