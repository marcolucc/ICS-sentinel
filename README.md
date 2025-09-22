# ICS Security Sentinel 🛡️

**Industrial Control Systems Security Monitoring and Threat Detection Framework**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-ICS-red)](https://attack.mitre.org/matrices/ics/)
[![Docker](https://img.shields.io/badge/docker-supported-blue)](https://www.docker.com/)

## Overview

ICS Security Sentinel is a cybersecurity framework for monitoring and protecting Industrial Control Systems (ICS), SCADA networks, and Operational Technology (OT) environments. It provides real-time threat detection, behavioral analysis, and automated incident response for industrial environments.

### Key Features

- **Multi-Protocol Support**: Native analysis for Modbus, DNP3, OPC UA protocols
- **MITRE ATT&CK Integration**: Complete mapping to MITRE ATT&CK for ICS tactics and techniques
- **Sigma Rules Engine**: Custom Sigma rules for ICS-specific threat detection
- **Behavioral Analysis**: Machine learning algorithms for anomaly detection
- **Real-time Monitoring**: Continuous monitoring of OT network traffic
- **Compliance Support**: IEC 62443, NIST CSF, NIS 2 compliance reporting
- **Docker Deployment**: Containerized for easy deployment and scaling
- **Modular Architecture**: Extensible plugin system for custom protocols

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   ICS Network   │────│  Traffic Mirror │────│ Security Sensor │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
┌─────────────────────────────────────────────────────▼─────────────┐
│                    ICS Security Sentinel                           │
├─────────────────┬─────────────────┬─────────────────┬─────────────┤
│ Protocol Engine │ Detection Engine│  MITRE Mapper   │ Sigma Rules │
├─────────────────┼─────────────────┼─────────────────┼─────────────┤
│ • Modbus        │ • Anomaly Det.  │ • Tactic Map    │ • Custom    │
│ • DNP3          │ • Signature     │ • Technique ID  │ • Community │
│ • OPC UA        │ • Behavioral    │ • IOCs          │ • Validated │
└─────────────────┴─────────────────┴─────────────────┴─────────────┘
                                   │
┌─────────────────────────────────▼─────────────────────────────────┐
│                        Output & Response                           │
├─────────────────┬─────────────────┬─────────────────┬─────────────┤
│    Alerting     │    Reporting    │     Logging     │ Integration │
│                 │                 │                 │             │
│ • SIEM Forward  │ • Risk Assess.  │ • Structured    │ • REST API  │
│ • Email Alerts  │ • Compliance    │ • JSON/CSV      │ • Webhooks  │
│ • Webhooks      │ • Executive     │ • Syslog        │ • Splunk    │
└─────────────────┴─────────────────┴─────────────────┴─────────────┘
```

## Quick Start

### Prerequisites
- Python 3.8+
- Docker (recommended)
- Network access to ICS/OT infrastructure
- Root privileges for packet capture

### Installation

```bash
# Clone the repository
git clone https://github.com/marcolucc/ics-sentinel.git
cd ics-sentinel

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Configure
cp config/config.example.yaml config/config.yaml
# Edit config.yaml with your network settings
```

### Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f sentinel
```

### Basic Usage

```python
from ics_security_sentinel import SecuritySentinel

# Initialize the framework
sentinel = SecuritySentinel(config_path="config/config.yaml")

# Start monitoring
sentinel.start_monitoring(
    interface="eth0",
    protocols=["modbus", "dnp3", "opc_ua"],
    enable_ml_detection=True
)

# Generate security report
report = sentinel.generate_security_report(
    timeframe="24h",
    include_mitre_mapping=True,
    format="json"
)
```

## MITRE ATT&CK for ICS Coverage

Detection capabilities for MITRE ATT&CK for ICS tactics:

| Tactic | Techniques | Detection Methods |
|--------|-----------|------------------|
| Initial Access | 8/12 | Network monitoring, Protocol analysis |
| Execution | 7/10 | Command monitoring, Process analysis |
| Persistence | 4/6 | Configuration monitoring, File integrity |
| Evasion | 5/7 | Traffic analysis, Behavioral detection |
| Discovery | 5/5 | Network mapping, Asset discovery |
| Lateral Movement | 6/7 | Traffic correlation, Network analysis |
| Collection | 8/11 | Data flow monitoring, Asset tracking |
| Command and Control | 3/3 | Communication analysis, C2 detection |
| Inhibit Response | 10/14 | System integrity monitoring |
| Impair Process Control | 4/5 | Process monitoring, Control logic analysis |
| Impact | 8/12 | Safety system monitoring, Process analysis |

## Custom Sigma Rules

Includes 25+ custom Sigma rules for ICS environments:

- **Modbus Function Code Anomalies**: Detects unusual Modbus function codes
- **DNP3 Authentication Failures**: Identifies authentication bypass attempts  
- **OPC UA Certificate Anomalies**: Monitors certificate-based attacks
- **PLC Programming Changes**: Detects unauthorized logic modifications
- **HMI Connection Anomalies**: Identifies suspicious HMI access patterns
- **Network Segmentation Violations**: Detects cross-zone communications

## Configuration

### Protocol Configuration

```yaml
protocols:
  modbus:
    enabled: true
    ports: [502]
    detect_anomalous_functions: true

  dnp3:
    enabled: true  
    ports: [20000]
    monitor_authentication: true

  opc_ua:
    enabled: true
    ports: [4840]
    certificate_validation: true
```

### Detection Configuration

```yaml
detection:
  machine_learning:
    enabled: true
    model: "isolation_forest"
    sensitivity: 0.1

  sigma_rules:
    enabled: true
    rules_directory: "config/sigma_rules/"

  mitre_mapping:
    enabled: true
    auto_tag: true
```

## Testing

```bash
# Run tests
python -m pytest tests/ -v

# Performance tests
python scripts/performance_test.py

# Coverage report
coverage run -m pytest tests/
coverage report -m
```



## Contributing

Contributions welcome! Please contact me directly.

### Development Setup

```bash
git clone https://github.com/marcolucc/ics-sentinel.git
cd ics-sentinel

# Install development dependencies
pip install -r requirements-dev.txt
pre-commit install

# Run linting
black src/ tests/
flake8 src/ tests/
```

## License

MIT License.

## Author

**Marco Lucchese**
- Email: marco.lucchese@gmx.com
- GitHub: [@marcolucc](https://github.com/marcolucc)



---

*This project is for legitimate security research and defensive purposes. Ensure compliance with applicable laws and regulations.*
