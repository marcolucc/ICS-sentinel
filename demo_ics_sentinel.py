"""
ICS Security Sentinel - Demonstration Script

Interactive demonstration of the ICS Security Sentinel framework
showing core capabilities including monitoring, threat detection, and reporting.

Author: Marco Lucchese
Email: marco.lucchese@gmx.com
"""

import asyncio
import argparse
import time
import signal
import sys
from pathlib import Path
import json

# Import framework (with fallback for demo)
try:
    from ics_security_sentinel import SecuritySentinel
except ImportError:
    print("Running in demo mode with mock implementation")

    class SecuritySentinel:
        def __init__(self, config_path):
            self.config_path = config_path
            self.monitoring_active = False
            self.detected_threats = []

        def start_monitoring(self, interface="eth0", protocols=None, enable_ml_detection=True):
            print(f"Starting monitoring on {interface}")
            print(f"Protocols: {protocols or ['modbus', 'dnp3', 'opc_ua']}")
            print(f"ML Detection: {'Enabled' if enable_ml_detection else 'Disabled'}")
            self.monitoring_active = True
            return True

        def stop_monitoring(self):
            print("Stopping monitoring...")
            self.monitoring_active = False
            return True

        def get_status(self):
            return {
                "monitoring_active": self.monitoring_active,
                "uptime": "2h 35m",
                "total_threats_detected": len(self.detected_threats),
                "recent_threats": 3,
                "protocols_monitored": ["modbus", "dnp3", "opc_ua"],
                "ml_detection_enabled": True,
                "sigma_rules_loaded": 25
            }

        def generate_security_report(self, timeframe="24h", include_mitre_mapping=True, format="json"):
            return {
                "metadata": {
                    "generated_at": "2025-09-22T15:30:00Z",
                    "timeframe": timeframe,
                    "format": format
                },
                "summary": {
                    "total_threats": 12,
                    "high_severity_threats": 2,
                    "medium_severity_threats": 7,
                    "low_severity_threats": 3,
                    "monitoring_uptime": "99.8%"
                },
                "mitre_analysis": {
                    "tactics_detected": ["TA0102", "TA0100", "TA0105"],
                    "techniques_detected": ["T0842", "T0845", "T0826"],
                    "coverage_percentage": 23.5
                } if include_mitre_mapping else None
            }


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    print("\nReceived shutdown signal. Cleaning up...")
    sys.exit(0)


def print_banner():
    """Print application banner."""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                        ICS Security Sentinel v1.0.0                         ║
║                Industrial Control Systems Security Framework                  ║
║                                                                              ║  
║              Developed by Marco Lucchese - September 2025                    ║
║                                                                              ║
║  🏭 OT/ICS Security Monitoring    🔍 Real-time Threat Detection              ║
║  🎯 MITRE ATT&CK Integration      📊 Comprehensive Reporting                 ║
║  🛡️ Sigma Rules Engine           🤖 ML-powered Analysis                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_status(sentinel):
    """Print current system status."""
    status = sentinel.get_status()

    print("\nSystem Status:")
    print("=" * 50)
    print(f"Monitoring Active:     {status['monitoring_active']}")
    print(f"System Uptime:        {status['uptime']}")
    print(f"Total Threats:         {status['total_threats_detected']}")
    print(f"Recent Threats (1h):   {status['recent_threats']}")
    print(f"Protocols Monitored:   {', '.join(status['protocols_monitored'])}")
    print(f"ML Detection:          {'Enabled' if status['ml_detection_enabled'] else 'Disabled'}")
    print(f"Sigma Rules Loaded:    {status['sigma_rules_loaded']}")
    print("=" * 50)


def simulate_threats():
    """Simulate threat detections for demonstration."""
    threats = [
        "Modbus unauthorized write detected from 192.168.1.100",
        "DNP3 authentication failure - possible brute force",
        "OPC UA certificate anomaly detected",
        "Network segmentation violation: Corporate -> Control zone",
        "ML Anomaly: Unusual protocol timing patterns detected"
    ]

    print("\nRecent Threat Detections:")
    print("-" * 50)
    for i, threat in enumerate(threats, 1):
        print(f"{i}. {threat}")
    print("-" * 50)


def demonstrate_mitre_mapping():
    """Demonstrate MITRE ATT&CK integration."""
    print("\nMITRE ATT&CK for ICS Integration:")
    print("=" * 50)

    mappings = [
        {"technique": "T0842", "name": "Network Sniffing", "tactic": "Discovery"},
        {"technique": "T0839", "name": "Modify Parameter", "tactic": "Impair Process Control"}, 
        {"technique": "T0826", "name": "Loss of Availability", "tactic": "Impact"},
        {"technique": "T0859", "name": "Valid Accounts", "tactic": "Initial Access"},
    ]

    for mapping in mappings:
        print(f"• {mapping['technique']} - {mapping['name']} ({mapping['tactic']})")
    print("=" * 50)


def generate_sample_report(sentinel):
    """Generate and display sample security report."""
    print("\nGenerating Security Report...")

    report = sentinel.generate_security_report(
        timeframe="24h",
        include_mitre_mapping=True,
        format="json"
    )

    print("\nSecurity Report Summary:")
    print("=" * 50)
    print(f"Time Period:           {report['metadata']['timeframe']}")
    print(f"Total Threats:         {report['summary']['total_threats']}")
    print(f"High Severity:         {report['summary']['high_severity_threats']}")
    print(f"Medium Severity:       {report['summary']['medium_severity_threats']}")
    print(f"Low Severity:          {report['summary']['low_severity_threats']}")
    print(f"Monitoring Uptime:     {report['summary']['monitoring_uptime']}")

    if report.get('mitre_analysis'):
        mitre = report['mitre_analysis']
        print(f"MITRE Tactics:         {len(mitre['tactics_detected'])}")
        print(f"MITRE Techniques:      {len(mitre['techniques_detected'])}")
        print(f"Coverage:              {mitre['coverage_percentage']:.1f}%")

    print("=" * 50)

    # Save report
    report_file = f"reports/demo_report_{int(time.time())}.json"
    Path("reports").mkdir(exist_ok=True)

    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"Report saved to: {report_file}")


async def monitoring_demo(sentinel, duration=300):
    """Demonstrate real-time monitoring capabilities."""
    print(f"\nStarting {duration}-second monitoring demonstration...")

    success = sentinel.start_monitoring(
        interface="eth0",
        protocols=["modbus", "dnp3", "opc_ua"],
        enable_ml_detection=True
    )

    if not success:
        print("Failed to start monitoring")
        return

    start_time = time.time()

    try:
        while time.time() - start_time < duration:
            print(f"\rMonitoring... {int(time.time() - start_time)}/{duration}s", end="", flush=True)
            await asyncio.sleep(1)

            # Show status updates every minute
            if int(time.time() - start_time) % 60 == 0 and int(time.time() - start_time) > 0:
                print("\n")
                print_status(sentinel)
                simulate_threats()

    except KeyboardInterrupt:
        print("\n\nMonitoring interrupted by user")
    finally:
        sentinel.stop_monitoring()
        print("\nMonitoring stopped")


def main():
    """Main demonstration function."""
    parser = argparse.ArgumentParser(description="ICS Security Sentinel Demo")
    parser.add_argument("--config", default="config/config.yaml", 
                       help="Configuration file path")
    parser.add_argument("--duration", type=int, default=300,
                       help="Monitoring duration in seconds")
    parser.add_argument("--mode", choices=["interactive", "automated"], default="interactive",
                       help="Demo mode")

    args = parser.parse_args()

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print_banner()

    try:
        print(f"Initializing ICS Security Sentinel with config: {args.config}")
        sentinel = SecuritySentinel(args.config)
        print("Framework initialized successfully")

        if args.mode == "interactive":
            while True:
                print("\nDemo Options:")
                print("1. Show System Status")
                print("2. Simulate Threat Detection")
                print("3. Show MITRE ATT&CK Integration") 
                print("4. Generate Security Report")
                print("5. Start Real-time Monitoring")
                print("6. Exit Demo")

                choice = input("\nSelect option (1-6): ").strip()

                if choice == "1":
                    print_status(sentinel)
                elif choice == "2":
                    simulate_threats()
                elif choice == "3":
                    demonstrate_mitre_mapping()
                elif choice == "4":
                    generate_sample_report(sentinel)
                elif choice == "5":
                    duration = int(input("Enter monitoring duration in seconds (default 300): ") or "300")
                    asyncio.run(monitoring_demo(sentinel, duration))
                elif choice == "6":
                    break
                else:
                    print("Invalid option. Please try again.")
        else:
            # Automated demo
            print("Running automated demonstration...")
            print_status(sentinel)
            simulate_threats()
            demonstrate_mitre_mapping()
            generate_sample_report(sentinel)
            asyncio.run(monitoring_demo(sentinel, args.duration))

    except Exception as e:
        print(f"Error running demonstration: {str(e)}")
        sys.exit(1)

    print("\nDemo completed. Thank you for trying ICS Security Sentinel!")
    print("For more information, visit: https://github.com/marcolucchese/ics-security-sentinel")


if __name__ == "__main__":
    main()
