# Multi-Vector Threat Detection 
#  From Raw Logs to Real-Time Detection
Turning scattered log data into actionable alerts across a simulated enterprise environment

<p align="center">

![Splunk](https://img.shields.io/badge/SIEM-Splunk_Enterprise-black?style=for-the-badge&logo=splunk)
![Windows](https://img.shields.io/badge/Windows-Event_Logs-blue?style=for-the-badge&logo=windows)
![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94?style=for-the-badge&logo=kalilinux)
![VMware](https://img.shields.io/badge/VMware-Workstation-orange?style=for-the-badge&logo=vmware)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge)
![SOC](https://img.shields.io/badge/SOC-Incident_Response-success?style=for-the-badge)

</p>

---

#  Project Overview

This project demonstrates the implementation of a **Security Information and Event Management (SIEM)** platform using **Splunk Enterprise** to detect, investigate, and respond to cybersecurity threats.

The project combines:

- Enterprise-scale threat investigation using the **Splunk Boss of the SOC (BOTSv2)** dataset
-  Live cyber attack simulations in a controlled virtual lab
-  Detection engineering using **Splunk Processing Language (SPL)**
-  Interactive dashboards for security monitoring and incident investigation

The objective is to simulate real-world **Security Operations Center (SOC)** workflows by collecting logs, identifying malicious activity, correlating events, and investigating security incidents.

---

#  Project Objectives

- Deploy and configure Splunk Enterprise
-  Centralize Windows Event Logs
-  Investigate enterprise attacks using BOTSv2
-  Simulate real-world cyber attacks
-  Develop SPL detection rules
-  Build security dashboards
-  Perform threat hunting and incident response

---

#  Lab Architecture

| Component | Technology |
|-----------|------------|
|  SIEM Platform | Splunk Enterprise |
|  Log Forwarder | Splunk Universal Forwarder |
|  Target Machine | Windows 10 |
|  Attacker Machine | Kali Linux |
|  Virtualization | VMware Workstation Pro |

---

# Data Sources

##  BOTSv2 Dataset

Enterprise-scale logs used for realistic SOC investigations including:

- Authentication Logs
- Endpoint Activity
- Network Traffic
- Web Logs
- Malware Events
- Security Alerts

##  Custom Lab Logs

Generated from live attack simulations.

- Windows Security Logs
- Windows System Logs
- Windows Application Logs
- Authentication Events
- Network Activity

---

#  Attack Simulations

##  Network Reconnaissance (Nmap)

```bash
sudo nmap -sS -sV -p- -T4 <Target-IP>
```

Detection Focus

- Port Scanning
- Service Enumeration
- Sequential Port Access
- Reconnaissance

---

##  SYN Flood (hping3)

```bash
hping3 -S --flood -p 80 <Target-IP>
```

Detection Focus

- High Packet Rate
- Traffic Spikes
- Potential DoS Activity

---

##  Brute Force (Hydra)

```bash
hydra -l <username> -P /usr/share/wordlists/rockyou.txt ssh://<Target-IP>
```

Detection Focus

- Failed Logins
- Event ID 4625
- Successful Login after Failures
- Authentication Anomalies

---

#  Detection Rules (SPL)

##  Brute Force Detection

```spl
index=windows EventCode=4625
| stats count by src_ip, Account_Name
| where count > 10
| sort - count
```

---

##  Port Scan Detection

```spl
index=network sourcetype=firewall
| stats dc(dest_port) as unique_ports by src_ip
| where unique_ports > 50
```

---

##  Successful Login After Multiple Failures

```spl
index=windows EventCode=4625 OR EventCode=4624
| stats count(eval(EventCode=4625)) as failures,
count(eval(EventCode=4624)) as successes
by Account_Name, src_ip
| where failures > 5 AND successes > 0
```

---

#  Splunk Dashboards

Custom dashboards were created for security monitoring.

- BOTSv2 Incident Dashboard
- Authentication Monitoring
-  Network Activity Monitoring

Dashboard Highlights

- Failed Logons
- Login Trends
- Port Scan Detection
- Security Timelines
- Threat Correlation

---

<img width="1774" height="887" alt="image" src="https://github.com/user-attachments/assets/5e9c2481-e1db-431a-a534-f47ab93d15f7" />


The workflow illustrates the complete SOC investigation lifecycle implemented in this project:

- Attack Simulation from Kali Linux
- Windows Event Log Generation
- Log Collection using Splunk Universal Forwarder
- Log Indexing in Splunk Enterprise
- Threat Detection using SPL Queries
- Alert Generation
- Dashboard-based Investigation
- Threat Hunting & Deep Analysis
- Incident Response and Reporting

---


#  Key Findings

-  Detected brute-force attacks
-  Identified reconnaissance activity
-  Detected abnormal traffic spikes
-  Investigated enterprise-scale attacks using BOTSv2
-  Correlated multiple log sources
-  Performed threat hunting using SPL

---

#  Skills Demonstrated

- Splunk Enterprise
- SIEM Deployment
- Threat Detection
- SPL Query Development
- Threat Hunting
- Event Correlation
- Incident Investigation
- Windows Event Log Analysis
- Dashboard Development
- MITRE ATT&CK Mapping

---

#  MITRE ATT&CK Mapping

| Technique | ATT&CK ID |
|-----------|-----------|
| Network Service Discovery | T1046 |
| Brute Force | T1110 |
| Endpoint Denial of Service | T1499 |
| Valid Accounts | T1078 |

---

#  Windows Event IDs Monitored

| Event ID | Description |
|----------|-------------|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4648 | Logon Using Explicit Credentials |
| 4672 | Special Privileges Assigned |
| 4768 | Kerberos Authentication Ticket Requested |

---

#  Technologies Used

- Splunk Enterprise
- Splunk Universal Forwarder
- Kali Linux
- Windows 10
- VMware Workstation Pro
- Nmap
- Hydra
- hping3
- BOTSv2 Dataset
- Splunk Processing Language (SPL)

---

#  Disclaimer

> This project was built in a **controlled virtual lab environment** for educational and defensive cybersecurity purposes only. All attack simulations were performed on systems owned or authorized for testing. No unauthorized systems or networks were targeted.

---

#  Support the Project

If you found this project helpful, consider giving it a **⭐ Star**. Contributions, suggestions, and feedback are always welcome!
