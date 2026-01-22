# Splunk-SOC-Home-Lab
# 🛡️ Splunk SOC Home Lab – SSH Brute Force Detection

## Overview
This project demonstrates a SOC-style home lab using Splunk Enterprise.  
It collects SSH logs from a Kali Linux endpoint and detects brute-force login attempts.  
The lab simulates a real-world environment with log forwarding and detection rules.

---

## Lab Architecture
| Role | OS | IP |
|----|----|----|
| Splunk Server | Ubuntu Server | 10.0.2.10 |
| Log Source / Attacker | Kali Linux | 10.0.2.5 |

---

## Splunk Enterprise Installation (Ubuntu Server)

**Install Splunk Enterprise:**

Install the .deb package and start Splunk:
```bash
sudo dpkg -i splunk.deb
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start

![Splunk Installation](./PNG's/install%20splunk%20wget.png)

Enable receiving on port 9997 so forwarders can send logs:
sudo /opt/splunk/bin/splunk enable listen 9997 -auth 'admin:1'
Verify Splunk is listening:

sudo ss -tulnp | grep 9997
Universal Forwarder Installation (Kali Linux)
Install the Universal Forwarder and start it:

sudo dpkg -i splunkforwarder.deb
sudo /opt/splunkforwarder/bin/splunk start --accept-license
Connect the forwarder to the Splunk Server:

sudo /opt/splunkforwarder/bin/splunk add forward-server 10.0.2.10:9997 -auth admin:1
Monitor SSH authentication logs:

sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log -sourcetype "SSH logs" -index main
sudo /opt/splunkforwarder/bin/splunk restart
Verify the forwarder is active:

sudo /opt/splunkforwarder/bin/splunk list forward-server
Testing and Log Generation
Simulate failed SSH login attempts on Kali Linux:

ssh fakeuser@localhost
Enter an incorrect password several times.

Verify the events are ingested in Splunk:

index=main sourcetype="SSH logs"
Detection Rules
Invalid vs Known User Login Attempts:

index="main" "Failed password"
| rex "Failed password for (?<invalid_prefix>invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| eval alert_name = if(isnotnull(invalid_prefix), "SSH Login Attempt (Invalid User)", "SSH Login Attempt (Known User)")
| eval severity = "High"
| eval description = "User '" + user + "' attempted access from IP " + src_ip
| table _time, alert_name, severity, description
| sort - _time
SOC-Style Alert Classification:

index="main" sourcetype="SSH logs" "Failed password"
| rex "Failed password for (?<status_user>invalid user |)(?<user>\S+) from (?<src_ip>\S+)"
| eval alert_name = if(status_user!="", "Failed Login (Invalid User)", "Failed Login (Known User)")
| eval severity = "High"
| rename user as description
| table _time, alert_name, severity, src_ip, description
| sort - _time
Validation
Check that Splunk is running:

/opt/splunk/bin/splunk status
Check forwarder connection:

sudo /opt/splunkforwarder/bin/splunk list forward-server
Search for ingested logs:

index=main sourcetype="SSH logs"
Summary
This lab demonstrates a complete home SOC deployment:

Splunk Enterprise setup

Universal Forwarder log forwarding

SSH brute-force detection

Alert enrichment and classification

