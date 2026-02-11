# 🛡️ Ultimate Secure Server Setup (Ansible Playbook)

This Ansible playbook automates the process of securing a Linux server (Kali, Debian, Ubuntu). It installs Docker, configures a Firewall (UFW) with safe defaults, sets up CrowdSec IPS, and installs a smart ClamAV antivirus scanner with webhook alerts.

## ✨ Features

* **System Updates:** Auto-updates repositories (Fixes Kali repos automatically).
* **User Security:** Creates a sudo user and sets up SSH keys.
* **Hardening:** Configures `sysctl` security parameters and SSH locking.
* **Firewall:** UFW configured with a "Default Deny" policy, preserving SSH & VPN connections.
* **Intrusion Prevention:** Installs **CrowdSec** + Firewall Bouncer.
* **Antivirus:** Installs **ClamAV** with a custom script for optimized daily scans.
* **Monitoring:** Optional Webhook integration for virus alerts (Discord/Slack/Telegram).

## 🚀 Usage

### 1. Prerequisites
* A fresh Linux server (Kali Linux, Ubuntu, or Debian).
* Ansible installed on your local machine (`sudo apt install ansible`).
* SSH access to the server as root.

### 2. Configuration
Open the `secure_kali_setup.yml` file and edit the **vars** section at the top:

```yaml
vars:
  target_user: "your_username"       # <--- Change this
  timezone: "Asia/Riyadh"            # <--- Change this
  
  # Optional: Add your SSH Public Key here to avoid password login issues
  ssh_public_key: "ssh-ed25519 AAAA..." 
  
  # Optional: Add a webhook URL for notifications (Discord, etc.)
  webhook_url: ""

2.Run the Playbook
Create an inventory file hosts.ini:
[servers]
192.168.1.100 ansible_user=root

3.Run the command:
ansible-playbook -i hosts.ini secure_kali_setup.yml

🛠️ What specific tools are configured?

Tool,Purpose,Configuration
UFW,Firewall,Deny Incoming / Allow Specific Outbound.
CrowdSec,IPS,"Monitors Syslogs, SSH, and Docker containers."
ClamAV,Antivirus,"Daily ""Smart Scan"" + Weekly Full Scan."
Fail2Ban,Bruteforce Protection,Protects SSH.
Docker,Container Engine,Installed with secure logging defaults.

⚠️ Disclaimer

This script modifies firewall rules and SSH configurations. Always ensure you have a backup access method (like a console/VNC) before running it on a remote server.

License
MIT