Markdown
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
* Ansible installed on your local machine:
  ```bash
  sudo apt install ansible
SSH access to the server as root.2. ConfigurationOpen the secure_kali_setup.yml file and edit the vars section at the top:YAMLvars:
  target_user: "your_username"       # <--- Change this
  timezone: "Asia/Riyadh"            # <--- Change this
  
  # Optional: Add your SSH Public Key here to avoid password login issues
  ssh_public_key: "ssh-ed25519 AAAA..." 
  
  # Optional: Add a webhook URL for notifications (Discord, etc.)
  webhook_url: ""
3. Create InventoryCreate a file named hosts.ini and add your server IP:Ini, TOML[servers]
192.168.1.100 ansible_user=root
4. Run the PlaybookRun the following command to start the setup:Bashansible-playbook -i hosts.ini secure_kali_setup.yml
🛠️ What specific tools are configured?ToolPurposeConfigurationUFWFirewallDeny Incoming / Allow Specific Outbound.CrowdSecIPSMonitors Syslogs, SSH, and Docker containers.ClamAVAntivirusDaily "Smart Scan" + Weekly Full Scan.Fail2BanBruteforce ProtectionProtects SSH.DockerContainer EngineInstalled with secure logging defaults.⚠️ DisclaimerThis script modifies firewall rules and SSH configurations. Always ensure you have a backup access method (like a console/VNC) before running it on a remote server.LicenseMIT