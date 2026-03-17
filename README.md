# 🛡️ SSH Honeypot Attack Analysis (Cowrie)

This project implements a Cowrie SSH honeypot to collect and analyze real-world cyber attack data.  
It provides automated data processing, visualization, and GitHub-based reporting of attacker behavior.

---

## 🚀 Features

- 📡 Real-time SSH attack data collection using Cowrie  
- 🔐 Username & password brute-force analysis  
- 🚨 Top attacker IP identification  
- 🌍 Geographic (country-based) attack analysis  
- 📊 Automated chart generation (Matplotlib)  
- 🤖 Fully automated pipeline using Cron jobs  
- 📂 Daily updates pushed to GitHub  

---

## 📊 Data Analysis

The system analyzes:

- 🚨 Top attacker IP addresses
- 👤 Username patterns
- 🔐 Password frequency
- 💻 Command execution
- 🌍 Geographic distribution




## 🏗️ System Architecture

```mermaid
graph TD
    A[Internet Attackers] --> B[Cowrie Honeypot]
    B --> C[Log Files - cowrie.json]
    C --> D[Python Analysis Script]
    D --> E[CSV and Charts]
    E --> F[GitHub Auto Update]
