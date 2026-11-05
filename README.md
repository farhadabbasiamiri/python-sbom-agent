# Python Dependency SBOM Risk Agent

**Group:** 10A  
**Course:** Applied AI Agents for Cybersecurity Operations  
**University:** Laurentian University

## Project Overview

This project aims to develop an AI-powered cybersecurity agent that analyzes Python dependencies, identifies known software vulnerabilities using the OSV database, evaluates security risks, and provides remediation recommendations.

The system will integrate vulnerability scanning, risk scoring, AI-generated security recommendations, and a Gradio dashboard.

## Authors — Group 10A

- Taha Khalid
- Rehnuma Khanom Ratul 
- Srinivas Dhadi 
- Rahi Fabia Rashid Chowdhury
- Harshilkumar Patel 

## Supervisor

Professor Farhad Abbasi Amiri 


## Current Development Status

### Completed Features
- Python dependency parsing
- OSV API vulnerability detection
- CVE identification and basic deduplication
- Improved weighted risk scoring based on:
  - Vulnerability severity (65%)
  - Number of vulnerabilities (25%)
  - Reported fix availability (10%)
- Fixed-version extraction from OSV
- Upgrade validation against known vulnerabilities
- PyPI release verification
- Automatic upgrade recommendations
- Basic Python-version compatibility filtering
- JSON report generation with risk scores and upgrade recommendations

### Planned Features
- AI agent integration
- Gradio dashboard
- Comprehensive testing and evaluation
- Final system integration and documentation
