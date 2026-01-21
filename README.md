# Security Log Analyzer (Python)

## Overview
Security Log Analyzer is a Python-based project designed to analyze security-related log files and identify suspicious activities. The project focuses on basic SOC-style detection techniques such as monitoring failed login attempts, suspicious user behavior, and error-level security events.

This project is created for educational and portfolio purposes to demonstrate fundamental log analysis and incident detection concepts.

---

## Problem Statement
Security teams rely on log analysis to detect suspicious behavior and potential security incidents. However, raw logs are difficult to analyze manually. This project simulates how basic alerting can be generated from log data using simple detection rules.

---

## Features
- Analyzes authentication-related log events
- Detects repeated failed login attempts from the same IP
- Flags suspicious users such as `unknown` and `guest`
- Counts ERROR-level security events
- Generates a readable security analysis report

---

## Tools & Technologies
- Python 3
- Regular Expressions (Regex)
- File Handling
- Git & GitHub

---

## How to Run
1. Ensure Python 3 is installed on your system  
2. Clone this repository or download the project files  
3. Ensure `log_analyzer.py` and `sample_logs.txt` are in the same directory  
4. Open a terminal in the project folder  
5. Run the following command:

```bash
python log_analyzer.py
