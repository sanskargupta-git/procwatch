# 🧠 ProcWatch – Suspicious Process Detector

A Python script to scan running system processes and flag those matching suspicious names or patterns. Works on Linux & Windows.

## 🔧 Features

- Cross-platform (Linux & Windows)
- Alerts for known red-team or hacking tools
- Flags `mimikatz`, `netcat`, `keylogger`, `powershell.exe`, etc.
- Optional output to file
- No external APIs or frameworks

## 🛠️ Usage

```bash
python procwatch.py -o alert_report.txt
