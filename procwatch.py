import psutil
import argparse

# Suspicious process keywords
blacklist = [
    "mimikatz", "keylogger", "netcat", "nc.exe", "powershell.exe",
    "cmd.exe", "python", "nmap", "meterpreter", "sqlmap"
]

def scan_processes(output=None):
    suspicious = []
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            name = proc.info['name'].lower()
            pid = proc.info['pid']
            user = proc.info['username']

            for keyword in blacklist:
                if keyword in name:
                    line = f"[ALERT] Suspicious process: {name} | PID: {pid} | User: {user}"
                    print(line)
                    suspicious.append(line)
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if output:
        with open(output, "w") as f:
            for entry in suspicious:
                f.write(entry + "\n")
        print(f"\n📁 Report saved to: {output}")

def main():
    parser = argparse.ArgumentParser(description="🧠 ProcWatch – Suspicious Process Detector")
    parser.add_argument("-o", "--output", help="Save alert report to file")
    args = parser.parse_args()

    scan_processes(args.output)

if __name__ == "__main__":
    main()
